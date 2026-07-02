// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::state::{DaemonEvent, DaemonState, ProjectionChangedSet};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use kin_model::session::{Intent, IntentScope, IntentSummary, LockType};
use kin_model::{
    Branch, BranchName, ChangeStore, ContractId, EntityId, EntityStore, FileLayout, FilePathId,
    GraphNodeId, IntentId, ProvenanceStore, SessionCapabilities, SessionId, SessionStore,
    SessionTransport, WorkStore,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::info;
use uuid::Uuid;

static BOOTSTRAP_EXPORTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

/// Acquire a `std::sync::Mutex`, recovering the guard if the lock was poisoned
/// by a panic in a prior holder.
///
/// The daemon's request-path locks guard simple in-memory map operations
/// (`insert`/`get`/`remove`/`clone`) that leave the data structurally
/// consistent even if a holder unwound mid-way. Propagating the poison would
/// turn one transient panic into a permanent `500` on every later request that
/// touches the lock (poison is sticky until restart). Recovering keeps the
/// path serving instead, which is the correct treatment here and never panics.
fn lock_recover<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read-acquire a `std::sync::RwLock`, recovering on poison. See
/// [`lock_recover`] for why recovery (not propagation) is correct here.
fn read_recover<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Write-acquire a `std::sync::RwLock`, recovering on poison. See
/// [`lock_recover`] for why recovery (not propagation) is correct here.
fn write_recover<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Health check response.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
    pub repo_id: String,
    pub repo_root: String,
    pub pid: u32,
    #[serde(default)]
    pub active_request_count: u64,
    #[serde(default)]
    pub event_subscriber_count: u64,
    #[serde(default)]
    pub external_session_count: u64,
    #[serde(default)]
    pub idle_seconds: u64,
    /// Whether the daemon has loaded a snapshot or completed its first
    /// reconciliation cycle (graph-trust signal for clients/operators).
    #[serde(default)]
    pub initialized: bool,
    /// Whether the most recent filesystem-sync tick refused a suspected
    /// mass-deletion wipe. When true, the graph is intact but in-flight bulk
    /// removals are being withheld pending operator confirmation
    /// (`KIN_ALLOW_MASS_DELETION=1`).
    #[serde(default)]
    pub mass_deletion_blocked: bool,
    /// Whether the background embedding worker has permanently stopped after
    /// exhausting its panic budget. The daemon keeps serving graph/locate/
    /// reconcile (embeddings are a derived index); the vector index is frozen
    /// until restart. A true value drives `status: "attention"`.
    #[serde(default)]
    pub embed_worker_failed: bool,
    /// Monotonic snapshot generation marker (`.kin/kindb/generation`), bumped
    /// when the daemon commits a newer graph snapshot. A freshness token that
    /// lets clients and the MCP envelope express `graph_as_of` and detect stale
    /// reads. Additive; `0` before the first snapshot is committed.
    #[serde(default)]
    pub graph_generation: u64,
    pub build: BuildResponse,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct BuildResponse {
    pub sha: String,
    pub dirty: bool,
    pub built_at: String,
}

/// Readiness response.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
}

/// Working copy status response.
#[derive(Debug, Serialize, serde::Deserialize)]
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
    #[serde(default)]
    scope: String,
    #[serde(default)]
    scopes: Vec<String>,
    lock_type: String,
    task_description: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StartSessionRequest {
    vendor: String,
    client_name: String,
    #[serde(default = "default_session_transport")]
    transport: String,
    #[serde(default)]
    pid: Option<u32>,
    cwd: String,
    #[serde(default)]
    capabilities: SessionCapabilities,
}

#[derive(Debug, Deserialize)]
struct McpToolCallRequest {
    name: String,
    #[serde(default)]
    arguments: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionStartResponse {
    session_id: String,
    vendor: String,
    client_name: String,
    transport: SessionTransport,
    started_at: kin_model::timestamp::Timestamp,
    capabilities: SessionCapabilities,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionHeartbeatResponse {
    session_id: String,
    status: String,
    heartbeat_at: kin_model::timestamp::Timestamp,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionEndResponse {
    session_id: String,
    vendor: String,
    status: String,
    started_at: kin_model::timestamp::Timestamp,
    ended_at: kin_model::timestamp::Timestamp,
}

#[derive(Debug, Deserialize)]
struct SetScopeRequest {
    ref_string: String,
}

#[derive(Debug, Serialize)]
struct ScopeResponse {
    ref_string: String,
    head: String,
    created_at_secs_ago: u64,
    ttl_remaining_secs: u64,
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

#[derive(Debug, Deserialize, Default)]
struct GraphMutationBatch {
    #[serde(default)]
    work_items: Vec<kin_model::WorkItem>,
    #[serde(default)]
    work_links: Vec<kin_model::WorkLink>,
    #[serde(default)]
    annotations: Vec<kin_model::Annotation>,
    #[serde(default)]
    work_status_updates: Vec<WorkStatusMutation>,
    #[serde(default)]
    audit_events: Vec<AuditMutation>,
}

#[derive(Debug, Deserialize)]
struct WorkStatusMutation {
    work_id: kin_model::WorkId,
    status: kin_model::WorkStatus,
}

#[derive(Debug, Deserialize)]
struct AuditMutation {
    action: String,
    target_scope: Option<kin_model::WorkScope>,
    details: Option<String>,
}

/// Query parameters for endpoints that support multi-repo selection.
#[derive(Debug, Deserialize, Default)]
struct RepoQuery {
    /// Optional repo ID. When provided, uses the lazily-loaded graph for that
    /// repo instead of the daemon's primary graph.
    #[serde(default)]
    repo: Option<String>,
}

/// List repos response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReposResponse {
    pub repos: Vec<String>,
}

/// Repo health response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoHealthResponse {
    pub repo_id: String,
    pub entity_count: usize,
    pub graph_loaded: bool,
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub mass_deletion_blocked: bool,
    #[serde(default)]
    pub embed_worker_failed: bool,
}

/// Repo entities search response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoEntitiesResponse {
    pub repo_id: String,
    pub entities: Vec<RepoEntityEntry>,
}

/// Repo file listing response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoFilesResponse {
    pub repo_id: String,
    pub files: Vec<RepoFileEntry>,
}

/// A single projected file entry returned from a repo file listing.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoFileEntry {
    pub path: String,
}

/// Repo refs response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoRefsResponse {
    pub repo_id: String,
    pub branch_name: Option<String>,
    pub default_branch: Option<String>,
    pub head_ref: Option<String>,
    pub refs: Vec<RepoRefEntry>,
}

/// A single repo ref entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoRefEntry {
    pub name: String,
    pub short_name: String,
    pub kind: String,
    pub commit_id: String,
    pub short_commit_id: String,
    pub is_head: bool,
    pub is_default_branch: bool,
}

/// Repo history response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoHistoryResponse {
    pub repo_id: String,
    pub branch_name: Option<String>,
    pub baseline_ref: Option<String>,
    pub head_ref: Option<String>,
    pub commits: Vec<RepoHistoryEntry>,
}

/// A single semantic history entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoHistoryEntry {
    pub commit_id: String,
    pub short_commit_id: String,
    pub author: String,
    pub authored_at: String,
    pub subject: String,
}

/// A single entity entry returned from the multi-repo search.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoEntityEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
}

/// Provenance hash chain step — one level in the Merkle DAG proof lineage.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvenanceHashStep {
    pub level: String,
    pub hash: String,
    pub description: String,
}

/// Entity provenance response — full Merkle DAG hash chain for an entity.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoProvenanceEntityResponse {
    pub repo_id: String,
    pub entity_id: String,
    pub entity_name: String,
    pub entity_kind: String,
    pub file_path: Option<String>,
    pub hash_chain: Vec<ProvenanceHashStep>,
    pub outgoing_relation_hashes: Vec<ProvenanceRelationHash>,
    pub subgraph_hash: String,
    pub graph_root_hash: String,
    pub verified: bool,
}

/// Hash of a single relation in the provenance chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvenanceRelationHash {
    pub relation_id: String,
    pub kind: String,
    pub destination_entity_id: String,
    pub destination_entity_name: String,
    pub hash: String,
}

/// Provenance verification response — Merkle DAG integrity check.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoProvenanceVerifyResponse {
    pub repo_id: String,
    pub valid: bool,
    pub checked_entities: usize,
    pub verified_entities: usize,
    pub broken_chains: Vec<ProvenanceBrokenChain>,
    pub graph_root_hash: String,
}

/// A broken chain entry in the provenance verification report.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvenanceBrokenChain {
    pub entity_id: String,
    pub entity_name: String,
    pub expected_hash: String,
    pub actual_hash: String,
}

/// Query parameters for multi-repo entity search.
#[derive(Debug, Deserialize)]
struct RepoEntitiesQuery {
    #[serde(default)]
    query: Option<String>,
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
    /// Optional VFS shim caller session. Additive field used for write-veto
    /// self-exclusion so a session's own hard intents don't block its writes
    /// (parity with `/vfs/write-notify`). Absent → no own-write exclusion.
    #[serde(default)]
    session_id: Option<String>,
}

/// Request body for VFS write-notify (shim → daemon immediate re-index).
#[derive(Debug, Deserialize)]
struct WriteNotifyRequest {
    file_path: String,
    /// Content hash from the shim (reserved for future use — the reconciler
    /// reads the file directly today, but the hash can be used for
    /// skip-if-unchanged optimization later).
    #[serde(default)]
    #[allow(dead_code)]
    content_hash: Option<String>,
    /// Session ID of the VFS shim caller, used for self-exclusion during
    /// lease checks so a session's own hard locks don't block its writes.
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DaemonCommitRequest {
    pub change: kin_model::SemanticChange,
    pub branch_name: kin_model::BranchName,
    #[serde(default)]
    pub shallow_files: Vec<kin_model::ShallowTrackedFile>,
    #[serde(default)]
    pub shallow_clears: Vec<kin_model::FilePathId>,
    #[serde(default)]
    pub audit_event: Option<kin_model::provenance::AuditEvent>,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// The current API version number, returned in the `X-Kin-API-Version` header.
pub const API_VERSION: &str = "1";

/// Axum middleware that adds `X-Kin-API-Version: 1` to every response.
async fn api_version_header(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Kin-API-Version",
        axum::http::HeaderValue::from_static(API_VERSION),
    );
    let info = kin_buildinfo::get();
    insert_header(response.headers_mut(), "X-Kin-Daemon-Sha", info.sha);
    insert_header(
        response.headers_mut(),
        "X-Kin-Daemon-Dirty",
        if info.dirty { "true" } else { "false" },
    );
    insert_header(
        response.headers_mut(),
        "X-Kin-Daemon-Built-At",
        info.built_at,
    );
    response
}

fn insert_header(headers: &mut axum::http::HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn current_build_response() -> BuildResponse {
    let info = kin_buildinfo::get();
    BuildResponse {
        sha: info.sha.to_string(),
        dirty: info.dirty,
        built_at: info.built_at.to_string(),
    }
}

#[derive(Clone)]
struct DaemonAuthState {
    auth_token: Option<String>,
}

fn is_public_route(path: &str) -> bool {
    let path = path.strip_prefix("/v1").unwrap_or(path);
    matches!(path, "/health" | "/ready" | "/readiness" | "/spine/health")
}

async fn daemon_auth(
    State(auth_state): State<DaemonAuthState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    if auth_state.auth_token.is_none() || is_public_route(request.uri().path()) {
        return next.run(request).await;
    }

    let expected_token = auth_state.auth_token.as_deref().unwrap_or_default();
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    if provided != Some(expected_token) {
        return auth_error(StatusCode::UNAUTHORIZED, "Authentication required");
    }

    next.run(request).await
}

async fn daemon_activity(
    State(state): State<Arc<DaemonState>>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    struct RequestActivityGuard(Arc<DaemonState>);

    impl Drop for RequestActivityGuard {
        fn drop(&mut self) {
            self.0.end_request();
        }
    }

    state.begin_request();
    let _guard = RequestActivityGuard(state);
    next.run(request).await
}

/// Strip an optional `:port` suffix from a Host/authority value, correctly
/// handling bracketed IPv6 literals like `[::1]:4219` (returns `::1`).
fn host_without_port(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
        return value;
    }
    match value.split_once(':') {
        Some((host, _port)) => host,
        None => value,
    }
}

fn is_host_allowed(host: &str) -> bool {
    let host = host.trim();
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return true;
    }
    if let Ok(bind_host) = std::env::var("KIN_DAEMON_BIND_HOST") {
        let bind_host = bind_host.trim();
        if bind_host == "0.0.0.0" || bind_host == "::" || bind_host == "[::]" {
            return true;
        }
        if !bind_host.is_empty() && host == bind_host {
            return true;
        }
    }
    false
}

async fn validate_host_and_origin(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // 1. Validate the Host header.
    //
    // HTTP/1.1 makes Host mandatory and every browser (the DNS-rebinding
    // drive-by threat) always sends it, so a rebound request carries the
    // attacker's Host and is rejected by the allowlist below. A *missing* Host
    // can only come from a hand-rolled raw-socket client deliberately skipping
    // the browser contract; on a sensitive (non-public) route we reject it so
    // the allowlist cannot be bypassed by simply omitting the header. Public
    // liveness routes (/health, /ready, …) stay reachable without a Host so
    // health-probe tooling is unaffected.
    match request.headers().get(header::HOST) {
        Some(host_val) => {
            if let Ok(host_str) = host_val.to_str() {
                let host_part = host_without_port(host_str);
                if !is_host_allowed(host_part) {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": format!("Host forbidden: {}", host_str) })),
                    )
                        .into_response();
                }
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Invalid Host header encoding" })),
                )
                    .into_response();
            }
        }
        None => {
            if !is_public_route(&path) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Host header required" })),
                )
                    .into_response();
            }
        }
    }

    // 2. Validate Origin header if present
    if let Some(origin_val) = request.headers().get(header::ORIGIN) {
        if let Ok(origin_str) = origin_val.to_str() {
            let origin_str = origin_str.trim();
            if origin_str == "null" {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Null origin is forbidden" })),
                )
                    .into_response();
            }

            let mut valid = false;
            if let Ok(uri) = origin_str.parse::<axum::http::Uri>() {
                if let Some(host) = uri.host() {
                    if is_host_allowed(host) {
                        valid = true;
                    }
                }
            }

            if !valid {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": format!("Origin forbidden: {}", origin_str) })),
                )
                    .into_response();
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid Origin header encoding" })),
            )
                .into_response();
        }
    }

    next.run(request).await
}

fn auth_error(status: StatusCode, message: &str) -> Response {
    let mut response = (status, Json(json!({ "error": message }))).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer realm=\"kin daemon\""),
    );
    response
}

/// Build the core route set (without state or middleware).
fn api_routes() -> Router<Arc<DaemonState>> {
    Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/ready", get(readiness))
        .route("/status", get(status))
        .route("/session", post(start_session).get(list_sessions))
        .route(
            "/session/{session_id}",
            get(get_session).delete(end_session),
        )
        .route("/session/{session_id}/heartbeat", post(session_heartbeat))
        .route(
            "/session/{session_id}/scope",
            post(set_scope).delete(clear_scope).get(get_scope),
        )
        .route(
            "/session/{session_id}/intents",
            get(list_session_intents).delete(clear_session_intents),
        )
        .route("/intent", get(list_intents))
        .route("/intent/register", post(register_intent))
        .route("/intent/{intent_id}", delete(release_intent))
        .route("/traffic/{scope}", get(traffic))
        .route("/locate", post(locate))
        .route("/search", post(search))
        .route("/context", post(context))
        .route("/trace", post(trace))
        .route("/impact", post(impact))
        .route("/review", post(review))
        .route("/work", post(work))
        .route("/note", post(note))
        .route("/embed", post(embed))
        .route("/blame", post(blame))
        .route("/history", post(history))
        .route("/verify/run", post(verify_run))
        .route("/commands/verify", post(command_verify))
        .route("/reconcile", post(reconcile))
        .route("/support", get(support))
        .route("/graph/bootstrap", get(graph_bootstrap))
        .route("/graph/commit", post(graph_commit))
        .route("/graph/mutations", post(graph_mutations))
        .route("/commands/status", post(command_status))
        .route("/commands/resources", post(command_resources))
        .route("/commands/graph", post(command_graph))
        .route("/commands/overview", post(command_overview))
        .route("/commands/dead-code", post(command_dead_code))
        .route("/commands/dead-code-seeded", post(command_dead_code_seeded))
        .route("/commands/trace-data-flow", post(command_trace_data_flow))
        .route("/commands/refs", post(command_refs))
        .route("/commands/bulk-refs", post(command_bulk_refs))
        .route("/commands/xref", post(command_xref))
        .route("/commands/diff", post(command_diff))
        .route("/commands/log", post(command_log))
        .route("/commands/audit", post(command_audit))
        .route("/commands/approvals", post(command_approvals))
        .route("/commands/security", post(command_security))
        .route("/commands/branch", post(command_branch))
        .route("/commands/checkout", post(command_checkout))
        .route("/commands/rename", post(command_rename))
        .route(
            "/commands/session-workspace",
            post(command_session_workspace),
        )
        .route("/commands/exec", post(command_exec))
        .route("/commands/commit", post(command_commit))
        .route(
            "/graph/branches",
            get(graph_list_branches).post(graph_create_branch),
        )
        .route("/graph/branches/{name}", delete(graph_delete_branch))
        .route("/graph/branches/{name}/head", put(graph_update_branch_head))
        .route("/mcp/tools/call", post(mcp_tools_call))
        // Multi-repo endpoints — list and query lazily-loaded repo graphs
        .route("/repos", get(list_repos))
        .route("/repos/{repo_id}/health", get(repo_health))
        .route("/repos/{repo_id}/entities", get(repo_entities))
        .route("/repos/{repo_id}/files", get(repo_files))
        .route("/repos/{repo_id}/refs", get(repo_refs))
        .route("/repos/{repo_id}/history", get(repo_history))
        .route("/repos/{repo_id}/compare", get(repo_compare))
        // Provenance endpoints — Merkle DAG proof lineage
        .route(
            "/repos/{repo_id}/provenance/entity/{entity_id}",
            get(repo_provenance_entity),
        )
        .route(
            "/repos/{repo_id}/provenance/verify",
            get(repo_provenance_verify),
        )
        // VFS endpoints — serve file tree and blob content to kin-vfs-daemon
        .route("/vfs/version", get(vfs_version))
        .route("/vfs/tree", get(vfs_tree))
        .route("/vfs/stat/{*path}", get(vfs_stat))
        .route("/vfs/read/{*path}", get(vfs_read))
        .route("/vfs/readdir/{*path}", get(vfs_readdir))
        .route("/vfs/file-changed", post(vfs_file_changed))
        .route("/vfs/write-notify", post(vfs_write_notify))
        .route("/vfs/subscribe", get(vfs_subscribe))
        // Archive endpoints — downloadable source archives
        // Axum doesn't allow parameters and literals in the same segment,
        // so we use /archive/tar/{ref} and /archive/zip/{ref} instead.
        .route("/archive/tar/{ref}", get(archive_tar_gz))
        .route("/archive/zip/{ref}", get(archive_zip))
        // Spine endpoints — cross-repo federation queries
        .route("/spine/health", get(spine_health))
        .route("/spine/repos", get(spine_repos))
        .route("/spine/resolve", get(spine_resolve))
        .route("/spine/impact", get(spine_impact))
        .route("/spine/xref", get(spine_xref))
        .route("/spine/repos/{repo_id}/ingest", post(spine_ingest_repo))
        .route(
            "/spine/refresh-cross-repo-edges",
            post(spine_refresh_cross_repo_edges),
        )
        // LSP enrichment — trigger a full cold sweep
        .route("/lsp/sweep", post(lsp_sweep))
}

#[derive(Clone)]
struct NpmRegistryAuthState {
    client: reqwest::Client,
    introspection_url: String,
}

#[derive(Debug, Deserialize)]
struct NpmRegistryAuthSubject {
    #[serde(rename = "userId")]
    user_id: String,
    email: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "actorKind")]
    actor_kind: String,
}

#[derive(Debug, Deserialize)]
struct NpmRegistryAuthResponse {
    subject: NpmRegistryAuthSubject,
    #[serde(rename = "credentialType")]
    credential_type: Option<String>,
    #[serde(rename = "orgIds", default)]
    org_ids: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

fn npm_registry_auth_state_from_env() -> Option<Arc<NpmRegistryAuthState>> {
    let introspection_url = std::env::var("KIN_REGISTRY_NPM_AUTH_URL").ok()?;
    let introspection_url = introspection_url.trim();
    if introspection_url.is_empty() {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    Some(Arc::new(NpmRegistryAuthState {
        client,
        introspection_url: introspection_url.to_string(),
    }))
}

fn npm_registry_routes(
    state: &Arc<DaemonState>,
    packages_dir: &std::path::Path,
    base_url: &str,
    auth_state: Option<Arc<NpmRegistryAuthState>>,
) -> Router {
    let npm_dir = packages_dir.join("npm");
    std::fs::create_dir_all(&npm_dir).ok();

    let router = kin_registry::npm::npm_routes(Arc::new(kin_registry::npm::NpmRegistryState {
        manifest_store: kin_registry::ManifestStore::new(state.layout.root()),
        blobs_dir: npm_dir,
        base_url: base_url.to_string(),
    }));

    match auth_state {
        Some(auth_state) => router.route_layer(middleware::from_fn_with_state(
            auth_state,
            npm_registry_auth,
        )),
        None => router,
    }
}

async fn npm_registry_auth(
    State(auth_state): State<Arc<NpmRegistryAuthState>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let action = if request.method() == axum::http::Method::PUT {
        "write"
    } else {
        "read"
    };

    let authorization = match request.headers().get(header::AUTHORIZATION) {
        Some(value) => match value.to_str() {
            Ok(value) if !value.trim().is_empty() => value.to_string(),
            _ => {
                return npm_registry_auth_error(
                    StatusCode::UNAUTHORIZED,
                    "Invalid Authorization header",
                );
            }
        },
        None => {
            return npm_registry_auth_error(StatusCode::UNAUTHORIZED, "Authentication required");
        }
    };

    let introspection = match auth_state
        .client
        .get(&auth_state.introspection_url)
        .query(&[("action", action)])
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("registry auth unavailable: {error}"),
                })),
            )
                .into_response();
        }
    };

    let status = introspection.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let error = introspection
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| {
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    "Authentication required".to_string()
                } else {
                    "Token scope does not allow this action".to_string()
                }
            });
        return npm_registry_auth_error(
            if status == reqwest::StatusCode::UNAUTHORIZED {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            },
            &error,
        );
    }

    if !status.is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": format!("registry auth failed with status {}", status.as_u16()),
            })),
        )
            .into_response();
    }

    let access = match introspection.json::<NpmRegistryAuthResponse>().await {
        Ok(access) => access,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("invalid registry auth response: {error}"),
                })),
            )
                .into_response();
        }
    };

    request
        .extensions_mut()
        .insert(kin_registry::npm::RegistryAccessIdentity {
            user_id: access.subject.user_id,
            email: access.subject.email,
            display_name: access.subject.display_name,
            actor_kind: access.subject.actor_kind,
            org_ids: access.org_ids,
            scopes: access.scopes,
            credential_type: access.credential_type,
        });

    next.run(request).await
}

fn npm_registry_auth_error(status: StatusCode, message: &str) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "error": message,
        })),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer realm=\"kinlab npm registry\""),
        );
    }
    response
}

/// Build the axum router with all daemon API routes.
///
/// Routes are served at both `/` (backward compat) and `/v1/` prefixes.
/// All responses include the `X-Kin-API-Version: 1` header.
pub fn router(state: Arc<DaemonState>) -> Router {
    router_with_auth(state, None)
}

fn router_with_auth(state: Arc<DaemonState>, auth_token: Option<String>) -> Router {
    let routes = api_routes();
    let activity_state = Arc::clone(&state);

    // Package registry — all ecosystems share the same packages dir and manifest store
    let packages_dir = state.layout.root().join("packages");
    std::fs::create_dir_all(&packages_dir).ok();
    let base_url = std::env::var("KIN_REGISTRY_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:4219".to_string());

    // Cargo registry. The publish (write) path is gated on a shared secret from
    // KIN_REGISTRY_CARGO_TOKEN; reads stay open. A None token fails closed
    // (publishing disabled), so an unset/empty env var never falls open.
    let crates_dir = packages_dir.join("crates");
    std::fs::create_dir_all(&crates_dir).ok();
    let cargo_publish_token = std::env::var("KIN_REGISTRY_CARGO_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let cargo_routes =
        kin_registry::cargo::cargo_routes(Arc::new(kin_registry::cargo::CargoRegistryState {
            manifest_store: kin_registry::ManifestStore::new(state.layout.root()),
            blobs_dir: crates_dir,
            base_url: base_url.clone(),
            publish_token: cargo_publish_token,
        }));

    let npm_routes = npm_registry_routes(
        &state,
        &packages_dir,
        &base_url,
        npm_registry_auth_state_from_env(),
    );

    // OCI container registry
    let oci_dir = packages_dir.join("oci");
    std::fs::create_dir_all(&oci_dir).ok();
    let oci_routes = kin_registry::oci::oci_routes(Arc::new(kin_registry::oci::OciRegistryState {
        blobs_dir: oci_dir,
        manifests: Default::default(),
        uploads: Default::default(),
    }));

    // Go module proxy
    let go_dir = packages_dir.join("go");
    std::fs::create_dir_all(&go_dir).ok();
    let go_routes = kin_registry::go::go_routes(Arc::new(kin_registry::go::GoProxyState {
        manifest_store: kin_registry::ManifestStore::new(state.layout.root()),
        blobs_dir: go_dir,
    }));

    // The package registries (cargo/npm/oci/go) are PUBLIC services with their
    // own per-write gates (cargo: `KIN_REGISTRY_CARGO_TOKEN`; npm:
    // `KIN_REGISTRY_NPM_AUTH_URL` introspection); their reads stay open. The
    // daemon API is a PROTECTED control surface. So `daemon_auth` is scoped to
    // ONLY the daemon routes — applied as an inner `.layer()` on the daemon
    // sub-router before it is merged — and must NOT wrap the registry routers.
    //
    // Why this matters: the cloud daemon binds `0.0.0.0` (its k8s Service routes
    // to the pod IP), which `bind_listener` permits only when a daemon auth
    // token is set. If `daemon_auth` wrapped the whole app, enabling that token
    // would also gate the registry — and `cargo` does not send credentials on
    // reads (its `config.json` has no `auth-required`), so the public index and
    // downloads would 401. Scoping `daemon_auth` to the daemon routes keeps a
    // 0.0.0.0-bound, token-protected daemon serving a public registry.
    //
    // The outer layers below (`daemon_activity`, `api_version_header`,
    // `validate_host_and_origin`) still apply to EVERYTHING, registry included.
    let daemon_routes = Router::new()
        .merge(routes.clone())
        .nest("/v1", routes)
        .layer(middleware::from_fn_with_state(
            DaemonAuthState { auth_token },
            daemon_auth,
        ))
        .with_state(state);

    let app = Router::new()
        .merge(daemon_routes)
        .merge(cargo_routes)
        .merge(npm_routes)
        .merge(oci_routes)
        .merge(go_routes)
        .layer(middleware::from_fn_with_state(
            activity_state,
            daemon_activity,
        ))
        .layer(middleware::from_fn(api_version_header))
        .layer(middleware::from_fn(validate_host_and_origin));

    // Synthetic in-process tower test requests (`Request::get("/…")`) omit the
    // Host header that every real HTTP/1.1 client — and the production
    // `axum::serve` path — always sends. Without it the
    // `validate_host_and_origin` missing-Host guard would 403 the entire unit
    // suite. This cfg(test)-only shim restores that realism by defaulting an
    // absent Host to loopback; it layers OUTSIDE (runs before) the guard and is
    // compiled out of production and integration builds. The guard's
    // missing-Host behaviour is covered directly by
    // `host_header_required_on_non_public_routes`.
    #[cfg(test)]
    let app = app.layer(middleware::from_fn(inject_loopback_host_in_tests));

    app
}

/// Test-only: default an absent `Host` header to loopback so synthetic tower
/// requests survive the `validate_host_and_origin` missing-Host guard. Never
/// compiled into production builds (`#[cfg(test)]`).
#[cfg(test)]
async fn inject_loopback_host_in_tests(
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !request.headers().contains_key(header::HOST) {
        request.headers_mut().insert(
            header::HOST,
            axum::http::HeaderValue::from_static("127.0.0.1"),
        );
    }
    next.run(request).await
}

/// Extract an optional session ID from the `X-Kin-Session` header or
/// `?session_id=` query parameter. Header takes precedence.
fn extract_session_id_from_headers(
    headers: &axum::http::HeaderMap,
) -> Result<Option<SessionId>, (StatusCode, String)> {
    if let Some(val) = headers.get("X-Kin-Session") {
        let s = val.to_str().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "invalid X-Kin-Session header".to_string(),
            )
        })?;
        return Ok(Some(parse_session_id(s)?));
    }
    Ok(None)
}

/// Resolve the graph for a request: scoped historical graph if the session
/// has an active temporal scope, otherwise the live HEAD graph.
///
/// Delegates to `DaemonState::graph_for_request` so the scope-routing
/// decision lives next to the scope storage and stays unit-testable.
async fn resolve_session_graph(
    state: &DaemonState,
    session_id: Option<&SessionId>,
) -> Arc<kin_db::InMemoryGraph> {
    state.graph_for_request(session_id).await
}

/// GET /health — liveness check with extended diagnostics.
/// Supports `?repo=X` to report health for a specific repo's graph.
async fn health(
    Query(repo_query): Query<RepoQuery>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(repo_id) = repo_query.repo {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "/health is liveness-only and will not lazy-load repo graphs; use /repos/{repo_id}/health"
            ),
        ));
    }
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let graph = Arc::clone(&state.graph);
    let entity_count = graph.entity_count();
    let graph_loaded = entity_count > 0;
    let external_session_count = state
        .coordinator
        .list_sessions()
        .map(|sessions| {
            sessions
                .iter()
                .filter(|session| session.vendor != "kin-daemon")
                .count() as u64
        })
        .unwrap_or(0);

    let initialized = state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed);
    let mass_deletion_blocked = state
        .mass_deletion_blocked
        .load(std::sync::atomic::Ordering::Relaxed);
    let embed_worker_failed = state
        .embed_worker_failed
        .load(std::sync::atomic::Ordering::Relaxed);
    // Surface graph-safety + derived-index health in the top-level status so an
    // operator or client polling /health sees a non-"ok" signal when the daemon
    // is withholding a suspected mass-deletion wipe OR the embedding worker has
    // permanently stopped (embed-degraded). The graph itself stays intact and
    // served in both cases.
    let status = if mass_deletion_blocked || embed_worker_failed {
        "attention"
    } else {
        "ok"
    };

    Ok(Json(HealthResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        graph_entity_count: Some(entity_count),
        graph_loaded,
        reconciliation_status: state.reconciliation_status_str().to_string(),
        repo_id: primary_repo_id(&state),
        repo_root: state
            .layout
            .working_dir()
            .canonicalize()
            .unwrap_or_else(|_| state.layout.working_dir().to_path_buf())
            .display()
            .to_string(),
        pid: std::process::id(),
        active_request_count: state.active_request_count(),
        event_subscriber_count: state.event_tx.receiver_count() as u64,
        external_session_count,
        idle_seconds: state.idle_duration().as_secs(),
        initialized,
        mass_deletion_blocked,
        embed_worker_failed,
        graph_generation: DaemonState::read_generation_marker(&state.layout),
        build: current_build_response(),
    }))
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

/// POST /session — register a rich session and return its authoritative state.
async fn start_session(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<StartSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let transport = parse_session_transport(&request.transport)?;
    let session_id = state
        .coordinator
        .register_session(
            &request.vendor,
            &request.client_name,
            transport,
            request.pid,
            PathBuf::from(request.cwd),
            request.capabilities,
        )
        .map_err(internal_error)?;
    let session = state
        .coordinator
        .get_session(&session_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("session missing after registration: {session_id}"),
            )
        })?;

    Ok(Json(SessionStartResponse {
        session_id: session.session_id.to_string(),
        vendor: session.vendor,
        client_name: session.client_name,
        transport: session.transport,
        started_at: session.started_at,
        capabilities: session.capabilities,
        status: "active".to_string(),
    }))
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

/// POST /session/{session_id}/heartbeat — record a session heartbeat.
async fn session_heartbeat(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    state
        .coordinator
        .heartbeat(&session_id)
        .map_err(internal_error)?;

    let session = state
        .coordinator
        .get_session(&session_id)
        .map_err(internal_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "session not found".to_string()))?;

    Ok(Json(SessionHeartbeatResponse {
        session_id: session.session_id.to_string(),
        status: "active".to_string(),
        heartbeat_at: session.last_heartbeat,
    }))
}

fn open_repo(path: &std::path::Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

fn resolve_scope_build_timeout(raw: Option<&str>) -> Duration {
    let seconds = raw
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(870)
        .max(1);
    Duration::from_secs(seconds)
}

fn scope_build_timeout() -> Duration {
    resolve_scope_build_timeout(
        std::env::var("KIN_DAEMON_SCOPE_BUILD_TIMEOUT_SECS")
            .ok()
            .as_deref(),
    )
}

/// POST /session/{session_id}/scope — set a temporal scope for a session.
async fn set_scope(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<SetScopeRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    // Validate session exists
    state
        .coordinator
        .get_session(&session_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("session not found: {session_id}"),
            )
        })?;

    // Offload the heavy computation to a blocking thread to keep the main event loop responsive
    let state_clone = Arc::clone(&state);
    let ref_string = req.ref_string.clone();
    let timeout = scope_build_timeout();
    let scope_task = tokio::task::spawn_blocking(
        move || -> std::result::Result<_, (StatusCode, String)> {
            // Resolve the ref to a SemanticChangeId using the LOCATE resolve mode
            // (enrich_semantics=false). Scope-for-retrieval only needs the
            // base_commit's tree state; the full per-commit semantic-delta enrichment
            // of its entire ancestry ("Hydrating History: [n/26747]") re-parses and
            // re-links every ancestor commit — ~10 min on a deep base_commit — and the
            // session-scope locate path never reads those deltas (it ranks the scoped
            // entity set with HEAD vectors via `vector_source`). The /locate ref path
            // already uses this lighter mode.
            let resolved =
            kin_cli::commands::ref_lookup::resolve_ref_importing_git_if_needed_for_locate_with_report(
                state_clone.graph.as_ref(),
                &state_clone.layout,
                Some(&ref_string),
            )
            .map_err(|err| (StatusCode::BAD_REQUEST, format!("{:#}", err)))?;
            if resolved.hydrated_git_history {
                state_clone.bump_version();
                state_clone.save_snapshot().map_err(internal_error)?;
                state_clone.mark_clean();
            }
            let head = resolved.head;

            // Build the historical graph at that ref, using cached OID mapping
            // for fast scope switching without re-walking the commit DAG.
            let oid_cache: Option<kin_core::ChangeOidCache> = {
                let needs_build = read_recover(&state_clone.change_oid_cache).is_none();
                if needs_build {
                    if let Ok(repo) = open_repo(state_clone.layout.working_dir()) {
                        match kin_core::build_change_oid_cache(&repo) {
                            Ok(cache) => {
                                info!("built change OID cache for fast scope switching");
                                *write_recover(&state_clone.change_oid_cache) = Some(cache);
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to build change OID cache, falling back to per-call lookup");
                            }
                        }
                    }
                }
                read_recover(&state_clone.change_oid_cache).clone()
            };
            let historical = if let Some(git_oid) = ref_string.strip_prefix("git:") {
                kin_core::build_graph_at_git_ref_with_repo(
                    state_clone.graph.as_ref(),
                    state_clone.blobs.as_ref(),
                    &head,
                    state_clone.layout.working_dir(),
                    git_oid,
                    oid_cache.as_ref(),
                )
            } else {
                kin_core::build_graph_at_ref_with_repo(
                    state_clone.graph.as_ref(),
                    state_clone.blobs.as_ref(),
                    &head,
                    Some(state_clone.layout.working_dir()),
                    oid_cache.as_ref(),
                )
            }
            .map_err(internal_error)?;

            // Refresh cochange relations from the historical change set so the
            // cached graph matches what run_with_graph_capture_at_ref() produces.
            let changes = kin_core::collect_changes_at_ref(&historical, &head)
                .map_err(|err| internal_error(err.to_string()))?;
            let _ = kin_cli::commands::cochange::refresh_from_changes(&historical, &changes);

            let cached_graph = Arc::new(historical);

            Ok((head, cached_graph))
        },
    );
    let (head, cached_graph) = match tokio::time::timeout(timeout, scope_task).await {
        Ok(joined) => joined.map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn_blocking failed: {err}"),
            )
        })??,
        Err(_) => {
            tracing::warn!(
                session = %session_id,
                ref_string = %req.ref_string,
                timeout_secs = timeout.as_secs(),
                "temporal scope build timed out"
            );
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                format!(
                    "temporal scope build timed out after {}s for {}",
                    timeout.as_secs(),
                    req.ref_string
                ),
            ));
        }
    };

    state
        .set_session_scope(&session_id, req.ref_string.clone(), head, cached_graph)
        .await;

    info!(
        session = %session_id,
        ref_string = %req.ref_string,
        "temporal scope set"
    );

    Ok(Json(ScopeResponse {
        ref_string: req.ref_string,
        head: head.to_string(),
        created_at_secs_ago: 0,
        ttl_remaining_secs: crate::state::DEFAULT_SCOPE_TTL.as_secs(),
    }))
}

/// DELETE /session/{session_id}/scope — clear a session's temporal scope.
async fn clear_scope(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    state.clear_session_scope(&session_id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /session/{session_id}/scope — query a session's temporal scope.
async fn get_scope(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    match state.get_session_scope(&session_id).await {
        Some((ref_string, head, created_at, ttl)) => {
            let elapsed = created_at.elapsed();
            let ttl_remaining = ttl.saturating_sub(elapsed);
            Ok(Json(ScopeResponse {
                ref_string,
                head: head.to_string(),
                created_at_secs_ago: elapsed.as_secs(),
                ttl_remaining_secs: ttl_remaining.as_secs(),
            })
            .into_response())
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

/// POST /graph/commit — accepts a full semantic commit from the CLI and applies it to Truth.
async fn graph_commit(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<DaemonCommitRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kin_model::{EntityDelta, RelationDelta};

    let graph = &*state.graph;

    // --- Lease enforcement gate ---
    // Collect the entity scopes touched by this commit and check for hard
    // lock conflicts. If another session holds a hard lease on any scope
    // in the write set, reject with 409 Conflict.
    {
        use kin_model::session::IntentScope;

        let mut scopes: Vec<IntentScope> = Vec::new();
        for delta in &request.change.entity_deltas {
            match delta {
                EntityDelta::Added(e) => scopes.push(IntentScope::Entity(e.id)),
                EntityDelta::Modified { new, .. } => scopes.push(IntentScope::Entity(new.id)),
                EntityDelta::Removed(id) => scopes.push(IntentScope::Entity(*id)),
            }
        }

        if !scopes.is_empty() {
            let caller_session = request
                .session_id
                .as_ref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok().map(kin_model::SessionId));
            let traffic = state
                .coordinator
                .check_traffic(&scopes)
                .map_err(internal_error)?;
            if traffic.has_hard_blocks {
                // Filter out blocks owned by the caller's own session.
                let foreign_blocks: Vec<_> = traffic
                    .reports
                    .iter()
                    .flat_map(|r| r.active_intents.iter())
                    .filter(|s| {
                        s.lock_type == kin_model::session::LockType::Hard
                            && caller_session.as_ref().is_none_or(|cs| &s.session_id != cs)
                    })
                    .collect();
                if !foreign_blocks.is_empty() {
                    let body = serde_json::json!({
                        "error": "lease_conflict",
                        "conflict_type": "HardCollision",
                        "blocking_intents": foreign_blocks.iter().map(|b| {
                            serde_json::json!({
                                "intent_id": b.intent_id.to_string(),
                                "session_id": b.session_id.to_string(),
                                "lock_type": format!("{:?}", b.lock_type),
                                "task_description": b.task_description,
                            })
                        }).collect::<Vec<_>>(),
                        "message": format!(
                            "commit blocked: {} entity scope(s) held by active hard lease(s)",
                            foreign_blocks.len()
                        ),
                    });
                    return Err((StatusCode::CONFLICT, body.to_string()));
                }
            }
        }
    }

    for delta in &request.change.entity_deltas {
        match delta {
            EntityDelta::Added(e) => {
                graph.upsert_entity(e).map_err(internal_error)?;
            }
            EntityDelta::Modified { new, .. } => {
                graph.upsert_entity(new).map_err(internal_error)?;
            }
            EntityDelta::Removed(id) => {
                graph.remove_entity(id).map_err(internal_error)?;
            }
        }
    }

    for delta in &request.change.relation_deltas {
        match delta {
            RelationDelta::Added(r) => {
                graph.upsert_relation(r).map_err(internal_error)?;
            }
            RelationDelta::Removed(id) => {
                graph.remove_relation(id).map_err(internal_error)?;
            }
        }
    }

    for clear in &request.shallow_clears {
        graph.delete_shallow_file(clear).map_err(internal_error)?;
    }

    for sf in &request.shallow_files {
        graph.upsert_shallow_file(sf).map_err(internal_error)?;
    }

    graph
        .create_change(&request.change)
        .map_err(internal_error)?;
    if graph
        .get_branch(&request.branch_name)
        .map_err(internal_error)?
        .is_some()
    {
        graph
            .update_branch_head(&request.branch_name, &request.change.id)
            .map_err(internal_error)?;
    } else {
        graph
            .create_branch(&Branch {
                name: request.branch_name.clone(),
                head: request.change.id,
            })
            .map_err(internal_error)?;
    }

    if let Some(audit) = &request.audit_event {
        graph.record_audit_event(audit).map_err(internal_error)?;
    }

    // Broadcast root hash change and compact the delta journal at the commit boundary.
    state.bump_version();
    state.save_snapshot_full().map_err(internal_error)?;
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: request.change.id.to_string(),
    });

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// POST /graph/mutations — apply daemon-authoritative graph metadata writes
/// that are not represented as SemanticChange commits.
async fn graph_mutations(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<GraphMutationBatch>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let graph = state.graph.as_ref();
    for item in &request.work_items {
        graph.create_work_item(item).map_err(internal_error)?;
    }
    for update in &request.work_status_updates {
        graph
            .update_work_status(&update.work_id, update.status)
            .map_err(internal_error)?;
    }
    for link in &request.work_links {
        graph.create_work_link(link).map_err(internal_error)?;
    }
    for ann in &request.annotations {
        graph.create_annotation(ann).map_err(internal_error)?;
    }
    for audit in &request.audit_events {
        kin_cli::provenance::record_cli_audit_event(
            graph,
            &audit.action,
            audit.target_scope.clone(),
            audit.details.clone(),
        )
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }

    state.bump_version();
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: "graph-mutations".to_string(),
    });

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// POST /commands/status — render CLI status from daemon-owned graph state.
async fn command_status(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::status::CommandStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let summary = kin_cli::commands::status::build_status_summary(&state.layout, graph.as_ref())
        .map_err(internal_error)?;
    let daemon_build = kin_buildinfo::get();
    let build = kin_cli::commands::status::BuildStatus {
        cli_sha: request
            .cli_sha
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        cli_dirty: request.cli_dirty,
        daemon_sha: daemon_build.sha.to_string(),
        daemon_dirty: daemon_build.dirty,
    };
    let response = kin_cli::commands::status::build_command_status_response(
        summary,
        request.json,
        Some(build),
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/resources — detect the resource plan for a profile and attach
/// live daemon embedding state. Inspect-only: never loads a model or embeds.
async fn command_resources(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::resources::CommandResourcesRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let profile = kin_cli::commands::resources::parse_profile(request.profile.as_deref())
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let plan = kin_infer::resource::ResourcePlan::detect(profile);

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let embed_status = graph.embedding_status();
    let embed_runtime = kin_cli::commands::resources::EmbedRuntimeState {
        embed_worker_failed: state
            .embed_worker_failed
            .load(std::sync::atomic::Ordering::Relaxed),
        embedding_work_busy: state.embedding_work.try_lock().is_err(),
        embeddings_indexed: embed_status.indexed,
        embeddings_pending: embed_status.pending,
        embeddings_total: embed_status.total,
        hybrid_metrics: hybrid_metrics_runtime(),
        metal_profile: metal_profile_runtime(),
    };

    let actual = kin_cli::commands::resources::ActualResources::capture();
    let response = kin_cli::commands::resources::build_command_resources_response(
        plan,
        embed_runtime,
        actual,
        request.json,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

fn hybrid_metrics_runtime() -> kin_cli::commands::resources::HybridMetricsRuntime {
    #[cfg(feature = "embeddings")]
    {
        let stats = kin_db::embed::hybrid_metrics::snapshot();
        return kin_cli::commands::resources::HybridMetricsRuntime {
            gpu_entities: stats.gpu_entities,
            gpu_tokens: stats.gpu_tokens,
            cpu_twin_entities: stats.cpu_twin_entities,
            cpu_twin_tokens: stats.cpu_twin_tokens,
            hybrid_batches: stats.hybrid_batches,
            single_side_batches: stats.single_side_batches,
            twin_unavailable_batches: stats.twin_unavailable_batches,
            cpu_parallel_batches: stats.cpu_parallel_batches,
        };
    }

    #[cfg(not(feature = "embeddings"))]
    {
        kin_cli::commands::resources::HybridMetricsRuntime::default()
    }
}

#[cfg(all(feature = "metal", target_os = "macos"))]
fn metal_profile_runtime() -> Option<kin_cli::commands::resources::MetalProfileRuntime> {
    std::env::var_os("KIN_INFER_METAL_PROFILE")?;
    let forward_calls = kin_infer::metal_backend::profile_forward_calls();
    let gpu_phase_nanos = kin_infer::metal_backend::profile_gpu_phase_nanos()
        .into_iter()
        .map(
            |(phase, nanos)| kin_cli::commands::resources::MetalPhaseRuntime {
                phase: phase.to_string(),
                nanos,
            },
        )
        .collect::<Vec<_>>();
    let gpu_total_nanos = gpu_phase_nanos.iter().map(|phase| phase.nanos).sum();
    let host_blocked_nanos = kin_infer::metal_backend::profile_host_blocked_nanos();
    Some(kin_cli::commands::resources::MetalProfileRuntime {
        submissions: kin_infer::metal_backend::profile_submissions(),
        round_trips: kin_infer::metal_backend::profile_round_trips(),
        forward_calls,
        host_blocked_nanos,
        host_blocked_nanos_per_forward: nanos_per_forward(host_blocked_nanos, forward_calls),
        gpu_phase_nanos,
        gpu_total_nanos,
    })
}

#[cfg(any(test, all(feature = "metal", target_os = "macos")))]
fn nanos_per_forward(total_nanos: u64, forward_calls: u64) -> Option<u64> {
    (forward_calls > 0).then(|| total_nanos / forward_calls)
}

#[cfg(not(all(feature = "metal", target_os = "macos")))]
fn metal_profile_runtime() -> Option<kin_cli::commands::resources::MetalProfileRuntime> {
    None
}

/// POST /commands/graph — render graph CLI commands from daemon-owned graph state.
async fn command_graph(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::graph::GraphCommandRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::graph::execute_graph_command(&state.layout, graph.as_ref(), &request)
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/overview — render overview from daemon-owned graph state.
async fn command_overview(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::overview::OverviewRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let repo_name = state
        .layout
        .working_dir()
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::overview::build_overview_response(&repo_name, graph.as_ref(), &request)
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/dead-code — render dead-code scan from daemon-owned graph state.
async fn command_dead_code(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(_request): Json<kin_cli::commands::dead_code::DeadCodeRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::dead_code::build_dead_code_response(graph.as_ref())
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/dead-code-seeded — seeded dead-code classification.
///
/// Combines `semantic_search(query)` + per-candidate incoming-reference count
/// + dead-filter into a single daemon-graph traversal. Closes the
/// find-dead-code token blowup where the agent loops `semantic_search` →
/// `find_references` per entity on large repos.
async fn command_dead_code_seeded(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::dead_code::DeadCodeSeededRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::dead_code::build_dead_code_seeded_response(graph.as_ref(), &request)
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/trace-data-flow — return the actual call/data-flow chain
/// rooted at a focal entity in a single substrate call.
///
/// Closes the trace-computation accuracy gap (Fix #3 in the per-family
/// accuracy plan) where the agent loops `get_entity_source` per step and
/// exhausts the 24-round tool-call cap on large repos.
async fn command_trace_data_flow(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::trace_data_flow::TraceDataFlowRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::trace_data_flow::build_trace_data_flow_response(
        &state.layout,
        graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/refs — render incoming references from daemon-owned graph state.
async fn command_refs(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::refs::RefsRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::refs::build_refs_response(&state.layout, graph.as_ref(), &request)
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/bulk-refs — classify reachability for many entities in a single
/// daemon-graph traversal. Closes the find-dead-code / count-real-callers token
/// blowup where the agent makes one find_references call per entity.
async fn command_bulk_refs(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::refs::BulkRefsRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::refs::build_bulk_refs_response(graph.as_ref(), &request)
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/xref — render cross-repo references from daemon-owned graph state.
async fn command_xref(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::xref::XrefRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::xref::build_xref_response(&state.layout, graph.as_ref(), &request)
            .await
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/diff — render semantic diffs from daemon-owned graph state.
async fn command_diff(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::diff::DiffRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::diff::build_diff_response(graph.as_ref(), &request)
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/log — render semantic logs from daemon-owned graph state.
async fn command_log(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::log::LogRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response =
        kin_cli::commands::log::build_log_response(&state.layout, graph.as_ref(), &request)
            .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/audit — render audit events from daemon-owned graph state.
async fn command_audit(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::audit::AuditRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::audit::build_audit_response(graph.as_ref(), &request)
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/approvals — render approvals from daemon-owned graph state.
async fn command_approvals(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::approvals::ApprovalsRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::approvals::build_approvals_response(graph.as_ref(), &request)
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/security — render security scan from daemon-owned graph state.
async fn command_security(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::security::SecurityRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let response = kin_cli::commands::security::build_security_response(graph.as_ref(), &request)
        .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/branch — run branch lifecycle commands in the repo daemon.
async fn command_branch(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::branch::BranchRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let response = kin_cli::commands::branch::execute_branch_request(
        &state.layout,
        state.graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    if response.mutated {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: "branch-state".to_string(),
        });
    }
    Ok(Json(response))
}

/// POST /commands/checkout — restore files through daemon-owned graph state.
async fn command_checkout(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::checkout::CheckoutRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;

    let response = kin_cli::commands::checkout::execute_checkout_request(
        &state.layout,
        graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/rename — build rename plans from daemon-owned graph state.
async fn command_rename(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::rename::RenameRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let response = kin_cli::commands::rename::build_rename_response(
        &state.layout,
        state.graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/session-workspace — materialize graph-owned files for sessions.
async fn command_session_workspace(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::session_workspace::SessionWorkspaceRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let response = kin_cli::commands::session_workspace::materialize_session_workspace(
        &state.layout,
        state.graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/exec — execute inside a daemon-materialized graph workspace.
/// Whether the daemon is permitted to run shell command execution
/// (`POST /commands/exec`, which spawns `sh -c`). This is a high-risk
/// capability (local RCE if an unauthorized caller reaches the loopback
/// daemon), so it stays disabled unless the operator explicitly opts in via
/// `KIN_DAEMON_ALLOW_EXEC`. Being initialized is necessary but NOT sufficient.
fn exec_capability_enabled() -> bool {
    std::env::var("KIN_DAEMON_ALLOW_EXEC")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

async fn command_exec(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<kin_cli::commands::exec::ExecRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    if !exec_capability_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            "command execution is disabled; set KIN_DAEMON_ALLOW_EXEC=1 to opt in to daemon-side `sh -c` execution".to_string(),
        ));
    }

    let response = kin_cli::commands::exec::execute_exec_request(
        &state.layout,
        state.graph.as_ref(),
        &request,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

// ── Thin-Client Commands ─────────────────────────────────────────────────

/// POST /commands/commit — Thin-client commit endpoint.
///
/// The daemon runs the entire commit pipeline: reconcile pending file changes,
/// build entity deltas from the working copy overlay, create the semantic change,
/// and update the branch head. The CLI just sends the message and dry_run flag.
///
/// This replaces the old pattern where the CLI did all parsing locally and
/// POSTed the pre-built SemanticChange to /graph/commit.
#[derive(Debug, Deserialize)]
struct CommandCommitRequest {
    message: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandCommitResponse {
    change_id: String,
    branch: String,
    entity_count: usize,
    relation_count: usize,
    file_count: usize,
}

async fn command_commit(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<CommandCommitRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Force a filesystem sync to guarantee the daemon has reconciled all offline changes
    // before building the commit deltas.
    let _ = crate::loop_runner::sync_filesystem_with_graph(&state).await;

    let graph = &*state.graph;

    // Read current branch from the .kin/HEAD file.
    let branch_name = kin_core::read_current_branch(&state.layout).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read HEAD: {e}"),
        )
    })?;

    // Ensure the branch exists in the graph (bootstrap if needed).
    let branch = graph
        .get_branch(&branch_name)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("branch '{}' not found", branch_name),
            )
        })?;

    // Compute deltas reconstructively by diffing current graph state against
    // the last-committed change-DAG node.  The reconcile loop's
    // `apply_overlay_to_graph` folds mutations into the primary graph and
    // then clears the working-copy overlay, so reading the overlay here
    // would always produce empty deltas.  Instead we walk the change DAG
    // from genesis to branch.head to reconstruct the committed baseline,
    // then diff it against the live graph — robust regardless of overlay drain timing.
    let commit_deltas = crate::commit_deltas::compute_deltas_vs_last_commit(
        graph,
        state.blobs.as_ref(),
        &state.layout,
        &branch.head,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to compute commit deltas: {e}"),
        )
    })?;

    let entity_deltas = commit_deltas.entity_deltas;
    let relation_deltas = commit_deltas.relation_deltas;
    let artifact_deltas = commit_deltas.artifact_deltas;

    let entity_count = entity_deltas.len();
    let relation_count = relation_deltas.len();
    let file_count = artifact_deltas.len();

    // --- Lease enforcement gate (same as /graph/commit) ---
    {
        use kin_model::session::IntentScope;

        let scopes: Vec<IntentScope> = entity_deltas
            .iter()
            .map(|d| match d {
                kin_model::EntityDelta::Added(e) => IntentScope::Entity(e.id),
                kin_model::EntityDelta::Modified { new, .. } => IntentScope::Entity(new.id),
                kin_model::EntityDelta::Removed(ref id) => IntentScope::Entity(*id),
            })
            .collect();

        if !scopes.is_empty() {
            let caller_session = request
                .session_id
                .as_ref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok().map(kin_model::SessionId));
            let traffic = state
                .coordinator
                .check_traffic(&scopes)
                .map_err(internal_error)?;
            if traffic.has_hard_blocks {
                let foreign_blocks: Vec<_> = traffic
                    .reports
                    .iter()
                    .flat_map(|r| r.active_intents.iter())
                    .filter(|s| {
                        s.lock_type == kin_model::session::LockType::Hard
                            && caller_session.as_ref().is_none_or(|cs| &s.session_id != cs)
                    })
                    .collect();
                if !foreign_blocks.is_empty() {
                    let body = serde_json::json!({
                        "error": "lease_conflict",
                        "conflict_type": "HardCollision",
                        "blocking_intents": foreign_blocks.iter().map(|b| {
                            serde_json::json!({
                                "intent_id": b.intent_id.to_string(),
                                "session_id": b.session_id.to_string(),
                                "lock_type": format!("{:?}", b.lock_type),
                                "task_description": b.task_description,
                            })
                        }).collect::<Vec<_>>(),
                        "message": format!(
                            "commit blocked: {} entity scope(s) held by active hard lease(s)",
                            foreign_blocks.len()
                        ),
                    });
                    return Err((StatusCode::CONFLICT, body.to_string()));
                }
            }
        }
    }

    if request.dry_run {
        return Ok(Json(CommandCommitResponse {
            change_id: "dry-run".to_string(),
            branch: branch_name.to_string(),
            entity_count,
            relation_count,
            file_count,
        }));
    }

    // Create the semantic change.
    let content_id =
        kin_core::content_identity_from_deltas(&entity_deltas, &relation_deltas, &artifact_deltas);
    let change = kin_model::SemanticChange {
        id: kin_core::compute_change_id(&request.message, &branch.head, &content_id),
        parents: vec![branch.head],
        author: kin_model::AuthorId::new(kin_core::whoami()),
        message: request.message,
        timestamp: kin_model::Timestamp::now(),
        entity_deltas,
        relation_deltas,
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: None,
    };

    let change_id = change.id;

    graph.create_change(&change).map_err(internal_error)?;
    graph
        .update_branch_head(&branch_name, &change_id)
        .map_err(internal_error)?;

    // Clear the working copy overlay — mutations are now committed.
    let mut working_copy = state.working_copy.write().await;
    working_copy.base_change = change_id;
    working_copy.uncommitted_mutations = kin_model::GraphOverlay::default();
    drop(working_copy);

    // Broadcast events and mark dirty for background persistence.
    state.bump_version();
    state.save_snapshot_full().map_err(internal_error)?;
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: change_id.to_string(),
    });

    Ok(Json(CommandCommitResponse {
        change_id: change_id.to_string(),
        branch: branch_name.to_string(),
        entity_count,
        relation_count,
        file_count,
    }))
}

// ── Branch Management ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateBranchRequest {
    name: String,
    head: String,
}

#[derive(Debug, Serialize)]
struct BranchResponse {
    name: String,
    head: String,
}

async fn graph_list_branches(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let branches = state.graph.list_branches().map_err(internal_error)?;
    let resp: Vec<BranchResponse> = branches
        .into_iter()
        .map(|b| BranchResponse {
            name: b.name.to_string(),
            head: b.head.to_string(),
        })
        .collect();

    Ok((StatusCode::OK, Json(resp)))
}

async fn graph_create_branch(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<CreateBranchRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    use kin_model::{Branch, BranchName, Hash256, SemanticChangeId};

    let head_hash = Hash256::from_hex(&request.head).map_err(bad_request)?;
    let branch = Branch {
        name: BranchName::new(&request.name),
        head: SemanticChangeId::from_hash(head_hash),
    };

    state.graph.create_branch(&branch).map_err(internal_error)?;
    state.bump_version();

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn graph_delete_branch(
    Path(name): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    use kin_model::BranchName;
    state
        .graph
        .delete_branch(&BranchName::new(&name))
        .map_err(internal_error)?;
    state.bump_version();

    Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))))
}

#[derive(Debug, Deserialize)]
struct UpdateBranchHeadRequest {
    head: String,
}

async fn graph_update_branch_head(
    Path(name): Path<String>,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<UpdateBranchHeadRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    use kin_model::{BranchName, Hash256, SemanticChangeId};

    let head_hash = Hash256::from_hex(&request.head).map_err(bad_request)?;

    state
        .graph
        .update_branch_head(
            &BranchName::new(&name),
            &SemanticChangeId::from_hash(head_hash),
        )
        .map_err(internal_error)?;

    // Broadcast root hash change. bump_version() marks dirty for background persistence.
    state.bump_version();
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: request.head,
    });

    Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))))
}

/// DELETE /session/{session_id} — end a session and release its intents.
async fn end_session(
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
    state
        .coordinator
        .deregister_session(&session_id)
        .map_err(internal_error)?;

    Ok(Json(SessionEndResponse {
        session_id: session.session_id.to_string(),
        vendor: session.vendor,
        status: "ended".to_string(),
        started_at: session.started_at,
        ended_at: kin_model::timestamp::Timestamp::now(),
    }))
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
    let mut scope_values = request.scopes;
    if scope_values.is_empty() {
        if request.scope.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "missing required scope or scopes".to_string(),
            ));
        }
        scope_values.push(request.scope);
    }
    let scopes = scope_values
        .iter()
        .map(|scope| parse_scope(scope))
        .collect::<Result<Vec<_>, _>>()?;
    let lock_type = parse_lock_type(&request.lock_type)?;
    let session_id = resolve_or_create_session(&state, request.session_id.as_deref())?;
    let result = state
        .coordinator
        .register_intent(
            &session_id,
            scopes,
            lock_type,
            &request.task_description,
            request
                .expires_at
                .as_deref()
                .map(parse_timestamp)
                .transpose()?,
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

/// GET /graph/bootstrap — export the daemon-authoritative primary graph snapshot.
/// If the request includes an `X-Kin-Session` header and the session has an
/// active temporal scope, exports the scoped historical graph instead.
fn bootstrap_export_semaphore() -> Arc<tokio::sync::Semaphore> {
    BOOTSTRAP_EXPORTS
        .get_or_init(|| {
            let limit = std::env::var("KIN_DAEMON_BOOTSTRAP_EXPORT_CONCURRENCY")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1)
                .max(1);
            Arc::new(tokio::sync::Semaphore::new(limit))
        })
        .clone()
}

async fn export_graph_snapshot_bytes(
    graph: Arc<kin_db::InMemoryGraph>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let permit = bootstrap_export_semaphore()
        .acquire_owned()
        .await
        .map_err(internal_error)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        graph
            .serialize_snapshot_borrowed()
            .map(|(bytes, _)| bytes)
            .map_err(internal_error)
    })
    .await
    .map_err(internal_error)?
}

async fn graph_bootstrap(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let bytes = export_graph_snapshot_bytes(graph).await?;

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

/// POST /locate — run locate against the daemon-resident graph and return the
/// same JSON payload as `kin locate --json`.
///
/// Session scope support: if an `X-Kin-Session` header is present and the
/// session has an active temporal scope, the scoped graph is used for queries
/// that don't specify an explicit `--ref`. Explicit `reference` always wins.
async fn locate(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::daemon_client::LocateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = extract_session_id_from_headers(&headers)?;

    // Resolve the bounded-snippet projection for this request. Off by default
    // (CLI human path, legacy clients); the agent JSON surface sets it so each
    // located definition symbol carries inline code from graph-owned content.
    let snippet_opts = if req.snippets {
        kin_cli::commands::locate::SnippetOptions::enabled(req.snippet_lines)
    } else {
        kin_cli::commands::locate::SnippetOptions::default()
    };

    tracing::info!(
        ">>> LOCATE: state.graph.embedding_status().indexed={}, graph root hash={:?}",
        state.graph.embedding_status().indexed,
        state.graph.compute_root_hash()
    );

    let result = if let Some(reference) = req.reference.as_deref() {
        // Explicit --ref always takes precedence over session scope.
        let resolved = kin_cli::commands::ref_lookup::resolve_ref_importing_git_if_needed_for_locate_with_report(
            state.graph.as_ref(),
            &state.layout,
            Some(reference),
        )
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
        if resolved.hydrated_git_history {
            state.bump_version();
            state.save_snapshot().map_err(internal_error)?;
            state.mark_clean();
        }
        let head = resolved.head;
        kin_cli::commands::locate::run_with_graph_capture_at_ref(
            &state.layout,
            state.graph.as_ref(),
            state.blobs.as_ref(),
            &head,
            reference,
            &req.text,
            req.explain,
            req.max_files,
            req.max_files_explicit,
            snippet_opts,
        )
        .map_err(|error| error.to_string())
    } else {
        // Use scoped graph if session has a temporal scope, otherwise HEAD.
        let graph = resolve_session_graph(&state, session_id.as_ref()).await;
        run_fused_locate_for_state(
            &state,
            session_id.as_ref(),
            graph.as_ref(),
            &req.text,
            req.explain,
            req.max_files,
            req.max_files_explicit,
            snippet_opts,
        )
        .await
    }
    .map_err(internal_error)?;
    Ok(Json(result))
}

/// Run the fused locate pipeline against daemon state for a non-ref query,
/// exactly as `POST /locate` serves it: session temporal scope honored,
/// historical test-artifact priority files discovered for scoped sessions,
/// and the HEAD graph passed as vector source. Shared by the `/locate`
/// endpoint and the fused `semantic_locate` MCP arm so the two agent-facing
/// retrieval surfaces cannot drift apart.
#[allow(clippy::too_many_arguments)]
async fn run_fused_locate_for_state(
    state: &Arc<DaemonState>,
    session_id: Option<&SessionId>,
    graph: &kin_db::InMemoryGraph,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    snippet_opts: kin_cli::commands::locate::SnippetOptions,
) -> Result<kin_cli::commands::locate::LocateResult, String> {
    // When a session scope is active, discover historical test artifact
    // priority files to match the ref-scoped path's behavior.
    let scope_ref_string = if let Some(sid) = session_id {
        state
            .get_session_scope(sid)
            .await
            .map(|(ref_str, _, _, _)| ref_str)
    } else {
        None
    };
    let extra_priority_files = scope_ref_string
        .as_deref()
        .map(|ref_str| {
            kin_cli::commands::locate::discover_historical_test_artifact_priority_files(
                &state.layout,
                ref_str,
                text,
            )
        })
        .unwrap_or_default();

    // Always pass the HEAD graph as vector source for embedding signals.
    // For scoped sessions, the scoped graph has no vector index — HEAD
    // vectors are queried and post-filtered to the scoped entity set.
    // For unscoped queries, the HEAD graph IS the primary graph, so
    // vector_source provides the same index — but extract_embedding_signals
    // only uses vector_source when the primary graph has no embeddings,
    // so there's no double-query.
    let vector_source = Some(state.graph.as_ref());
    let workspace_root = if scope_ref_string.is_some() {
        None
    } else {
        Some(kin_core::source_dir(&state.layout))
    };
    kin_cli::commands::locate::run_with_graph_capture_with_priority_files_and_vector_source(
        graph,
        workspace_root.as_deref(),
        text,
        explain,
        max_files,
        max_files_explicit,
        extra_priority_files,
        vector_source,
        snippet_opts,
    )
    .map_err(|error| error.to_string())
}

/// POST /search — run CLI search against daemon-owned graph state.
async fn search(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::search::DaemonSearchRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let mut result =
        kin_cli::commands::search::collect_daemon_search_response(graph.as_ref(), &req)
            .map_err(internal_error)?;
    if req.show_body {
        attach_search_bodies(
            &state.layout,
            graph.as_ref(),
            &mut result,
            req.body_limit.unwrap_or(10),
        );
    }
    Ok(Json(result))
}

/// POST /context — build context packs against daemon-owned graph state.
async fn context(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::context::ContextRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let result = kin_cli::commands::context::build_context_response(graph.as_ref(), &req)
        .map_err(internal_error)?;
    Ok(Json(result))
}

/// POST /trace — render agent navigation traces against daemon-owned graph state.
async fn trace(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::trace::TraceRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let result =
        kin_cli::commands::trace::build_trace_response(&state.layout, graph.as_ref(), &req)
            .map_err(internal_error)?;
    Ok(Json(result))
}

/// POST /impact — compute downstream impact against daemon-owned graph state.
async fn impact(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::impact::ImpactRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let result =
        kin_cli::commands::impact::build_impact_response(&state.layout, graph.as_ref(), &req)
            .await
            .map_err(internal_error)?;
    Ok(Json(result))
}

/// POST /review — run review reads and review-state mutations in the repo daemon.
async fn review(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::review::ReviewRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let mutates = matches!(
        req,
        kin_cli::commands::review::ReviewRequest::Create { .. }
            | kin_cli::commands::review::ReviewRequest::Decide { .. }
            | kin_cli::commands::review::ReviewRequest::Note { .. }
            | kin_cli::commands::review::ReviewRequest::Discuss { .. }
            | kin_cli::commands::review::ReviewRequest::Reply { .. }
            | kin_cli::commands::review::ReviewRequest::Resolve { .. }
            | kin_cli::commands::review::ReviewRequest::Assign { .. }
    );
    let graph = if mutates {
        Arc::clone(&state.graph)
    } else {
        let session_id = extract_session_id_from_headers(&headers)?;
        resolve_session_graph(&state, session_id.as_ref()).await
    };
    let execution =
        kin_cli::commands::review::execute_review_request(&state.layout, graph.as_ref(), req)
            .await
            .map_err(internal_error)?;
    if execution.mutated {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: "review-state".to_string(),
        });
    }
    Ok(Json(execution.response))
}

/// POST /work — run work item reads and mutations in the repo daemon.
async fn work(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::work::WorkRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let mutates = matches!(
        req,
        kin_cli::commands::work::WorkRequest::Create { .. }
            | kin_cli::commands::work::WorkRequest::Link { .. }
            | kin_cli::commands::work::WorkRequest::Decompose { .. }
            | kin_cli::commands::work::WorkRequest::Block { .. }
            | kin_cli::commands::work::WorkRequest::Implement { .. }
            | kin_cli::commands::work::WorkRequest::Status { .. }
            | kin_cli::commands::work::WorkRequest::Close { .. }
            | kin_cli::commands::work::WorkRequest::TodoImport { .. }
    );
    let graph = if mutates {
        Arc::clone(&state.graph)
    } else {
        let session_id = extract_session_id_from_headers(&headers)?;
        resolve_session_graph(&state, session_id.as_ref()).await
    };
    let execution =
        kin_cli::commands::work::execute_work_request(&state.layout, graph.as_ref(), req)
            .map_err(internal_error)?;
    if execution.mutated {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: "work-state".to_string(),
        });
    }
    Ok(Json(execution.response))
}

/// POST /note — run note reads, note mutations, and TODO imports in the repo daemon.
async fn note(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::note::NoteRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let mutates = matches!(
        req,
        kin_cli::commands::note::NoteRequest::Add { .. }
            | kin_cli::commands::note::NoteRequest::TodoImport { .. }
    );
    let graph = if mutates {
        Arc::clone(&state.graph)
    } else {
        let session_id = extract_session_id_from_headers(&headers)?;
        resolve_session_graph(&state, session_id.as_ref()).await
    };
    let execution =
        kin_cli::commands::note::execute_note_request(&state.layout, graph.as_ref(), req)
            .map_err(internal_error)?;
    if execution.mutated {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: "note-state".to_string(),
        });
    }
    Ok(Json(execution.response))
}

/// POST /embed — run bounded embedding work inside the repo daemon.
async fn embed(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::embed::EmbedRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let state_for_embed = Arc::clone(&state);
    let result = tokio::task::spawn_blocking(move || {
        let bounded_request = req.max_seconds.is_some_and(|seconds| seconds > 0);
        if bounded_request {
            state_for_embed.pause_background_embed();
        } else {
            state_for_embed.resume_background_embed();
        }
        // Mark the explicit pass before waiting on the embedding mutex. The
        // background worker checks this flag between batches and stands down,
        // so a foreground bounded embed cannot be starved by worker re-locks.
        let _embed_pass = state_for_embed.begin_embed_pass();
        let _guard = state_for_embed
            .embedding_work
            .lock()
            .map_err(|_| "embedding work lock poisoned".to_string())?;
        // Suppress the background idle flush for the duration of the pass —
        // this handler does its own pre/per-batch/post persistence, and a
        // full-graph flush per feed gap amplifies FS churn on large repos.

        // Pin graph.kndb on disk at the current root hash H before embedding so
        // the per-batch kvec flushes (which tag metadata with H) match on reopen.
        // The vector index is a pure sidecar (not in the merkle root), so
        // embedding never changes H; this only closes the mutated-but-unsaved
        // window. Cost: one snapshot write up front.
        // save_snapshot() acquires persist_lock internally; the non-reentrant std
        // Mutex self-deadlocks if we hold persist_lock across this call (this was
        // the daemon embed hang — the worker wedged here before embedding started).
        state_for_embed
            .save_snapshot()
            .map_err(|error| format!("embed pre-persist save failed: {error:#}"))?;

        let persist_state = Arc::clone(&state_for_embed);
        let persist_batch =
            || -> Result<(), kin_db::KinDbError> { persist_foreground_embed_batch(&persist_state) };

        // Rebuild migration: drop any loaded vector index (which may be sized to
        // an older model's dimension, e.g. a 384-dim index that rejects the
        // current 768-dim model) and re-queue every entity/artifact so the embed
        // pass below recreates the index at the live embedder dimension. The
        // per-batch persist then overwrites the stale on-disk sidecar. The
        // explicit re-queue guarantees a FULL rebuild even if the embedding queue
        // already held a partial set from prior graph mutations (the gated
        // queue-missing pass in build_embed_response only fires on an empty
        // queue). A normal embed (rebuild=false) leaves graph state untouched.
        if req.rebuild {
            state_for_embed.graph.reset_vector_index();
            state_for_embed.graph.queue_missing_for_embedding();
            state_for_embed
                .graph
                .queue_missing_artifacts_for_embedding();
        }

        let is_cancelled = || {
            state_for_embed
                .is_shutdown
                .load(std::sync::atomic::Ordering::Relaxed)
        };

        let result = kin_cli::commands::embed::build_embed_response(
            &state_for_embed.layout,
            state_for_embed.graph.as_ref(),
            &req,
            persist_batch,
            is_cancelled,
        )
        .map_err(|error| format!("embed build failed: {error:#}"))?;
        if !bounded_request || !result.result.time_limited {
            state_for_embed.resume_background_embed();
        }
        if result.result.total_entities > 0 || result.result.total_artifacts > 0 {
            state_for_embed.bump_version();
            state_for_embed
                .save_snapshot()
                .map_err(|error| format!("embed snapshot save failed: {error:#}"))?;
            state_for_embed.mark_clean();
        }
        Ok::<_, String>(result)
    })
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;
    Ok(Json(result))
}

fn persist_foreground_embed_batch(state: &DaemonState) -> Result<(), kin_db::KinDbError> {
    state.flush_embed_progress().map(|_| ()).map_err(|error| {
        kin_db::KinDbError::StorageError(format!("embed progress flush failed: {error:#}"))
    })
}

/// POST /blame — render entity blame from daemon-owned graph state.
async fn blame(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::blame::BlameRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let execution =
        kin_cli::commands::blame::execute_blame_request(&state.layout, graph.as_ref(), &req)
            .map_err(internal_error)?;
    if execution.hydrated_git_history {
        state.bump_version();
        state.save_snapshot().map_err(internal_error)?;
        state.mark_clean();
    }
    Ok(Json(execution.response))
}

/// POST /history — render entity history from daemon-owned graph state.
async fn history(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::history::HistoryRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let execution =
        kin_cli::commands::history::execute_history_request(&state.layout, graph.as_ref(), &req)
            .map_err(internal_error)?;
    if execution.hydrated_git_history {
        state.bump_version();
        state.save_snapshot().map_err(internal_error)?;
        state.mark_clean();
    }
    Ok(Json(execution.response))
}

/// POST /verify/run — execute and persist a verification run in daemon state.
async fn verify_run(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::verify::VerifyRunRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let state_for_verify = Arc::clone(&state);
    let response = tokio::task::spawn_blocking(move || {
        let response = kin_cli::commands::verify::execute_verify_run(
            &state_for_verify.layout,
            state_for_verify.graph.as_ref(),
            &req,
        )
        .map_err(|error| error.to_string())?;
        state_for_verify.bump_version();
        state_for_verify
            .save_snapshot()
            .map_err(|error| error.to_string())?;
        state_for_verify.mark_clean();
        Ok::<_, String>(response)
    })
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /commands/verify — render verify read commands from daemon-owned graph state.
async fn command_verify(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<kin_cli::commands::verify::VerifyCommandRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let response = kin_cli::commands::verify::execute_verify_command(
        &state.layout,
        state.graph.as_ref(),
        &req,
    )
    .map_err(internal_error)?;
    Ok(Json(response))
}

/// POST /reconcile — reconcile a session workspace into daemon-owned graph state.
async fn reconcile(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<kin_cli::commands::reconcile::ReconcileRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let state_for_reconcile = Arc::clone(&state);

    let summary = if let Some(sid) = session_id {
        // Resolve the session's PRIVATE scoped graph for this write. A scoped
        // reconcile mutates this graph in place without persisting (session
        // edits are ephemeral and isolated from HEAD). It must therefore never
        // fall back to the shared HEAD graph: doing so would leak the edits
        // into every other session and diverge in-memory HEAD from the durable
        // snapshot while the generation marker still reads clean.
        let scoped_graph = match state_for_reconcile.scoped_graph_for_write(&sid).await {
            Some(graph) => graph,
            None => {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "no active temporal scope for session {sid}; \
                         POST /session/{{id}}/scope before reconcile"
                    ),
                ));
            }
        };
        tokio::task::spawn_blocking(move || {
            kin_cli::commands::reconcile::execute_reconcile_session_dir_scoped(
                &state_for_reconcile.layout,
                scoped_graph.as_ref(),
                &req.session_dir,
            )
            .map_err(|error| error.to_string())
        })
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?
    } else {
        tokio::task::spawn_blocking(move || {
            kin_cli::commands::reconcile::execute_reconcile_session_dir_with_persist(
                &state_for_reconcile.layout,
                state_for_reconcile.graph.as_ref(),
                &req.session_dir,
                || {
                    state_for_reconcile.bump_version();
                    state_for_reconcile.save_snapshot().map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
                    })?;
                    state_for_reconcile.mark_clean();
                    Ok(())
                },
            )
            .map_err(|error| error.to_string())
        })
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?
    };
    Ok(Json(summary))
}

fn attach_search_bodies(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    response: &mut kin_cli::commands::search::DaemonSearchResponse,
    max_lines: usize,
) {
    let Some((blob_store, tree)) = search_body_source_from_graph(layout, graph) else {
        return;
    };
    for record in &mut response.records {
        let kin_cli::commands::search::DaemonSearchRecord::Entity(entity) = record else {
            continue;
        };
        if let Some((body, omitted)) = search_body_from_graph(&blob_store, &tree, entity, max_lines)
        {
            entity.body = Some(body);
            entity.body_omitted_line_count = omitted;
        }
    }
}

fn search_body_source_from_graph(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Option<(
    kin_blobs::BlobStore,
    HashMap<kin_model::FilePathId, kin_model::Hash256>,
)> {
    let branch_name = kin_core::read_current_branch(layout).ok()?;
    let branch = graph.get_branch(&branch_name).ok()??;
    let genesis = kin_core::build_genesis_change();
    let tree = kin_core::build_file_tree(graph, &genesis.id, &branch.head).ok()?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).ok()?;
    Some((blob_store, tree))
}

fn search_body_from_graph(
    blob_store: &kin_blobs::BlobStore,
    tree: &HashMap<kin_model::FilePathId, kin_model::Hash256>,
    entity: &kin_cli::commands::search::DaemonSearchEntityRecord,
    max_lines: usize,
) -> Option<(String, usize)> {
    let rel_path = entity.file.as_deref()?;
    let file_id = safe_graph_relative_file_id(rel_path)?;
    let hash = tree.get(&file_id)?;
    let bytes = blob_store
        .read(&kin_blobs::Hash256(*hash.as_bytes()))
        .ok()?;
    let start = entity.start_byte?.min(bytes.len());
    let end = entity.end_byte?.min(bytes.len());
    if start >= end {
        return None;
    }

    let snippet = String::from_utf8_lossy(&bytes[start..end]);
    let lines = snippet.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    let shown = lines.len().min(max_lines.max(1));
    Some((lines[..shown].join("\n"), lines.len().saturating_sub(shown)))
}

fn safe_graph_relative_file_id(rel_path: &str) -> Option<kin_model::FilePathId> {
    let rel = FsPath::new(rel_path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    Some(kin_model::FilePathId::new(rel_path))
}

/// GET /support — return graph observability from daemon-owned graph state.
async fn support(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let graph = resolve_session_graph(&state, session_id.as_ref()).await;
    let result = kin_cli::commands::support::inspect_support_graph(&state.layout, graph.as_ref())
        .map_err(internal_error)?;
    Ok(Json(result))
}

fn mcp_tool_is_session_endpoint(name: &str) -> bool {
    matches!(
        name,
        "register_session"
            | "kin_session_start"
            | "kin_session_heartbeat"
            | "kin_session_end"
            | "kin_register_intent"
            | "kin_release_intent"
            | "kin_check_traffic"
    )
}

fn mcp_tool_is_transaction(name: &str) -> bool {
    matches!(
        name,
        "kin_transaction_begin"
            | "kin_transaction_stage"
            | "kin_transaction_validate"
            | "kin_transaction_commit"
            | "kin_transaction_abort"
    )
}

fn mcp_tool_mutates_graph(name: &str) -> bool {
    matches!(
        name,
        "kin_work_create"
            | "kin_work_link"
            | "kin_work_decompose"
            | "kin_work_block"
            | "kin_work_implement"
            | "kin_work_status"
            | "kin_annotation_add"
            | "kin_annotation_mark_resolved"
            | "kin_todo_import"
            | "kin_review_create"
            | "kin_review_decide"
            | "kin_review_note_add"
            | "kin_review_discuss"
            | "kin_review_discuss_reply"
            | "kin_review_discuss_resolve"
            | "kin_review_assign"
            | "kin_review_unassign"
            // Commit applies staged entity/relation deltas via
            // apply_transaction_delta, so it must run against the canonical
            // mutable graph — never a session's read-only temporal-scope view.
            | "kin_transaction_commit"
    )
}

fn mcp_session_registry_snapshot(
    state: &DaemonState,
) -> Result<kin_mcp::SessionRegistry, (StatusCode, String)> {
    let sessions = state.coordinator.list_sessions().map_err(internal_error)?;
    let intents = state.graph.list_all_intents().map_err(internal_error)?;
    let registry = kin_mcp::SessionRegistry::new();
    registry.replace_agent_sessions_and_intents(sessions, intents);
    // Restore in-flight transactions so a registry built fresh for this request
    // sees what earlier requests staged; sessions/intents persist via the graph,
    // but transactions live only in DaemonState.
    let transactions = lock_recover(&state.mcp_transactions)
        .values()
        .cloned()
        .collect();
    registry.replace_transactions(transactions);
    Ok(registry)
}

/// Persist the registry's transactions back into `DaemonState` after a tool call
/// so begin/stage/validate/commit issued across separate HTTP requests share
/// state. Counterpart to the restore in `mcp_session_registry_snapshot`.
fn persist_mcp_transactions(state: &DaemonState, registry: &kin_mcp::SessionRegistry) {
    let mut store = lock_recover(&state.mcp_transactions);
    // Merge, don't clear: only upsert the transactions this request's registry
    // holds. Clearing would drop a transaction another request begun
    // concurrently (it restored the store before this one, but this registry
    // never saw it) — a lost-update window. Upsert-only keeps concurrently-begun
    // transactions intact.
    for transaction in registry.list_transactions() {
        store.insert(transaction.transaction_id.clone(), transaction);
    }
    // Mirror the in-flight set to disk so a restart does not silently
    // drop staged-but-uncommitted transactions.
    crate::state::write_persisted_mcp_transactions(&state.layout, &store);
}

/// Drop a transaction from the durable store once it reaches a terminal state
/// (committed/aborted), so finished transactions do not accumulate. Called only
/// after the terminal tool call succeeds.
fn forget_mcp_transaction(state: &DaemonState, transaction_id: &str) {
    let mut store = lock_recover(&state.mcp_transactions);
    store.remove(transaction_id);
    // Keep the durable mirror in step with the in-memory eviction so a
    // committed/aborted transaction does not reappear after a restart.
    crate::state::write_persisted_mcp_transactions(&state.layout, &store);
}

/// Collect the current graph state of all entities referenced in a commit
/// transaction's staged operations.  Called immediately before the commit is
/// applied so the returned entities carry the source-span metadata set by the
/// last reconcile — the information
/// [`project_after_mcp_commit`](crate::projection_wiring::project_after_mcp_commit)
/// needs to splice the mutation back into the working-directory files.
///
/// Only entity operations are projected (relations and blobs have no file span).
/// Entities not yet in the graph (new creates staged for the first time) are
/// silently omitted — they have no span, so
/// `project_after_mcp_commit` would skip them anyway.
fn collect_pre_commit_entities(
    state: &DaemonState,
    sessions: &kin_mcp::SessionRegistry,
    arguments: &HashMap<String, serde_json::Value>,
) -> (
    Vec<kin_model::Entity>,
    HashMap<kin_model::EntityId, Vec<u8>>,
) {
    let Some(tx_id) = arguments
        .get("transaction_id")
        .and_then(serde_json::Value::as_str)
    else {
        return (vec![], HashMap::new());
    };
    let Some(transaction) = sessions.get_transaction(tx_id) else {
        return (vec![], HashMap::new());
    };

    let mut entities = Vec::new();
    let mut supplied_bodies: HashMap<kin_model::EntityId, Vec<u8>> = HashMap::new();
    for op in &transaction.staged_operations {
        let Some(kin_mcp::McpMutationPayload::Entity(payload_entity)) = op.payload.as_ref() else {
            continue;
        };
        // Capture the agent-supplied new source text (if present) keyed
        // by entity id, so the post-commit projection writes it to the working
        // file instead of re-splicing the file's own bytes (an identity no-op).
        if let Some(body) = op.body.as_ref() {
            supplied_bodies.insert(payload_entity.id, body.clone().into_bytes());
        }
        // Look up the pre-commit entity from the graph — it carries the span
        // set by the last reconcile.  The agent's staged payload may not have
        // span metadata (agents do not know file placement).
        if let Ok(Some(graph_entity)) = state.graph.get_entity(&payload_entity.id) {
            entities.push(graph_entity);
        }
    }
    (entities, supplied_bodies)
}

/// The transaction id a terminal transaction tool (commit/abort) acted on, used
/// to evict it from the durable store after success.
fn terminal_transaction_id(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Option<String> {
    if !matches!(name, "kin_transaction_commit" | "kin_transaction_abort") {
        return None;
    }
    arguments
        .get("transaction_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

// Opt-in re-rank of the `semantic_locate` cosine result set. Default OFF so the
// shipped ranking is unchanged until a paired benchmark validates the effect and
// flips the default; set KIN_SEMLOC_RERANK=1 to enable. Weights are env-tunable.
// The full graph-native `kin locate` pipeline already applies richer role/exact
// ranking; this brings the lighter cosine surface (the agent's `semantic_locate`)
// toward the same shape without re-running that pipeline.
fn semloc_rerank_enabled() -> bool {
    matches!(
        std::env::var("KIN_SEMLOC_RERANK").ok().as_deref(),
        Some("1") | Some("true") | Some("on") | Some("yes")
    )
}

fn semloc_env_f32(key: &str, default: f32) -> f32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// True when the query is itself about test/spec/fixture code, in which case
/// test-role entities must NOT be demoted (they may be the edit target).
fn semloc_query_is_test_related(query: &str) -> bool {
    let q = query.to_ascii_lowercase();
    q.contains("test") || q.contains("spec") || q.contains("fixture")
}

/// True when `name` appears as a literal token of `query` (case-insensitive),
/// including the last dotted segment of a qualified name (e.g. query
/// "constant.Raspbian" matches entity "Raspbian"). Tokens split on non-[a-z0-9_].
fn semloc_query_has_exact_token(query: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let target = name.to_ascii_lowercase();
    let last = target.rsplit('.').next().unwrap_or(&target).to_string();
    query
        .to_ascii_lowercase()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .any(|tok| tok == target || tok == last)
}

/// Re-rank PRIORITY for one cosine hit (LOWER = better rank). Pure: no graph.
///   Lever A — role-aware demotion: Generated/Vendored/Docs always pushed back;
///     Test pushed back only when the query is not test-related.
///   Lever B — exact-name boost: a literal symbol/path-token query match floats up.
/// The displayed cosine score is unchanged; only the ORDER is affected. The demote
/// penalty dominates the exact bonus, so an exact-name match in a demoted role does
/// not jump ahead of real source.
fn semloc_rerank_priority(
    role: Option<kin_model::EntityRole>,
    name: &str,
    query: &str,
    is_test_query: bool,
    cosine_distance: f32,
) -> f32 {
    use kin_model::EntityRole;
    let demote = semloc_env_f32("KIN_SEMLOC_DEMOTE", 10.0);
    let bonus = semloc_env_f32("KIN_SEMLOC_EXACT_BONUS", 1.0);
    let mut p = cosine_distance;
    let is_demotable = match role {
        Some(EntityRole::Generated) | Some(EntityRole::Vendored) | Some(EntityRole::Docs) => true,
        Some(EntityRole::Test) => !is_test_query,
        _ => false, // Source / External / unknown: never demoted
    };
    if is_demotable {
        p += demote;
    }
    if semloc_query_has_exact_token(query, name) {
        p -= bonus;
    }
    p
}

/// POST /mcp/tools/call — execute an MCP tool against daemon-owned graph state.
///
/// MCP stdio processes are transport shims only. They forward graph-backed
/// tools here so query and mutation authority remains in the repo daemon.
/// Build the `semantic_locate` response from the daemon's real vector index.
///
/// Contract (shared verbatim with the MCP server): args
/// `{query, limit?=20, granularity?="entity"|"file", include_snippet?=true}`;
/// response object with a ranked
/// `results: [{entity_id, name, file, score, snippet?}]` array plus a
/// `semantic_coverage` float (`indexed / total`). `score` is cosine similarity
/// (`1.0 - distance`), higher is better; results are already rank-ordered.
/// `snippet` is a bounded inline body excerpt (entity granularity only),
/// projected from graph-owned content via the same body projection
/// `get_entity_source` uses, so one `semantic_locate` is act-on-able without a
/// follow-up read; omitted on a graph gap or when `include_snippet` is false.
fn build_semantic_locate_result(
    graph: &kin_db::InMemoryGraph,
    arguments: &HashMap<String, serde_json::Value>,
) -> kin_mcp::ToolCallResult {
    let query = match arguments.get("query").and_then(serde_json::Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.to_string(),
        _ => {
            return kin_mcp::ToolCallResult::error("missing required parameter: query".to_string());
        }
    };
    let limit = arguments
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value as usize)
        .filter(|value| *value > 0)
        .unwrap_or(20);
    let file_granularity = arguments
        .get("granularity")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.eq_ignore_ascii_case("file"))
        .unwrap_or(false);
    // Inline a bounded code snippet on each entity hit by default, so a single
    // `semantic_locate` is act-on-able without a follow-up `get_entity_source`.
    // Suppressible via `include_snippet: false`; never applies to file
    // granularity (a file hit has no single entity body).
    let include_snippet = arguments
        .get("include_snippet")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
        && !file_granularity;

    // Coverage is reported, never gated: a partially-embedded graph still
    // returns whatever the index can answer (graceful degradation per R5).
    let status = graph.embedding_status();
    let semantic_coverage = if status.total == 0 {
        0.0_f32
    } else {
        status.indexed as f32 / status.total as f32
    };

    // Over-fetch so post-resolution dedupe can still fill `limit`: by file for
    // file granularity, by resolved entity for entity granularity.
    // Every entity carries both an `Entity(E)` and an `EntityRevision(head)`
    // vector in the index, both resolving to the same entity, so without the
    // entity dedup below each entity would appear ~twice and effective recall@k
    // would halve.
    let fetch_limit = limit.saturating_mul(8).max(limit);

    let raw = match graph.semantic_search(&query, fetch_limit) {
        Ok(hits) => hits,
        Err(error) => {
            return kin_mcp::ToolCallResult::error(format!("semantic search failed: {error}"));
        }
    };

    // Opt-in (KIN_SEMLOC_RERANK=1): role-aware demotion + exact-name boost over the
    // cosine hit set ONLY. Resolve once for scoring, then stable-sort by priority with
    // the original cosine order as the deterministic tiebreak (no nondeterminism).
    let raw = if semloc_rerank_enabled() {
        let is_test_q = semloc_query_is_test_related(&query);
        let mut scored: Vec<_> = raw
            .into_iter()
            .enumerate()
            .map(|(idx, (key, distance))| {
                let prio = match graph.resolve_retrieval_key(&key) {
                    Some(kin_db::ResolvedRetrievalItem::Entity(entity)) => semloc_rerank_priority(
                        Some(entity.role),
                        &entity.name,
                        &query,
                        is_test_q,
                        distance,
                    ),
                    _ => semloc_rerank_priority(None, "", &query, is_test_q, distance),
                };
                (prio, idx, key, distance)
            })
            .collect();
        scored.sort_by(|a, b| {
            a.0.partial_cmp(&b.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.cmp(&b.1))
        });
        scored
            .into_iter()
            .map(|(_, _, key, distance)| (key, distance))
            .collect()
    } else {
        raw
    };

    let mut results = Vec::with_capacity(limit);
    let mut seen_files: HashSet<String> = HashSet::new();
    let mut seen_entities: HashSet<String> = HashSet::new();
    for (key, distance) in raw {
        if results.len() >= limit {
            break;
        }
        let Some(item) = graph.resolve_retrieval_key(&key) else {
            continue;
        };
        let (entity_id, name, file) = match &item {
            kin_db::ResolvedRetrievalItem::Entity(entity) => (
                entity.id.to_string(),
                entity.name.clone(),
                entity.file_origin.as_ref().map(|origin| origin.0.clone()),
            ),
            other => {
                let file = other.file_path().map(|path| path.0.clone());
                let name = file
                    .as_deref()
                    .and_then(|path| {
                        FsPath::new(path)
                            .file_name()
                            .and_then(|component| component.to_str())
                    })
                    .unwrap_or_default()
                    .to_string();
                let id = file.clone().unwrap_or_else(|| name.clone());
                (id, name, file)
            }
        };

        if file_granularity {
            match &file {
                Some(path) => {
                    if !seen_files.insert(path.clone()) {
                        continue;
                    }
                }
                // File granularity requires a file path; skip pathless hits.
                None => continue,
            }
        } else if !seen_entities.insert(entity_id.clone()) {
            // Collapse the two index keys per entity (`Entity(E)` +
            // `EntityRevision(head)`) into a single result. `raw` is rank-ordered
            // by distance, so the first occurrence of an entity is its best hit.
            continue;
        }

        // Project the bounded snippet only for kept entity hits (top `limit`),
        // from graph-owned content — no working-tree read; a graph gap yields no
        // snippet rather than a fallback.
        let snippet = if include_snippet {
            if let kin_db::ResolvedRetrievalItem::Entity(entity) = &item {
                kin_mcp::handlers::common::read_bounded_entity_snippet(graph, entity)
            } else {
                None
            }
        } else {
            None
        };

        let score = 1.0_f32 - distance;
        let mut hit = json!({
            "entity_id": entity_id,
            "name": name,
            "file": file,
            "score": score,
        });
        if let Some(snippet) = snippet {
            hit["snippet"] = json!(snippet);
        }
        results.push(hit);
    }

    let payload = json!({
        "query": query,
        "granularity": if file_granularity { "file" } else { "entity" },
        "routing": "cosine-v0",
        "semantic_coverage": semantic_coverage,
        "results": results,
    });

    match serde_json::to_string_pretty(&payload) {
        Ok(text) => kin_mcp::ToolCallResult::text(text),
        Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
    }
}

/// Resolve the graph entity behind one fused-locate symbol so a
/// `semantic_locate` hit stays act-on-able (`get_entity_source(entity_id)`)
/// without a name search round-trip. Matches by file + exact name, breaking
/// ties by span start; graph-owned truth only.
fn resolve_symbol_entity_id(
    graph: &kin_db::InMemoryGraph,
    file_path: &str,
    symbol: &kin_cli::commands::locate::LocateSymbol,
) -> Option<String> {
    let filter = kin_model::EntityFilter {
        file_path: Some(kin_model::FilePathId::new(file_path)),
        ..Default::default()
    };
    let entities = graph.query_entities(&filter).ok()?;
    let mut candidates: Vec<_> = entities
        .into_iter()
        .filter(|entity| entity.name == symbol.name)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if let Some(span) = symbol.span {
        candidates.sort_by_key(|entity| {
            let start = entity
                .span
                .as_ref()
                .map(|entity_span| entity_span.start_line)
                .unwrap_or(u32::MAX);
            start.abs_diff(span[0])
        });
    }
    candidates.first().map(|entity| entity.id.to_string())
}

/// Build the `semantic_locate` response from the full fused locate pipeline
/// (the same multi-signal fusion + rerank `POST /locate` serves) instead of
/// the single-vector cosine ranking. Selected by the retrieval quality
/// profile (`KIN_PROFILE`) or an explicit per-call `pipeline` argument.
///
/// Contract: args `{query, limit?=20, granularity?="entity"|"file",
/// include_snippet?=true, explain?=false, pipeline?}`. Response keeps the
/// legacy shape — ranked `results` array plus a `semantic_coverage` float —
/// and adds per-hit line spans/kind/definition, a structured
/// `semantic_coverage_detail`, the `degradations` array, and
/// `routing: "fused-v1"` so a caller can tell which pipeline answered.
async fn build_fused_semantic_locate_result(
    state: &Arc<DaemonState>,
    session_id: Option<&SessionId>,
    graph: &kin_db::InMemoryGraph,
    arguments: &HashMap<String, serde_json::Value>,
) -> kin_mcp::ToolCallResult {
    let query = match arguments.get("query").and_then(serde_json::Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.to_string(),
        _ => {
            return kin_mcp::ToolCallResult::error("missing required parameter: query".to_string());
        }
    };
    let limit = arguments
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value as usize)
        .filter(|value| *value > 0)
        .unwrap_or(20);
    let file_granularity = arguments
        .get("granularity")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.eq_ignore_ascii_case("file"))
        .unwrap_or(false);
    let include_snippet = arguments
        .get("include_snippet")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
        && !file_granularity;
    let explain = arguments
        .get("explain")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let snippet_opts = if include_snippet {
        kin_cli::commands::locate::SnippetOptions::enabled(None)
    } else {
        kin_cli::commands::locate::SnippetOptions::default()
    };

    // The agent asked for `limit` ranked hits; give the fused pipeline the
    // same number of file slots EXPLICITLY so the adaptive cap cannot shrink
    // the pool below what the caller asked to see (entity hits flatten from
    // the file ranking in file-major order).
    let locate_result = match run_fused_locate_for_state(
        state,
        session_id,
        graph,
        &query,
        explain,
        limit,
        true,
        snippet_opts,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return kin_mcp::ToolCallResult::error(format!("fused locate failed: {error}"));
        }
    };

    let coverage_fraction = locate_result
        .semantic_coverage
        .as_ref()
        .map(|coverage| {
            if coverage.total == 0 {
                0.0_f32
            } else {
                coverage.indexed as f32 / coverage.total as f32
            }
        })
        .unwrap_or(0.0);

    let mut results = Vec::with_capacity(limit);
    let mut seen_entities: HashSet<String> = HashSet::new();
    'files: for file_entry in &locate_result.files {
        if file_granularity {
            let name = FsPath::new(&file_entry.path)
                .file_name()
                .and_then(|component| component.to_str())
                .unwrap_or_default()
                .to_string();
            let mut hit = json!({
                "entity_id": file_entry.path,
                "name": name,
                "file": file_entry.path,
                "score": file_entry.score,
            });
            if !file_entry.spans.is_empty() {
                hit["spans"] = json!(file_entry.spans);
            }
            if !file_entry.signals.is_empty() {
                hit["signals"] = json!(file_entry.signals);
            }
            results.push(hit);
            if results.len() >= limit {
                break 'files;
            }
            continue;
        }
        for symbol in &file_entry.symbols {
            let Some(entity_id) = resolve_symbol_entity_id(graph, &file_entry.path, symbol) else {
                // A symbol Kin cannot re-attach to a graph entity is not
                // act-on-able over MCP (no source read without an id); skip it
                // rather than emit a dead hit.
                continue;
            };
            if !seen_entities.insert(entity_id.clone()) {
                continue;
            }
            let mut hit = json!({
                "entity_id": entity_id,
                "name": symbol.name,
                "file": file_entry.path,
                "score": symbol.score,
                "file_score": file_entry.score,
                "kind": symbol.kind,
                "definition": symbol.definition,
            });
            if let Some(span) = symbol.span {
                hit["start_line"] = json!(span[0]);
                hit["end_line"] = json!(span[1]);
            }
            if let Some(snippet) = symbol.snippet.as_ref() {
                hit["snippet"] = json!(snippet);
            }
            if !file_entry.signals.is_empty() {
                hit["signals"] = json!(file_entry.signals);
            }
            results.push(hit);
            if results.len() >= limit {
                break 'files;
            }
        }
    }

    let mut payload = json!({
        "query": query,
        "granularity": if file_granularity { "file" } else { "entity" },
        "routing": "fused-v1",
        "semantic_coverage": coverage_fraction,
        "results": results,
    });
    if let Some(coverage) = locate_result.semantic_coverage.as_ref() {
        payload["semantic_coverage_detail"] = json!(coverage);
    }
    if !locate_result.degradations.is_empty() {
        payload["degradations"] = json!(locate_result.degradations);
    }
    if explain {
        if let Some(debug) = locate_result.debug.as_ref() {
            payload["debug"] = json!(debug);
        }
    }

    match serde_json::to_string_pretty(&payload) {
        Ok(text) => kin_mcp::ToolCallResult::text(text),
        Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
    }
}

/// Map a resolved [`kin_cli::commands::graph::EntitySourceOutcome`] to an MCP
/// tool result.
///
/// The three application outcomes are surfaced distinctly so an agent can act on
/// each: a not-found ID and a sourceless-but-valid entity each carry their own
/// explanatory error — reported ahead of any generic missing-source text — while
/// a found entity serializes to its source record. Genuine read failures (`Err`)
/// surface their message verbatim. Generic over the error type so the daemon
/// need not name the caller's error crate.
fn entity_source_tool_result<E: std::fmt::Display>(
    outcome: Result<kin_cli::commands::graph::EntitySourceOutcome, E>,
) -> kin_mcp::ToolCallResult {
    use kin_cli::commands::graph::EntitySourceOutcome;
    match outcome {
        Ok(EntitySourceOutcome::Found(source)) => match serde_json::to_string_pretty(&source) {
            Ok(json) => kin_mcp::ToolCallResult::text(json),
            Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
        },
        // The ID does not resolve — non-retryable. Surfaced verbatim so the agent
        // stops retrying and probing the ID (this case previously masqueraded as
        // "graph source response missing source").
        Ok(EntitySourceOutcome::NotFound(message)) => kin_mcp::ToolCallResult::error(message),
        // A real entity with no attached source body — distinct from not-found.
        Ok(EntitySourceOutcome::NoSource(message)) => kin_mcp::ToolCallResult::error(message),
        Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
    }
}

async fn mcp_tools_call(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<McpToolCallRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".to_string(),
        ));
    }

    if mcp_tool_is_session_endpoint(&request.name) {
        return Ok(Json(kin_mcp::ToolCallResult::error(format!(
            "tool '{}' is served by daemon session endpoints, not the graph tool dispatcher",
            request.name
        ))));
    }

    let session_id = extract_session_id_from_headers(&headers)?;
    let mutates = mcp_tool_mutates_graph(&request.name);
    let graph = if mutates {
        Arc::clone(&state.graph)
    } else {
        resolve_session_graph(&state, session_id.as_ref()).await
    };

    if matches!(
        request.name.as_str(),
        "get_entity_source" | "get_entity_body"
    ) {
        let Some(entity_id) = request
            .arguments
            .get("entity_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(Json(kin_mcp::ToolCallResult::error(
                "missing required parameter: entity_id".to_string(),
            )));
        };
        let result =
            entity_source_tool_result(kin_cli::commands::graph::build_entity_source_outcome(
                &state.layout,
                graph.as_ref(),
                entity_id,
            ));
        return Ok(Json(result));
    }

    // Special-case `trace_data_flow` so MCP callers get the same response
    // shape as the CLI (`kin trace-data-flow`) — including inlined source
    // bodies for each step. The generic GraphStore handler in kin-mcp
    // returns the chain without bodies; the concrete InMemoryGraph here
    // unlocks the blob-backed source records.
    if request.name == "trace_data_flow" {
        let focal = request
            .arguments
            .get("focal")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.to_string());
        let depth = request
            .arguments
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);
        let limit_per_step = request
            .arguments
            .get("limit_per_step")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);
        let direction = request
            .arguments
            .get("direction")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.to_string());
        let Some(focal) = focal else {
            return Ok(Json(kin_mcp::ToolCallResult::error(
                "missing required parameter: focal".to_string(),
            )));
        };
        let parsed_direction = match direction.as_deref() {
            Some(value) => match kin_cli::commands::trace_data_flow::TraceDirection::parse(value) {
                Ok(dir) => Some(dir),
                Err(error) => {
                    return Ok(Json(kin_mcp::ToolCallResult::error(error.to_string())));
                }
            },
            None => None,
        };
        let req = kin_cli::commands::trace_data_flow::TraceDataFlowRequest {
            focal,
            depth,
            direction: parsed_direction,
            limit_per_step,
        };
        let result = match kin_cli::commands::trace_data_flow::build_trace_data_flow_response(
            &state.layout,
            graph.as_ref(),
            &req,
        ) {
            Ok(response) => match serde_json::to_string_pretty(&response) {
                Ok(json) => kin_mcp::ToolCallResult::text(json),
                Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
            },
            Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
        };
        return Ok(Json(result));
    }

    // Special-case `find_dead_code_seeded` so MCP callers get the same
    // vector-semantic search path as the CLI (`kin dead_code --seed ...`).
    // The generic GraphStore handler in kin-mcp falls back to substring
    // matching; the concrete InMemoryGraph here unlocks the HNSW vector index.
    if request.name == "find_dead_code_seeded" {
        let query = request
            .arguments
            .get("query")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.to_string());
        let limit = request
            .arguments
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);
        let name_pattern = request
            .arguments
            .get("name_pattern")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty());
        let Some(query) = query else {
            return Ok(Json(kin_mcp::ToolCallResult::error(
                "missing required parameter: query".to_string(),
            )));
        };
        let req = kin_cli::commands::dead_code::DeadCodeSeededRequest {
            query,
            limit,
            name_pattern,
        };
        let result = match kin_cli::commands::dead_code::build_dead_code_seeded_response(
            graph.as_ref(),
            &req,
        ) {
            Ok(response) => match serde_json::to_string_pretty(&response) {
                Ok(json) => kin_mcp::ToolCallResult::text(json),
                Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
            },
            Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
        };
        return Ok(Json(result));
    }

    // R14 — `semantic_locate`: serve the agent's primary retrieval tool from
    // the daemon's real pipelines. Under the accuracy profile (default) this
    // is the SAME fused multi-signal ranking `POST /locate` serves — vector,
    // lexical, and graph fusion with role-aware ranking — so the MCP surface
    // is no longer a weaker single-vector shadow of the product ranker. The
    // legacy cosine ranking stays reachable via `KIN_PROFILE=compat-v0` or a
    // per-call `pipeline: "cosine"` argument for A/B comparison. Both paths
    // return partial results plus `semantic_coverage` rather than hard-gating
    // on full embedding coverage (graceful degradation per R5).
    if request.name == "semantic_locate" {
        let pipeline_override = request
            .arguments
            .get("pipeline")
            .and_then(serde_json::Value::as_str);
        let use_fused = match pipeline_override {
            Some(value) if value.eq_ignore_ascii_case("fused") => true,
            Some(value) if value.eq_ignore_ascii_case("cosine") => false,
            Some(other) => {
                return Ok(Json(kin_mcp::ToolCallResult::error(format!(
                    "invalid pipeline '{other}': expected \"fused\" or \"cosine\""
                ))));
            }
            None => {
                kin_cli::retrieval_profile::RetrievalProfile::from_env().semantic_locate_fused()
            }
        };
        if use_fused {
            return Ok(Json(
                build_fused_semantic_locate_result(
                    &state,
                    session_id.as_ref(),
                    graph.as_ref(),
                    &request.arguments,
                )
                .await,
            ));
        }
        return Ok(Json(build_semantic_locate_result(
            graph.as_ref(),
            &request.arguments,
        )));
    }

    let sessions = mcp_session_registry_snapshot(&state)?;

    // Snapshot entity state before the commit so we can project the
    // mutations into working-directory files after the graph is updated.
    // Entities without a span (new creates, relation-only ops) are included but
    // silently skipped by project_after_mcp_commit.
    let (pre_commit_entities, supplied_bodies) = if request.name == "kin_transaction_commit" {
        collect_pre_commit_entities(&state, &sessions, &request.arguments)
    } else {
        (vec![], HashMap::new())
    };

    let mut result = match kin_mcp::handlers::handle_tool_call(
        &request.name,
        &request.arguments,
        graph.as_ref(),
        &sessions,
        kin_mcp::SessionAuthorityMode::OfflineFallback,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
    };

    // Persist transaction state mutated by this call so the next HTTP request
    // (potentially a later stage/commit on the same transaction) sees it.
    if mcp_tool_is_transaction(&request.name) {
        persist_mcp_transactions(&state, &sessions);
        // Once a transaction commits or aborts successfully, evict it so the
        // durable store does not grow without bound.
        if result.is_error != Some(true) {
            if let Some(tx_id) = terminal_transaction_id(&request.name, &request.arguments) {
                forget_mcp_transaction(&state, &tx_id);
            }
        }
    }

    if mutates && result.is_error != Some(true) {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: format!("mcp-tool:{}", request.name),
        });
    }

    // Project entity mutations into working-directory files (so the next
    // reconcile does not silently clobber the graph — file-wins LWW) and enrich
    // the commit response with what the commit actually did.
    //
    // The graph commit has already landed and the version counter already
    // reflects it above.  A projection failure does NOT roll back the graph —
    // the agent's intent is preserved and the caller is told loudly so it can
    // retry or inspect the source file.
    //
    // Conflicts (skip-conflicted semantics): entities where a
    // concurrent human file edit was detected are NOT projected; the commit is
    // surfaced as an error so the agent can resolve.
    if request.name == "kin_transaction_commit" && result.is_error != Some(true) {
        // The real graph Merkle root, now that the delta has landed.
        let new_root_hash = hex::encode(state.graph.compute_root_hash());

        let (modified_files, collision_warnings) = if pre_commit_entities.is_empty() {
            // Relation-only / new-entity / zero-op commit: nothing to project.
            (Vec::new(), Vec::new())
        } else {
            match crate::projection_wiring::project_after_mcp_commit(
                &state,
                &pre_commit_entities,
                &supplied_bodies,
            )
            .await
            {
                Err(proj_err) => {
                    return Ok(Json(kin_mcp::ToolCallResult::error(format!(
                        "graph commit succeeded but file projection failed — agent intent is \
                         preserved in the graph; retry projection or inspect the source file. \
                         Detail: {proj_err}"
                    ))));
                }
                Ok((_modified, _warnings, conflicts)) if !conflicts.is_empty() => {
                    // Some entities were skipped due to concurrent file edits.
                    // Surface each conflict loudly so the agent can resolve.
                    let conflict_msgs: Vec<String> = conflicts
                        .iter()
                        .map(|c| {
                            format!(
                                "conflict on {}: {}",
                                c.affected_files
                                    .first()
                                    .map(|f| f.to_string())
                                    .unwrap_or_else(|| "<unknown file>".into()),
                                c.divergence_reason
                            )
                        })
                        .collect();
                    return Ok(Json(kin_mcp::ToolCallResult::error(format!(
                        "graph commit succeeded but {n} entity/entities had concurrent file \
                         edits — those entities were NOT projected (human edits preserved). \
                         Resolve conflicts and retry. Details: {details}",
                        n = conflicts.len(),
                        details = conflict_msgs.join("; "),
                    ))));
                }
                Ok((modified, warnings, _conflicts)) => (modified, warnings),
            }
        };

        // Fold the projection outcome and root hash into the success
        // response so a commit reports what it did instead of an opaque
        // "committed". `ops_applied`/`empty` already rode in from the handler.
        result = enrich_commit_result(result, &new_root_hash, &modified_files, &collision_warnings);
    }

    Ok(Json(result))
}

/// Enrich a successful `kin_transaction_commit` text result with the
/// post-commit graph root hash and the graph→file projection outcome.
///
/// The base handler returns `{transaction_id, state, status, ops_applied,
/// empty}`; this adds `new_root_hash`, `modified_files`, `collision_warnings`,
/// and `conflicts: []` (a non-empty conflict set is surfaced as an error by the
/// caller, so the success path always reports an empty conflicts list). Errors
/// and non-JSON payloads pass through untouched.
fn enrich_commit_result(
    result: kin_mcp::ToolCallResult,
    new_root_hash: &str,
    modified_files: &[FilePathId],
    collision_warnings: &[kin_model::IntentSummary],
) -> kin_mcp::ToolCallResult {
    if result.is_error == Some(true) {
        return result;
    }
    let Some(kin_mcp::ContentBlock::Text { text }) = result.content.first() else {
        return result;
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) else {
        return result;
    };
    let Some(map) = value.as_object_mut() else {
        return result;
    };
    map.insert("new_root_hash".into(), serde_json::json!(new_root_hash));
    map.insert(
        "modified_files".into(),
        serde_json::json!(modified_files
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()),
    );
    map.insert(
        "collision_warnings".into(),
        serde_json::to_value(collision_warnings).unwrap_or_else(|_| serde_json::json!([])),
    );
    map.insert("conflicts".into(), serde_json::json!([]));

    match serde_json::to_string_pretty(&value) {
        Ok(json) => kin_mcp::ToolCallResult::text(json),
        Err(_) => kin_mcp::ToolCallResult::error(
            "commit succeeded but response serialization failed".to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Multi-repo endpoints — list and query lazily-loaded repo graphs
// ---------------------------------------------------------------------------

/// GET /repos — list all repos available in storage.
///
/// In cloud mode this discovers repos from GCS (bucket listing), so it
/// returns repos even if they haven't been loaded into memory yet.
/// In local mode it falls back to the loaded repo keys.
async fn list_repos(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let repos = state.list_available_repos().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list repos: {e}"),
        )
    })?;
    Ok(Json(ReposResponse { repos }))
}

/// GET /repos/{repo_id}/health — health check for a specific repo's graph.
async fn repo_health(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let entity_count = graph.entity_count();
    Ok(Json(RepoHealthResponse {
        repo_id,
        entity_count,
        graph_loaded: entity_count > 0,
        initialized: state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed),
        mass_deletion_blocked: state
            .mass_deletion_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        embed_worker_failed: state
            .embed_worker_failed
            .load(std::sync::atomic::Ordering::Relaxed),
    }))
}

/// GET /repos/{repo_id}/entities?query=X — search entities in a specific repo's graph.
async fn repo_entities(
    Path(repo_id): Path<String>,
    Query(params): Query<RepoEntitiesQuery>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;

    let filter = kin_model::EntityFilter {
        name_pattern: params.query.clone(),
        ..Default::default()
    };

    let entities = graph.query_entities(&filter).map_err(internal_error)?;

    let entries: Vec<RepoEntityEntry> = entities
        .into_iter()
        .map(|e| RepoEntityEntry {
            id: e.id.to_string(),
            name: e.name.clone(),
            kind: format!("{:?}", e.kind),
            file_path: e.file_origin.as_ref().map(|f| f.0.clone()),
        })
        .collect();

    Ok(Json(RepoEntitiesResponse {
        repo_id,
        entities: entries,
    }))
}

/// GET /repos/{repo_id}/files — list projected file paths for a specific repo.
async fn repo_files(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let mut files = graph.indexed_file_paths();
    files.sort();
    Ok(Json(RepoFilesResponse {
        repo_id,
        files: files
            .into_iter()
            .map(|path| RepoFileEntry { path })
            .collect(),
    }))
}

/// GET /repos/{repo_id}/refs — list semantic branch refs for a specific repo.
async fn repo_refs(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let branches = sorted_branches(graph.as_ref())?;
    let default_branch_name = select_default_branch_name(&branches);
    let selected_branch = select_default_branch(&branches);
    let selected_head = selected_branch
        .as_ref()
        .map(|branch| branch.head.to_string());
    let refs = branches
        .into_iter()
        .map(|branch| {
            let name = branch.name.to_string();
            let commit_id = branch.head.to_string();
            RepoRefEntry {
                short_name: name.clone(),
                name,
                kind: "branch".to_string(),
                short_commit_id: short_change_id(&commit_id),
                commit_id,
                is_head: selected_head
                    .as_ref()
                    .map(|head| head == &branch.head.to_string())
                    .unwrap_or(false),
                is_default_branch: default_branch_name
                    .as_ref()
                    .map(|default_name| default_name == &branch.name.to_string())
                    .unwrap_or(false),
            }
        })
        .collect();
    Ok(Json(RepoRefsResponse {
        repo_id,
        branch_name: default_branch_name.clone(),
        default_branch: default_branch_name,
        head_ref: selected_head,
        refs,
    }))
}

/// GET /repos/{repo_id}/history — list semantic history for the selected branch.
async fn repo_history(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let branches = sorted_branches(graph.as_ref())?;
    let selected_branch = select_default_branch(&branches);
    let Some(branch) = selected_branch else {
        return Ok(Json(RepoHistoryResponse {
            repo_id,
            branch_name: None,
            baseline_ref: None,
            head_ref: None,
            commits: Vec::new(),
        }));
    };

    let mut commits = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(branch.head.clone());
    while let Some(change_id) = current {
        if !seen.insert(change_id.clone()) {
            break;
        }
        let Some(change) = graph.get_change(&change_id).map_err(internal_error)? else {
            break;
        };
        let commit_id = change.id.to_string();
        commits.push(RepoHistoryEntry {
            short_commit_id: short_change_id(&commit_id),
            commit_id,
            author: change.author.to_string(),
            authored_at: change.timestamp.to_string(),
            subject: change.message,
        });
        current = change.parents.first().cloned();
        if commits.len() >= 50 {
            break;
        }
    }

    Ok(Json(RepoHistoryResponse {
        repo_id,
        branch_name: Some(branch.name.to_string()),
        baseline_ref: None,
        head_ref: Some(branch.head.to_string()),
        commits,
    }))
}

fn sorted_branches(
    graph: &kin_db::InMemoryGraph,
) -> std::result::Result<Vec<kin_model::Branch>, (StatusCode, String)> {
    let mut branches = graph.list_branches().map_err(internal_error)?;
    branches.sort_by(|left, right| left.name.0.cmp(&right.name.0));
    Ok(branches)
}

fn select_default_branch_name(branches: &[kin_model::Branch]) -> Option<String> {
    select_default_branch(branches).map(|branch| branch.name.to_string())
}

fn select_default_branch(branches: &[kin_model::Branch]) -> Option<kin_model::Branch> {
    branches
        .iter()
        .find(|branch| branch.name.0 == "main")
        .cloned()
        .or_else(|| branches.first().cloned())
}

fn short_change_id(value: &str) -> String {
    value.chars().take(10).collect()
}

// ---------------------------------------------------------------------------
// Provenance endpoints — Merkle DAG proof lineage and verification
// ---------------------------------------------------------------------------

/// GET /repos/{repo_id}/provenance/entity/{entity_id} — full hash chain for an entity.
///
/// Returns the Merkle DAG proof lineage: entity content hash → outgoing relation
/// hashes → subgraph root hash → graph root hash. Each step includes the raw
/// SHA-256 so callers can independently verify the chain.
async fn repo_provenance_entity(
    Path((repo_id, entity_id_str)): Path<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let entity_id = parse_entity_id_hex(&entity_id_str)?;

    let snapshot = graph.to_snapshot();

    let entity = snapshot.entities.get(&entity_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("entity {entity_id_str} not found"),
        )
    })?;

    // Step 1: entity content hash
    let entity_hash = kin_db::compute_entity_hash(entity);

    // Step 2: outgoing relation hashes
    let mut relation_hashes_out = Vec::new();
    if let Some(rel_ids) = snapshot.outgoing.get(&entity_id) {
        for rel_id in rel_ids {
            if let Some(relation) = snapshot.relations.get(rel_id) {
                let dst_entity = match relation.dst {
                    GraphNodeId::Entity(dst_entity_id) => snapshot.entities.get(&dst_entity_id),
                    _ => None,
                };
                let dst_hash = dst_entity
                    .map(|e| kin_db::compute_entity_hash(e))
                    .unwrap_or(kin_db::ZERO_HASH);
                let rel_hash = kin_db::compute_relation_hash(relation, entity_hash, dst_hash);
                relation_hashes_out.push(ProvenanceRelationHash {
                    relation_id: rel_id.to_string(),
                    kind: format!("{:?}", relation.kind),
                    destination_entity_id: relation.dst.to_string(),
                    destination_entity_name: dst_entity
                        .map(|e| e.name.clone())
                        .unwrap_or_else(|| "<missing>".to_string()),
                    hash: hex::encode(rel_hash),
                });
            }
        }
    }

    // Step 3: subgraph hash
    let mut subgraph_cache = std::collections::HashMap::new();
    let subgraph_hash = kin_db::compute_subgraph_hash(&entity_id, &snapshot, &mut subgraph_cache);

    // Step 4: graph root hash
    let graph_root_hash = kin_db::compute_graph_root_hash(&snapshot);

    // Verification: check this entity's hash against a freshly built hash map
    let stored_hashes = kin_db::build_entity_hash_map(&snapshot);
    let verification = kin_db::verify_entity(&entity_id, &snapshot, &stored_hashes);
    let verified = matches!(verification, kin_db::EntityVerification::Valid);

    // Build the hash chain
    let hash_chain = vec![
        ProvenanceHashStep {
            level: "entity".to_string(),
            hash: hex::encode(entity_hash),
            description: format!(
                "SHA-256 content hash of {} ({:?})",
                entity.name, entity.kind
            ),
        },
        ProvenanceHashStep {
            level: "subgraph".to_string(),
            hash: hex::encode(subgraph_hash),
            description: format!(
                "Subgraph root hash combining entity hash with {} outgoing relation(s)",
                relation_hashes_out.len()
            ),
        },
        ProvenanceHashStep {
            level: "graph_root".to_string(),
            hash: hex::encode(graph_root_hash),
            description: format!(
                "Graph root hash over {} entity subgraphs",
                snapshot.entities.len()
            ),
        },
    ];

    Ok(Json(RepoProvenanceEntityResponse {
        repo_id,
        entity_id: entity_id_str,
        entity_name: entity.name.clone(),
        entity_kind: format!("{:?}", entity.kind),
        file_path: entity.file_origin.as_ref().map(|f| f.0.clone()),
        hash_chain,
        outgoing_relation_hashes: relation_hashes_out,
        subgraph_hash: hex::encode(subgraph_hash),
        graph_root_hash: hex::encode(graph_root_hash),
        verified,
    }))
}

/// GET /repos/{repo_id}/provenance/verify — verify Merkle DAG integrity.
///
/// Computes content hashes for every entity and compares them against the
/// stored hash map. Returns a report with the number of verified/broken
/// entities and the current graph root hash.
async fn repo_provenance_verify(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;
    let snapshot = graph.to_snapshot();

    // Build a stored hash map from the current snapshot (this represents the
    // "expected" hashes). Then verify each entity's current content against it.
    let stored_hashes = kin_db::build_entity_hash_map(&snapshot);

    let mut verified_count = 0usize;
    let mut broken_chains = Vec::new();

    for (eid, entity) in &snapshot.entities {
        let actual = kin_db::compute_entity_hash(entity);
        match stored_hashes.get(eid) {
            Some(&expected) if expected == actual => {
                verified_count += 1;
            }
            Some(&expected) => {
                broken_chains.push(ProvenanceBrokenChain {
                    entity_id: eid.to_string(),
                    entity_name: entity.name.clone(),
                    expected_hash: hex::encode(expected),
                    actual_hash: hex::encode(actual),
                });
            }
            None => {
                // Entity exists but has no stored hash — treat as broken
                broken_chains.push(ProvenanceBrokenChain {
                    entity_id: eid.to_string(),
                    entity_name: entity.name.clone(),
                    expected_hash: "none".to_string(),
                    actual_hash: hex::encode(actual),
                });
            }
        }
    }

    let graph_root_hash = kin_db::compute_graph_root_hash(&snapshot);

    Ok(Json(RepoProvenanceVerifyResponse {
        repo_id,
        valid: broken_chains.is_empty(),
        checked_entities: snapshot.entities.len(),
        verified_entities: verified_count,
        broken_chains,
        graph_root_hash: hex::encode(graph_root_hash),
    }))
}

// ---------------------------------------------------------------------------
// Compare endpoint — arbitrary ref pairs, entity-level conflicts, merge sim
// ---------------------------------------------------------------------------

/// Query parameters for the compare endpoint.
#[derive(Debug, Deserialize)]
struct RepoCompareQuery {
    #[serde(default)]
    left: Option<String>,
    #[serde(default)]
    right: Option<String>,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    simulate_merge: bool,
}

/// Compare response payload.
#[derive(Debug, Serialize)]
pub struct RepoCompareResponsePayload {
    pub repo_id: String,
    pub base_ref: String,
    pub head_ref: String,
    pub merge_base_ref: Option<String>,
    pub ahead: usize,
    pub behind: usize,
    pub files: Vec<CompareFileEntry>,
    pub conflicts: Vec<EntityConflict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_simulation: Option<MergeSimulation>,
}

/// A file entry in the compare result.
#[derive(Debug, Serialize)]
pub struct CompareFileEntry {
    pub path: String,
    pub status: String,
}

/// Entity-level conflict detail for overlapping changes.
#[derive(Debug, Serialize)]
pub struct EntityConflict {
    pub file: String,
    pub entity_id: String,
    pub entity_name: String,
    pub left_version: EntityVersion,
    pub right_version: EntityVersion,
}

/// Snapshot of an entity at a particular side of the comparison.
#[derive(Debug, Serialize)]
pub struct EntityVersion {
    pub change_type: String,
    pub signature: String,
    pub fingerprint: String,
}

/// Result of a simulated 3-way merge.
#[derive(Debug, Serialize)]
pub struct MergeSimulation {
    pub can_auto_merge: bool,
    pub clean_merges: usize,
    pub auto_resolvable_conflicts: usize,
    pub manual_conflicts: usize,
    pub details: Vec<MergeDetail>,
}

/// Per-entity merge simulation detail.
#[derive(Debug, Serialize)]
pub struct MergeDetail {
    pub entity_id: String,
    pub entity_name: String,
    pub file: String,
    pub resolution: String,
}

/// Resolve an arbitrary ref string to a SemanticChangeId.
///
/// Accepts: branch name, full commit hash (hex), or special refs like `HEAD~N`.
fn resolve_ref(
    graph: &kin_db::InMemoryGraph,
    ref_str: &str,
) -> std::result::Result<kin_model::SemanticChangeId, (StatusCode, String)> {
    if let Some(suffix) = ref_str.strip_prefix("HEAD") {
        let branches = sorted_branches(graph)?;
        let branch = select_default_branch(&branches).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "No branch found for HEAD".to_string(),
            )
        })?;
        let mut current = branch.head;
        if let Some(tilde_part) = suffix.strip_prefix('~') {
            let n: usize = tilde_part.parse().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid HEAD~N syntax: {ref_str}"),
                )
            })?;
            for _ in 0..n {
                let change = graph
                    .get_change(&current)
                    .map_err(internal_error)?
                    .ok_or_else(|| {
                        (
                            StatusCode::NOT_FOUND,
                            format!("Change {current} not found in history"),
                        )
                    })?;
                current = change.parents.first().cloned().ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("HEAD~{n} exceeds history depth"),
                    )
                })?;
            }
        } else if !suffix.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown ref syntax: {ref_str}"),
            ));
        }
        return Ok(current);
    }

    // Try as branch name
    if let Some(branch) = graph
        .get_branch(&BranchName::new(ref_str))
        .map_err(internal_error)?
    {
        return Ok(branch.head);
    }

    // Try as hex commit hash
    if let Ok(hash) = kin_model::Hash256::from_hex(ref_str) {
        let change_id = kin_model::SemanticChangeId::from_hash(hash);
        if graph
            .get_change(&change_id)
            .map_err(internal_error)?
            .is_some()
        {
            return Ok(change_id);
        }
    }

    Err((
        StatusCode::BAD_REQUEST,
        format!("Cannot resolve ref: {ref_str}"),
    ))
}

/// Collect which files each side touched.
fn collect_changed_files(
    left_changes: &[kin_model::SemanticChange],
    right_changes: &[kin_model::SemanticChange],
) -> Vec<CompareFileEntry> {
    let mut file_statuses: HashMap<String, String> = HashMap::new();

    for change in left_changes.iter().chain(right_changes.iter()) {
        for file in &change.projected_files {
            file_statuses
                .entry(file.0.clone())
                .or_insert_with(|| "modified".to_string());
        }
        for delta in &change.entity_deltas {
            let path = match delta {
                kin_model::EntityDelta::Added(e) => e.file_origin.as_ref().map(|f| f.0.clone()),
                kin_model::EntityDelta::Modified { new, .. } => {
                    new.file_origin.as_ref().map(|f| f.0.clone())
                }
                kin_model::EntityDelta::Removed(_) => None,
            };
            if let Some(p) = path {
                file_statuses
                    .entry(p)
                    .or_insert_with(|| "modified".to_string());
            }
        }
        for delta in &change.entity_deltas {
            if let kin_model::EntityDelta::Added(e) = delta {
                if let Some(ref f) = e.file_origin {
                    file_statuses.insert(f.0.clone(), "added".to_string());
                }
            }
        }
    }

    let mut files: Vec<CompareFileEntry> = file_statuses
        .into_iter()
        .map(|(path, status)| CompareFileEntry { path, status })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn extract_entity_deltas(
    changes: &[kin_model::SemanticChange],
    out: &mut HashMap<String, (kin_model::EntityDelta, String)>,
) {
    for change in changes {
        for delta in &change.entity_deltas {
            let (id, file) = match delta {
                kin_model::EntityDelta::Added(e) => (
                    e.id.to_string(),
                    e.file_origin
                        .as_ref()
                        .map(|f| f.0.clone())
                        .unwrap_or_default(),
                ),
                kin_model::EntityDelta::Modified { new, .. } => (
                    new.id.to_string(),
                    new.file_origin
                        .as_ref()
                        .map(|f| f.0.clone())
                        .unwrap_or_default(),
                ),
                kin_model::EntityDelta::Removed(id) => (id.to_string(), String::new()),
            };
            out.insert(id, (delta.clone(), file));
        }
    }
}

/// Detect entity-level conflicts: entities modified on both sides since the merge base.
fn detect_entity_conflicts(
    left_changes: &[kin_model::SemanticChange],
    right_changes: &[kin_model::SemanticChange],
) -> Vec<EntityConflict> {
    let mut left_entities: HashMap<String, (kin_model::EntityDelta, String)> = HashMap::new();
    let mut right_entities: HashMap<String, (kin_model::EntityDelta, String)> = HashMap::new();

    extract_entity_deltas(left_changes, &mut left_entities);
    extract_entity_deltas(right_changes, &mut right_entities);

    let mut conflicts = Vec::new();
    for (entity_id, (left_delta, file)) in &left_entities {
        if let Some((right_delta, _)) = right_entities.get(entity_id) {
            let left_ver = entity_version_from_delta(left_delta);
            let right_ver = entity_version_from_delta(right_delta);
            let name = entity_name_from_delta(left_delta);
            conflicts.push(EntityConflict {
                file: file.clone(),
                entity_id: entity_id.clone(),
                entity_name: name,
                left_version: left_ver,
                right_version: right_ver,
            });
        }
    }
    conflicts.sort_by(|a, b| a.file.cmp(&b.file).then(a.entity_name.cmp(&b.entity_name)));
    conflicts
}

fn entity_version_from_delta(delta: &kin_model::EntityDelta) -> EntityVersion {
    match delta {
        kin_model::EntityDelta::Added(e) => EntityVersion {
            change_type: "added".to_string(),
            signature: e.signature.clone(),
            fingerprint: format!("{:?}", e.fingerprint.ast_hash),
        },
        kin_model::EntityDelta::Modified { new, .. } => EntityVersion {
            change_type: "modified".to_string(),
            signature: new.signature.clone(),
            fingerprint: format!("{:?}", new.fingerprint.ast_hash),
        },
        kin_model::EntityDelta::Removed(id) => EntityVersion {
            change_type: "removed".to_string(),
            signature: String::new(),
            fingerprint: id.to_string(),
        },
    }
}

fn entity_name_from_delta(delta: &kin_model::EntityDelta) -> String {
    match delta {
        kin_model::EntityDelta::Added(e) => e.name.clone(),
        kin_model::EntityDelta::Modified { new, .. } => new.name.clone(),
        kin_model::EntityDelta::Removed(id) => id.to_string(),
    }
}

/// Simulate a 3-way merge: compare entity deltas from both sides against the merge base.
fn simulate_merge(
    left_changes: &[kin_model::SemanticChange],
    right_changes: &[kin_model::SemanticChange],
) -> MergeSimulation {
    let mut left_entities: HashMap<String, (kin_model::EntityDelta, String)> = HashMap::new();
    let mut right_entities: HashMap<String, (kin_model::EntityDelta, String)> = HashMap::new();

    extract_entity_deltas(left_changes, &mut left_entities);
    extract_entity_deltas(right_changes, &mut right_entities);

    let mut clean_merges: usize = 0;
    let mut auto_resolvable: usize = 0;
    let mut manual_conflicts: usize = 0;
    let mut details = Vec::new();

    let all_ids: HashSet<String> = left_entities
        .keys()
        .chain(right_entities.keys())
        .cloned()
        .collect();
    for entity_id in &all_ids {
        let in_left = left_entities.get(entity_id);
        let in_right = right_entities.get(entity_id);
        match (in_left, in_right) {
            (Some((delta, file)), None) | (None, Some((delta, file))) => {
                clean_merges += 1;
                details.push(MergeDetail {
                    entity_id: entity_id.clone(),
                    entity_name: entity_name_from_delta(delta),
                    file: file.clone(),
                    resolution: "clean".to_string(),
                });
            }
            (Some((left_delta, file)), Some((right_delta, _))) => {
                let left_fp = entity_version_from_delta(left_delta).fingerprint;
                let right_fp = entity_version_from_delta(right_delta).fingerprint;
                if left_fp == right_fp {
                    auto_resolvable += 1;
                    details.push(MergeDetail {
                        entity_id: entity_id.clone(),
                        entity_name: entity_name_from_delta(left_delta),
                        file: file.clone(),
                        resolution: "auto_resolved".to_string(),
                    });
                } else {
                    manual_conflicts += 1;
                    details.push(MergeDetail {
                        entity_id: entity_id.clone(),
                        entity_name: entity_name_from_delta(left_delta),
                        file: file.clone(),
                        resolution: "manual_conflict".to_string(),
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }

    details.sort_by(|a, b| a.file.cmp(&b.file).then(a.entity_name.cmp(&b.entity_name)));
    MergeSimulation {
        can_auto_merge: manual_conflicts == 0,
        clean_merges,
        auto_resolvable_conflicts: auto_resolvable,
        manual_conflicts,
        details,
    }
}

/// GET /repos/{repo_id}/compare — compare arbitrary ref pairs with entity-level conflict detail.
async fn repo_compare(
    Path(repo_id): Path<String>,
    Query(params): Query<RepoCompareQuery>,
    State(state): State<Arc<DaemonState>>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state
        .get_repo_graph(&repo_id)
        .await
        .map_err(internal_error)?;

    let left_ref_str = params.left.or(params.base).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Missing required query param: base (or left)".to_string(),
        )
    })?;
    let right_ref_str = params.right.or(params.head).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Missing required query param: head (or right)".to_string(),
        )
    })?;

    let left_id = resolve_ref(&graph, &left_ref_str)?;
    let right_id = resolve_ref(&graph, &right_ref_str)?;

    let merge_bases = graph
        .find_merge_bases(&left_id, &right_id)
        .map_err(internal_error)?;
    let merge_base = merge_bases.first().cloned();
    let merge_base_ref = merge_base.as_ref().map(|id| id.to_string());

    let left_changes = if let Some(ref base) = merge_base {
        graph
            .get_changes_since(base, &left_id)
            .map_err(internal_error)?
    } else {
        Vec::new()
    };

    let right_changes = if let Some(ref base) = merge_base {
        graph
            .get_changes_since(base, &right_id)
            .map_err(internal_error)?
    } else {
        Vec::new()
    };

    let ahead = right_changes.len();
    let behind = left_changes.len();

    let files = collect_changed_files(&left_changes, &right_changes);
    let conflicts = detect_entity_conflicts(&left_changes, &right_changes);

    let merge_simulation = if params.simulate_merge {
        Some(simulate_merge(&left_changes, &right_changes))
    } else {
        None
    };

    Ok(Json(RepoCompareResponsePayload {
        repo_id,
        base_ref: left_id.to_string(),
        head_ref: right_id.to_string(),
        merge_base_ref,
        ahead,
        behind,
        files,
        conflicts,
        merge_simulation,
    }))
}

// ---------------------------------------------------------------------------
// VFS endpoints — serve the committed file tree and blob content
// ---------------------------------------------------------------------------

/// Resolve the genesis ID and current branch head for the active branch.
///
/// Returns `Ok(None)` when no branch exists yet.
fn resolve_branch_head(
    state: &DaemonState,
) -> Result<Option<(kin_model::SemanticChangeId, kin_model::SemanticChangeId)>, (StatusCode, String)>
{
    let genesis = kin_core::build_genesis_change();
    let genesis_id = genesis.id;

    let current_branch = kin_core::read_current_branch(&state.layout).ok();

    let head = state
        .graph
        .get_branch(current_branch.as_ref().unwrap_or(&BranchName::new("main")))
        .map_err(internal_error)?
        .map(|b| b.head)
        .or_else(|| {
            state
                .graph
                .get_branch(&BranchName::new("main"))
                .ok()
                .flatten()
                .map(|b| b.head)
        })
        .or_else(|| {
            state
                .graph
                .list_branches()
                .ok()
                .and_then(|branches| branches.into_iter().next().map(|b| b.head))
        });

    match head {
        Some(head_id) => Ok(Some((genesis_id, head_id))),
        None => Ok(None),
    }
}

/// Build the current file tree from the graph's active branch.
///
/// Uses `kin_core::build_file_tree` with the genesis change and the current
/// branch head. Falls back to `main`, then to the first branch, and finally to
/// an empty tree if no branch exists yet.
fn build_current_file_tree(
    state: &DaemonState,
) -> Result<HashMap<FilePathId, kin_model::Hash256>, (StatusCode, String)> {
    let Some((genesis_id, head_id)) = resolve_branch_head(state)? else {
        return Ok(HashMap::new());
    };

    kin_core::build_file_tree(state.graph.as_ref(), &genesis_id, &head_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Walk the SemanticChange DAG and collect the last-modified epoch timestamp
/// for each file path.  Uses the same branch resolution as `build_current_file_tree`.
fn build_current_file_timestamps(
    state: &DaemonState,
) -> Result<HashMap<FilePathId, u64>, (StatusCode, String)> {
    use kin_model::ArtifactDeltaKind;

    let Some((genesis_id, head_id)) = resolve_branch_head(state)? else {
        return Ok(HashMap::new());
    };

    let changes = state
        .graph
        .get_changes_since(&genesis_id, &head_id)
        .map_err(internal_error)?;

    let mut timestamps: HashMap<FilePathId, u64> = HashMap::new();
    for change in &changes {
        let epoch_secs = change.timestamp.0.timestamp() as u64;
        for delta in &change.artifact_deltas {
            match delta.kind {
                ArtifactDeltaKind::Added | ArtifactDeltaKind::Modified => {
                    timestamps.insert(delta.file_id.clone(), epoch_secs);
                }
                ArtifactDeltaKind::Removed => {
                    timestamps.remove(&delta.file_id);
                }
            }
        }
    }
    Ok(timestamps)
}

/// GET /vfs/version — monotonic counter that increments on graph mutations.
async fn vfs_version(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    Json(json!({ "version": state.vfs_version.load(std::sync::atomic::Ordering::SeqCst) }))
}

/// GET /vfs/tree — full file tree as `{ files: { path: hex_hash, ... }, timestamps: { path: epoch_secs, ... } }`.
///
/// Merges the committed tree with overlay additions and removals from the
/// working copy so the VFS sees uncommitted new/deleted files.
async fn vfs_tree(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut tree = build_current_file_tree(&state)?;
    let timestamps = build_current_file_timestamps(&state)?;

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

    let ts: HashMap<String, u64> = timestamps
        .into_iter()
        .map(|(path, epoch)| (path.0, epoch))
        .collect();

    Ok(Json(json!({ "files": files, "timestamps": ts })))
}

/// GET /vfs/stat/*path — return VirtualStat-like JSON for a file path.
async fn vfs_stat(
    Path(path): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tree = build_current_file_tree(&state)?;
    let timestamps = build_current_file_timestamps(&state)?;

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

        let mtime = timestamps.get(&file_id).copied().unwrap_or(0);

        return Ok(Json(json!({
            "is_file": true,
            "is_dir": false,
            "size": size,
            "content_hash": hash.to_string(),
            "mode": 0o644,
            "mtime": mtime,
        })));
    }

    // Check if the path is a directory (any file starts with path/).
    let dir_prefix = if path.ends_with('/') {
        path.clone()
    } else {
        format!("{}/", path)
    };

    let is_dir =
        path.is_empty() || path == "." || tree.keys().any(|k| k.0.starts_with(&dir_prefix));

    if is_dir {
        // Directory mtime = max mtime of any file under it.
        let dir_mtime = timestamps
            .iter()
            .filter(|(fid, _)| fid.0.starts_with(&dir_prefix) || path.is_empty() || path == ".")
            .map(|(_, &t)| t)
            .max()
            .unwrap_or(0);

        return Ok(Json(json!({
            "is_file": false,
            "is_dir": true,
            "size": 0,
            "content_hash": null,
            "mode": 0o755,
            "mtime": dir_mtime,
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
    let hash = tree
        .get(&file_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("file not found: {path}")))?;

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

    let projected = project_vfs_overlay_bytes(&file_id, &blob_data, layout, &merged_bodies)?;

    drop(projection);
    drop(wc);
    Ok(projected)
}

fn project_vfs_overlay_bytes(
    file_id: &FilePathId,
    blob_data: &[u8],
    layout: Option<&FileLayout>,
    merged_bodies: &HashMap<EntityId, Vec<u8>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let Some(layout) = layout else {
        return Ok(blob_data.to_vec());
    };

    match kin_projection::project_overlay_to_bytes(blob_data, layout, merged_bodies) {
        Ok(Some(projected)) => Ok(projected),
        Ok(None) => Ok(blob_data.to_vec()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("projection failed for {}: {}", file_id, e),
        )),
    }
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

/// Rung-3 write-veto precheck shared by the VFS apply paths (`vfs_file_changed`
/// and `vfs_write_notify`) so the two siblings can never drift — leaving one
/// ungated would make enforce-mode trivially bypassable via the other endpoint.
///
/// Under `KIN_WRITE_VETO=enforce`, returns `Err((409, body))` when the file's
/// existing entity scopes or its artifact scope are held under another session's
/// hard intent, rejecting the write *before* it is folded into the graph.
/// Returns `Ok(())` when the veto is off (default) or the write is allowed,
/// leaving the apply path byte-identical to prior behavior. `caller` is the
/// writing session when attributed; a session is never blocked by its own
/// intent. See [`crate::write_veto`].
async fn write_veto_precheck(
    state: &Arc<DaemonState>,
    file_path: &FsPath,
    display_path: &str,
    caller: Option<SessionId>,
) -> std::result::Result<(), (StatusCode, String)> {
    if !crate::write_veto::WriteVetoMode::from_env().is_enforcing() {
        return Ok(());
    }
    let file_id = kin_index::normalize_file_path_id(file_path, state.layout.working_dir());
    let filter = kin_model::EntityFilter {
        file_path: Some(file_id.clone()),
        ..Default::default()
    };
    // Perf: this `query_entities` runs once per write under enforce; it is
    // O(entities-in-file) and is the only added cost on the hot path. Cap the
    // per-file entity-scope comparison set so the veto can never cost more than
    // the reconcile it guards — a file-level hard intent is still caught via the
    // always-present Artifact scope, and the reconciler's own (uncapped) check
    // remains the backstop.
    const VETO_SCOPE_CAP: usize = 1024;
    let file_entities = state
        .graph
        .query_entities(&filter)
        .map_err(internal_error)?;
    if file_entities.len() > VETO_SCOPE_CAP {
        tracing::warn!(
            path = %display_path,
            entities = file_entities.len(),
            cap = VETO_SCOPE_CAP,
            "write-veto: capping per-file entity-scope comparison set"
        );
    }
    let mut touched: Vec<IntentScope> = file_entities
        .iter()
        .take(VETO_SCOPE_CAP)
        .map(|e| IntentScope::Entity(e.id))
        .collect();
    touched.push(IntentScope::Artifact(file_id));

    let intents = state.graph.list_all_intents().map_err(internal_error)?;
    if let crate::write_veto::WriteVetoDecision::Deny { blocking } =
        crate::write_veto::evaluate_write_veto(&intents, &touched, caller)
    {
        tracing::info!(
            path = %display_path,
            blocking = blocking.len(),
            "write-veto: scope held by foreign hard intent"
        );
        let body = crate::write_veto::veto_conflict_body(display_path, &blocking);
        return Err((StatusCode::CONFLICT, body.to_string()));
    }
    Ok(())
}

/// Under `KIN_WRITE_VETO=enforce`, map a reconcile `CollisionBlocked` (e.g. a
/// brand-new entity colliding with a foreign hard intent — a scope the precheck
/// cannot see because the entity does not yet exist in the graph) to the same
/// structured pre-write 409. Returns `None` otherwise, leaving the caller's
/// soft-notification path intact.
fn write_veto_collision_response(
    err: &kin_reconcile::ReconcileError,
    display_path: &str,
) -> Option<(StatusCode, String)> {
    if !crate::write_veto::WriteVetoMode::from_env().is_enforcing() {
        return None;
    }
    if let kin_reconcile::ReconcileError::CollisionBlocked {
        blocking_intents, ..
    } = err
    {
        tracing::info!(
            path = %display_path,
            blocking = blocking_intents.len(),
            "write-veto: hard collision during reconcile"
        );
        let body = crate::write_veto::veto_conflict_body(display_path, blocking_intents);
        return Some((StatusCode::CONFLICT, body.to_string()));
    }
    None
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

    // Rung-3 write veto (KIN_WRITE_VETO=enforce): the general-purpose sibling of
    // /vfs/write-notify must gate too, else enforce is trivially bypassable by
    // choosing this endpoint. Off by default (byte-identical).
    let caller = request
        .session_id
        .as_ref()
        .and_then(|s| s.parse::<Uuid>().ok())
        .map(SessionId);
    write_veto_precheck(&state, &file_path, &request.path, caller).await?;

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

    // Temporarily adopt the caller's session so the reconciler's own collision
    // check excludes the caller's intents (parity with /vfs/write-notify); the
    // write-veto precheck above applies the same own-write exclusion.
    let prev_session_id = if let Some(ref sid) = request.session_id {
        let prev = reconciler.session_id().copied();
        if let Ok(parsed) = sid.parse::<Uuid>() {
            reconciler.set_session_id(SessionId(parsed));
        }
        prev
    } else {
        None
    };

    let result = reconciler.reconcile_file_change_with_hint(
        &event,
        &state.blobs,
        state.graph.as_ref(),
        &mut wc.uncommitted_mutations,
        edit_hint.as_ref(),
    );

    if request.session_id.is_some() {
        match prev_session_id {
            Some(prev) => reconciler.set_session_id(prev),
            None => reconciler.clear_session_id(),
        }
    }

    match result {
        Ok(outcome) => {
            let should_apply = matches!(
                &outcome,
                kin_reconcile::ReconcileOutcome::Updated { .. }
                    | kin_reconcile::ReconcileOutcome::FileRemoved { .. }
            );
            if should_apply {
                kin_reconcile::apply_overlay_to_graph(
                    state.graph.as_ref(),
                    &mut wc.uncommitted_mutations,
                )
                .map_err(internal_error)?;
                state
                    .persist_projection_truth_from_reconcile(&reconciler, &outcome)
                    .map_err(internal_error)?;
            }
            let mut projection_changed = ProjectionChangedSet::default();
            if should_apply {
                projection_changed.record_reconcile_outcome(&outcome);
            }
            drop(wc);
            drop(reconciler);
            tracing::debug!(path = %request.path, ?outcome, "reconciled file change");

            // Emit SSE events for each entity affected by the file change.
            use crate::state::{ChangeType, DaemonEvent};
            use kin_reconcile::ReconcileOutcome;

            let (added_count, modified_count, removed_count) = match &outcome {
                ReconcileOutcome::Updated {
                    added,
                    modified,
                    removed,
                    ..
                } => {
                    for id in added {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Created,
                            file_path: Some(request.path.clone()),
                            // Truthful attribution: the originating session the
                            // VFS write-back request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    for id in modified {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Modified,
                            file_path: Some(request.path.clone()),
                            // Truthful attribution: the originating session the
                            // VFS write-back request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    for id in removed {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Deleted,
                            file_path: Some(request.path.clone()),
                            // Truthful attribution: the originating session the
                            // VFS write-back request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    (added.len(), modified.len(), removed.len())
                }
                _ => (0, 0, 0),
            };

            // Bump version counter and refresh projection so subsequent
            // VFS reads serve updated FileLayouts.
            if !projection_changed.is_empty() {
                state.bump_version(); // marks dirty for background persistence
                if let Err(e) = state.refresh_projection(&projection_changed).await {
                    tracing::warn!(error = %e, "failed to refresh projection after write-back");
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
            // Under enforce, surface a hard collision detected during reconcile
            // as a pre-write 409 rather than the soft notification below.
            if let Some(resp) = write_veto_collision_response(&e, &request.path) {
                return Err(resp);
            }
            tracing::warn!(path = %request.path, error = %e, "reconciliation failed");
            Ok(Json(json!({
                "status": "error",
                "path": request.path,
                "error": e.to_string(),
            })))
        }
    }
}

/// POST /vfs/write-notify — immediate re-index triggered by VFS shim after write-through.
///
/// The shim sends this notification right after a write completes on disk,
/// tightening the window where file state leads graph state. Unlike
/// `/vfs/file-changed` (which is general-purpose), this endpoint is
/// optimized for the shim hot-path: minimal request body, fast response.
async fn vfs_write_notify(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<WriteNotifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let file_path = std::path::PathBuf::from(&request.file_path);
    tracing::info!(path = %request.file_path, "VFS write-notify received");

    // Rung-3 write veto (KIN_WRITE_VETO=enforce): reject a write whose existing
    // entity/artifact scopes are held under another session's hard intent
    // before the reconciler touches the overlay. Off by default (byte-identical).
    let caller = request
        .session_id
        .as_ref()
        .and_then(|s| s.parse::<Uuid>().ok())
        .map(SessionId);
    write_veto_precheck(&state, &file_path, &request.file_path, caller).await?;

    let event = kin_index::FileEvent::Changed(file_path);

    let mut reconciler = state.reconciler.write().await;
    let mut wc = state.working_copy.write().await;

    // If the caller supplies a session_id, temporarily set it on the
    // reconciler so check_scopes() excludes the caller's own intents.
    let prev_session_id = if let Some(ref sid) = request.session_id {
        let prev = reconciler.session_id().copied();
        if let Ok(parsed) = sid.parse::<Uuid>() {
            reconciler.set_session_id(SessionId(parsed));
        }
        prev
    } else {
        None
    };

    let result = reconciler.reconcile_file_change_with_hint(
        &event,
        &state.blobs,
        state.graph.as_ref(),
        &mut wc.uncommitted_mutations,
        None,
    );

    // Always restore the previous session_id so caller identity doesn't
    // leak into future reconciles through the shared reconciler.
    if request.session_id.is_some() {
        match prev_session_id {
            Some(prev) => reconciler.set_session_id(prev),
            None => reconciler.clear_session_id(),
        }
    }

    match result {
        Ok(outcome) => {
            let should_apply = matches!(
                &outcome,
                kin_reconcile::ReconcileOutcome::Updated { .. }
                    | kin_reconcile::ReconcileOutcome::FileRemoved { .. }
            );
            if should_apply {
                kin_reconcile::apply_overlay_to_graph(
                    state.graph.as_ref(),
                    &mut wc.uncommitted_mutations,
                )
                .map_err(internal_error)?;
                state
                    .persist_projection_truth_from_reconcile(&reconciler, &outcome)
                    .map_err(internal_error)?;
            }
            let mut projection_changed = ProjectionChangedSet::default();
            if should_apply {
                projection_changed.record_reconcile_outcome(&outcome);
            }

            let entity_count = match &outcome {
                kin_reconcile::ReconcileOutcome::Updated {
                    added,
                    modified,
                    removed,
                    ..
                } => {
                    let count = added.len() + modified.len() + removed.len();

                    for id in added {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: crate::state::ChangeType::Created,
                            file_path: Some(request.file_path.clone()),
                            // Truthful attribution: the originating session the
                            // write-notify request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    for id in modified {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: crate::state::ChangeType::Modified,
                            file_path: Some(request.file_path.clone()),
                            // Truthful attribution: the originating session the
                            // write-notify request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    for id in removed {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: crate::state::ChangeType::Deleted,
                            file_path: Some(request.file_path.clone()),
                            // Truthful attribution: the originating session the
                            // write-notify request carried (None if anonymous).
                            session_id: request.session_id.clone(),
                        });
                    }
                    count
                }
                _ => 0,
            };

            drop(wc);
            drop(reconciler);

            if !projection_changed.is_empty() {
                state.bump_version(); // marks dirty for background persistence
                if let Err(e) = state.refresh_projection(&projection_changed).await {
                    tracing::warn!(error = %e, "failed to refresh projection after write-notify");
                }
            }

            Ok(Json(json!({
                "reindexed": true,
                "entity_count": entity_count,
            })))
        }
        Err(e) => {
            drop(wc);
            drop(reconciler);
            // Under enforce, surface a hard collision detected during reconcile
            // (e.g. a brand-new entity the precheck cannot see) as a pre-write
            // 409 rather than the soft notification below.
            if let Some(resp) = write_veto_collision_response(&e, &request.file_path) {
                return Err(resp);
            }
            tracing::warn!(path = %request.file_path, error = %e, "write-notify reconciliation failed");
            Ok(Json(json!({
                "reindexed": false,
                "entity_count": 0,
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
async fn vfs_subscribe(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
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
    let spine = state.ensure_spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine disabled via KIN_DISABLE_SPINE".to_string(),
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
    let spine = state.ensure_spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine disabled via KIN_DISABLE_SPINE".to_string(),
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
    let spine = state.ensure_spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine disabled via KIN_DISABLE_SPINE".to_string(),
        )
    })?;

    let kind_str = params.kind.as_deref();
    let kind = kind_str.and_then(parse_entity_kind);
    let mut results = spine.resolve(&params.name, kind, None);
    // "test" is role-based — spine EntityEntry now carries role
    if kind_str.is_some_and(|k| k.eq_ignore_ascii_case("test")) {
        results.retain(|r| r.role == Some(kin_model::EntityRole::Test));
    }

    Ok(Json(json!({ "results": results })))
}

/// GET /spine/impact?repo=A&entity=X&depth=3 — federated impact analysis.
async fn spine_impact(
    Query(params): Query<SpineImpactParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.ensure_spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine disabled via KIN_DISABLE_SPINE".to_string(),
        )
    })?;

    let entity_id = parse_entity_id_hex(&params.entity)?;
    let impact = spine.federated_impact(&params.repo, &entity_id, params.depth);

    let mut body = serde_json::to_value(&impact).map_err(internal_error)?;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "version".to_string(),
            json!(kin_spine::SPINE_PAYLOAD_VERSION),
        );
    }
    Ok(Json(body))
}

/// GET /spine/xref?repo=A&entity=X — cross-repo edges for an entity.
async fn spine_xref(
    Query(params): Query<SpineXrefParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.ensure_spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine disabled via KIN_DISABLE_SPINE".to_string(),
        )
    })?;

    let entity_id = parse_entity_id_hex(&params.entity)?;
    let edges = spine.cross_repo_edges_for(&params.repo, &entity_id);

    Ok(Json(
        json!({ "version": kin_spine::SPINE_PAYLOAD_VERSION, "edges": edges }),
    ))
}

/// Body for `POST /spine/repos/{repo_id}/ingest`.
///
/// The control-plane import orchestrator (kinlab) POSTs this per cataloged repo
/// to drive the daemon's graph-authority ingest path. `repo` is informational
/// (the path `repo_id` is authoritative); `refresh_cross_repo_edges` is set for
/// the cross-repo anchor so the resolver runs once the spine is multi-repo.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpineIngestBody {
    /// Repo name as the orchestrator knows it (informational; path wins).
    #[serde(default)]
    repo: Option<String>,
    /// Materialize cross-repo edges for this repo after registering it. Set by
    /// the orchestrator for the anchor repo (e.g. `kin`).
    #[serde(default)]
    refresh_cross_repo_edges: bool,
}

/// `POST /spine/repos/{repo_id}/ingest` — load a repo's graph from durable
/// storage (GCS in cloud) into the spine store.
///
/// This is the production multi-repo write path: it lets a single-repo hosted
/// pod build a spine holding ≥2 repos so `GET /spine/xref` returns non-empty
/// cross-repo edges. The daemon answers purely from graph-owned truth — it
/// loads the named repo's graph through the configured `StorageBackend`,
/// registers its entity metadata (write-through to the durable spine store),
/// and — for the anchor — materializes the cross-repo edges.
///
/// Reports graph-derived counts the control plane gates the org graph on,
/// including `resolvableRelationCount` (relations that can actually bind into
/// cross-repo edges). Field names are camelCase to match the orchestrator's
/// `DaemonIngestResponse`.
async fn spine_ingest_repo(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    body: Option<Json<SpineIngestBody>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let Json(body) = body.unwrap_or_default();

    // The path `repo_id` is authoritative; reject a body `repo` that disagrees
    // so an orchestrator wiring bug can't ingest the wrong repo silently.
    if let Some(repo) = body.repo.as_deref() {
        if !repo.is_empty() && repo != repo_id {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("body repo {repo:?} does not match path repo_id {repo_id:?}"),
            ));
        }
    }

    let outcome = state
        .ingest_repo_into_spine(&repo_id, body.refresh_cross_repo_edges)
        .await
        .map_err(internal_error)?;

    Ok(Json(json!({
        "repoId": outcome.repo_id,
        "rootHash": outcome.root_hash,
        "entityCount": outcome.entity_count,
        "relationCount": outcome.relation_count,
        "resolvableRelationCount": outcome.resolvable_relations,
    })))
}

/// `POST /spine/refresh-cross-repo-edges` — re-resolve cross-repo edges for
/// every registered repo.
///
/// The control-plane import orchestrator calls this once, after all repos are
/// ingested, so cross-repo edges emanate from every repo (mirroring the local
/// daemon's multi-anchor pass) rather than only the anchor. Loads each repo's
/// graph from durable storage and re-materializes its outgoing edges; the
/// operation is idempotent. Field names are camelCase to match the orchestrator.
async fn spine_refresh_cross_repo_edges(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let outcome = state
        .refresh_all_cross_repo_edges()
        .await
        .map_err(internal_error)?;

    Ok(Json(json!({
        "reposRefreshed": outcome.repos_refreshed,
        "crossRepoEdges": outcome.cross_repo_edges,
    })))
}

/// POST /lsp/sweep — trigger a full LSP cold sweep of all entities.
async fn lsp_sweep(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    state.queue_lsp_sweep();
    Json(json!({"status": "sweep_queued"}))
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
        // "test" is role-based (EntityRole::Test), not kind-based.
        // Return None so the caller can apply role filtering instead.
        "test" => None,
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

fn default_session_transport() -> String {
    "mcp".to_string()
}

fn parse_session_transport(transport: &str) -> Result<SessionTransport, (StatusCode, String)> {
    match transport.trim().to_ascii_lowercase().as_str() {
        "mcp" => Ok(SessionTransport::Mcp),
        "cli" => Ok(SessionTransport::Cli),
        "wrapper" => Ok(SessionTransport::Wrapper),
        "ui" => Ok(SessionTransport::Ui),
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("invalid transport '{other}': expected mcp, cli, wrapper, or ui"),
        )),
    }
}

fn parse_timestamp(value: &str) -> Result<kin_model::timestamp::Timestamp, (StatusCode, String)> {
    serde_json::from_value(serde_json::json!(value)).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid timestamp '{value}': {error}"),
        )
    })
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

fn primary_repo_id(state: &DaemonState) -> String {
    std::env::var("KIN_REPO_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            state
                .layout
                .working_dir()
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string())
        })
        .unwrap_or_else(|| "default".to_string())
}

/// Derive a short repo name from the daemon's working directory.
fn repo_name(state: &DaemonState) -> String {
    primary_repo_id(state)
}

/// Collect the current file tree contents as (path, bytes) pairs.
fn collect_archive_files(
    state: &DaemonState,
) -> Result<Vec<(String, Vec<u8>)>, (StatusCode, String)> {
    let tree = build_current_file_tree(state)?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(tree.len());
    for (file_id, hash) in &tree {
        let blob_hash = kin_blobs::Hash256(hash.0);
        let data = state.blobs.read(&blob_hash).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("blob read error for {}: {e}", file_id.0),
            )
        })?;
        files.push((file_id.0.clone(), data));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// GET /archive/{ref}.tar.gz — download a gzipped tarball of the repo file tree.
async fn archive_tar_gz(
    Path(git_ref): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let files = collect_archive_files(&state)?;
    let name = repo_name(&state);
    let prefix = format!("{name}-{git_ref}/");

    let mut buf = Vec::new();
    {
        let gz = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::fast());
        let mut archive = tar::Builder::new(gz);

        for (path, data) in &files {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            let entry_path = format!("{prefix}{path}");
            archive
                .append_data(&mut hdr, &entry_path, data.as_slice())
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("tar write error: {e}"),
                    )
                })?;
        }

        archive.finish().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("tar finish error: {e}"),
            )
        })?;
    }

    let filename = format!("{name}-{git_ref}.tar.gz");
    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "public, max-age=300".to_string()),
        ],
        buf,
    ))
}

/// GET /archive/{ref}.zip — download a zip archive of the repo file tree.
async fn archive_zip(
    Path(git_ref): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let files = collect_archive_files(&state)?;
    let name = repo_name(&state);
    let prefix = format!("{name}-{git_ref}/");

    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);

        for (path, data) in &files {
            let entry_path = format!("{prefix}{path}");
            zip.start_file(&entry_path, options).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("zip write error: {e}"),
                )
            })?;
            zip.write_all(data).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("zip write error: {e}"),
                )
            })?;
        }

        zip.finish().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("zip finish error: {e}"),
            )
        })?;
    }

    let filename = format!("{name}-{git_ref}.zip");
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "public, max-age=300".to_string()),
        ],
        buf,
    ))
}

fn internal_error<E: std::fmt::Display>(error: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn bad_request<E: std::fmt::Display>(error: E) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
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
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    serve_with_shutdown(state, port, shutdown_rx).await
}

/// Start the API server on the given port and stop when shutdown is signaled.
pub async fn serve_with_shutdown(
    state: Arc<DaemonState>,
    port: u16,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let bind_host = bind_host_from_env();
    let auth_token = resolve_serve_auth_token(&state.layout);
    let app = router_with_auth(state, auth_token.clone());
    let listener = bind_listener(&bind_host, port, auth_token.is_some())?;

    info!(port, "daemon API server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
}

fn resolve_bind_host(bind_host: Option<String>) -> String {
    bind_host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn bind_host_from_env() -> String {
    resolve_bind_host(std::env::var("KIN_DAEMON_BIND_HOST").ok())
}

fn resolve_auth_token(auth_token: Option<String>) -> Option<String> {
    auth_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn auth_token_from_env() -> Option<String> {
    resolve_auth_token(std::env::var("KIN_DAEMON_AUTH_TOKEN").ok())
}

/// `.kin/daemon.token` — auto-provisioned per-install loopback token.
fn loopback_token_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.root().join("daemon.token")
}

/// Load the per-install loopback token, generating and persisting one (mode
/// 0600 on unix) on first run. This token defends the loopback daemon against
/// non-browser local processes (browser cross-origin is already blocked by
/// `validate_host_and_origin`); local clients read the same file and send it
/// as `Authorization: Bearer <token>`.
fn ensure_loopback_token(layout: &kin_core::KinLayout) -> std::io::Result<String> {
    let path = loopback_token_path(layout);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

/// Whether the daemon should ENFORCE the per-install loopback token.
///
/// Enforcement is opt-in (`KIN_DAEMON_REQUIRE_TOKEN`) because turning it on by
/// default would `401` every local client that does not yet send the token —
/// the CLI (`daemon_client.rs`) and any un-updated path. The file is still
/// auto-provisioned so clients can adopt it; once CLI + MCP delegate both read
/// it, flip this flag to require it. The primary DNS-rebinding defense
/// (`validate_host_and_origin`) is always active regardless of this flag.
fn loopback_token_enforced() -> bool {
    std::env::var("KIN_DAEMON_REQUIRE_TOKEN")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Resolve the auth token the serving daemon enforces: an explicit
/// `KIN_DAEMON_AUTH_TOKEN` override always wins. Otherwise the per-install
/// loopback token is auto-provisioned under `.kin/` (so local clients can adopt
/// it) but only returned for enforcement when `KIN_DAEMON_REQUIRE_TOKEN`
/// is set. If provisioning fails the daemon still starts (loopback Host/Origin
/// validation remains active) but logs a warning.
fn resolve_serve_auth_token(layout: &kin_core::KinLayout) -> Option<String> {
    if let Some(env_token) = auth_token_from_env() {
        return Some(env_token);
    }
    match ensure_loopback_token(layout) {
        Ok(token) => loopback_token_enforced().then_some(token),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to provision loopback auth token; daemon will run without bearer auth"
            );
            None
        }
    }
}

fn parse_bind_host(bind_host: &str) -> std::io::Result<IpAddr> {
    if bind_host.eq_ignore_ascii_case("localhost") {
        return Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    bind_host.parse::<IpAddr>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid KIN_DAEMON_BIND_HOST: {bind_host}"),
        )
    })
}

fn bind_listener(
    bind_host: &str,
    port: u16,
    auth_token_present: bool,
) -> std::io::Result<tokio::net::TcpListener> {
    let bind_ip = parse_bind_host(bind_host)?;
    if !bind_ip.is_loopback() && !auth_token_present {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "KIN_DAEMON_AUTH_TOKEN is required when binding to a non-loopback host",
        ));
    }

    let address = SocketAddr::new(bind_ip, port);
    let domain = match bind_ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if matches!(bind_ip, IpAddr::V6(_)) {
        socket.set_only_v6(false)?;
    }
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

    #[test]
    fn semloc_rerank_priority_demotes_and_boosts() {
        use kin_model::EntityRole;
        let q = "raspbian package detection";
        // Equal cosine distance: a Source entity outranks (lower priority than) a
        // Test/Docs/Generated/Vendored entity when the query is not test-related.
        let src = semloc_rerank_priority(Some(EntityRole::Source), "Detector", q, false, 0.30);
        for role in [
            EntityRole::Test,
            EntityRole::Docs,
            EntityRole::Generated,
            EntityRole::Vendored,
        ] {
            let demoted = semloc_rerank_priority(Some(role), "Detector", q, false, 0.30);
            assert!(
                demoted > src,
                "{role:?} must be demoted below Source at equal cosine"
            );
        }
        // External / unknown role are NOT demoted.
        assert!(
            (semloc_rerank_priority(Some(EntityRole::External), "X", q, false, 0.30) - 0.30).abs()
                < 1e-6
        );
        assert!((semloc_rerank_priority(None, "X", q, false, 0.30) - 0.30).abs() < 1e-6);
    }

    fn tool_result_json(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
        serde_json::to_value(result).unwrap()
    }

    #[test]
    fn entity_source_tool_result_not_found_surfaces_error_not_missing_source() {
        use kin_cli::commands::graph::EntitySourceOutcome;
        // The case that previously rendered as "graph source response missing
        // source": a not-found ID must surface its own error verbatim.
        let message = "no entity exists with ID 'abc'. This entity ID is invalid or stale.";
        let result = entity_source_tool_result(Ok::<_, String>(EntitySourceOutcome::NotFound(
            message.into(),
        )));

        let json = tool_result_json(&result);
        assert_eq!(json["isError"], serde_json::json!(true));
        let text = json["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, message);
        assert!(!text.contains("missing source"), "{text}");
    }

    #[test]
    fn entity_source_tool_result_no_source_is_distinct_from_not_found() {
        use kin_cli::commands::graph::EntitySourceOutcome;
        let not_found =
            entity_source_tool_result(Ok::<_, String>(EntitySourceOutcome::NotFound("NF".into())));
        let no_source =
            entity_source_tool_result(Ok::<_, String>(EntitySourceOutcome::NoSource("NS".into())));

        let nf = tool_result_json(&not_found);
        let ns = tool_result_json(&no_source);
        assert_eq!(nf["isError"], serde_json::json!(true));
        assert_eq!(ns["isError"], serde_json::json!(true));
        let nf_text = nf["content"][0]["text"].as_str().unwrap();
        let ns_text = ns["content"][0]["text"].as_str().unwrap();
        assert_eq!(nf_text, "NF");
        assert_eq!(ns_text, "NS");
        assert_ne!(nf_text, ns_text);
    }

    #[test]
    fn entity_source_tool_result_found_serializes_record_without_error_flag() {
        use kin_cli::commands::graph::{EntitySourceOutcome, GraphSourceRecord};
        let record = GraphSourceRecord {
            id: "id-1".into(),
            name: "target".into(),
            kind: "Function".into(),
            language: "rust".into(),
            file_path: "src/lib.rs".into(),
            start_line: 1,
            end_line: 3,
            start_byte: 0,
            end_byte: 14,
            signature: "fn target()".into(),
            body: "fn target() {}".into(),
        };
        let result = entity_source_tool_result(Ok::<_, String>(EntitySourceOutcome::Found(record)));

        let json = tool_result_json(&result);
        // A success result omits the isError flag entirely.
        assert!(json.get("isError").is_none());
        let text = json["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"body\": \"fn target() {}\""), "{text}");
    }

    #[test]
    fn entity_source_tool_result_genuine_error_surfaces_message() {
        use kin_cli::commands::graph::EntitySourceOutcome;
        let result = entity_source_tool_result(Err::<EntitySourceOutcome, _>(
            "graph blob for file 'src/lib.rs' is unavailable".to_string(),
        ));
        let json = tool_result_json(&result);
        assert_eq!(json["isError"], serde_json::json!(true));
        let text = json["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("graph blob for file 'src/lib.rs' is unavailable"),
            "{text}"
        );
    }

    #[test]
    fn semloc_rerank_test_role_kept_for_test_query() {
        use kin_model::EntityRole;
        // When the query IS test-related, a Test-role entity is not demoted.
        let p = semloc_rerank_priority(
            Some(EntityRole::Test),
            "X",
            "fix the parser test",
            true,
            0.40,
        );
        assert!(
            (p - 0.40).abs() < 1e-6,
            "test-role must survive a test query"
        );
    }

    #[test]
    fn semloc_rerank_exact_name_boost_and_dominance() {
        use kin_model::EntityRole;
        // Lever B: exact token match floats a Source entity up (lower priority).
        let exact = semloc_rerank_priority(
            Some(EntityRole::Source),
            "Raspbian",
            "constant.Raspbian",
            false,
            0.50,
        );
        let fuzzy = semloc_rerank_priority(
            Some(EntityRole::Source),
            "RaspbianHelper",
            "constant.Raspbian",
            false,
            0.50,
        );
        assert!(
            exact < fuzzy,
            "exact name token must outrank a fuzzy namesake"
        );
        // Demotion dominates the exact bonus: an exact match in a demoted role does
        // not jump ahead of a non-exact Source entity at the same cosine.
        let exact_test = semloc_rerank_priority(
            Some(EntityRole::Generated),
            "Raspbian",
            "constant.Raspbian",
            false,
            0.50,
        );
        let plain_src = semloc_rerank_priority(
            Some(EntityRole::Source),
            "Other",
            "constant.Raspbian",
            false,
            0.50,
        );
        assert!(
            exact_test > plain_src,
            "demote must dominate the exact bonus"
        );
    }

    #[test]
    fn semloc_query_token_matching() {
        assert!(semloc_query_has_exact_token(
            "constant.Raspbian",
            "Raspbian"
        ));
        assert!(semloc_query_has_exact_token(
            "RemoveRaspbianPackFromResult here",
            "RemoveRaspbianPackFromResult"
        ));
        assert!(!semloc_query_has_exact_token("scan results", "Detector"));
        assert!(!semloc_query_has_exact_token("anything", ""));
        assert!(semloc_query_is_test_related("the wav2vec feature test"));
        assert!(!semloc_query_is_test_related("css scoping selector"));
    }
    use axum::routing::get as axum_get;
    use kin_model::{
        AgentSession, AnnotationFilter, ArtifactDelta, ArtifactDeltaKind, AuthorId, Branch,
        BranchName, Entity, EntityDelta, EntityId, EntityKind, EntityRole, FilePathId,
        FingerprintAlgorithm, Hash256, IdentityRef, ImportSection, IntentScope, LanguageId,
        Priority, SemanticChange, SemanticChangeId, SemanticFingerprint, SourceRegion, SourceSpan,
        TestCase, TestKind, TestRunner, Timestamp, Visibility, WorkItem, WorkKind, WorkScope,
        WorkStatus, WorkStore,
    };
    use kin_model::{ReviewStore, VerificationStore};
    use kin_registry::Ecosystem;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    fn install_test_registry_override() {
        static REGISTRY_PATH: OnceLock<PathBuf> = OnceLock::new();
        let path = REGISTRY_PATH.get_or_init(|| {
            let root = std::env::temp_dir()
                .join(format!("kin-daemon-test-registry-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("registry.toml");
            std::fs::write(&path, "repos = []\n").unwrap();
            path
        });

        std::env::set_var("KIN_REGISTRY_PATH", path);
    }

    #[test]
    fn nanos_per_forward_is_absent_without_forward_calls() {
        assert_eq!(nanos_per_forward(42, 0), None);
        assert_eq!(nanos_per_forward(42, 2), Some(21));
    }

    fn test_state() -> Arc<DaemonState> {
        install_test_registry_override();
        let dir = std::env::temp_dir().join(format!("kin-daemon-test-state-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let kin_dir = dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("objects")).unwrap();
        std::fs::create_dir_all(kin_dir.join("working")).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);
        kin_core::manifest::KinManifest::new()
            .save(&layout.manifest_path())
            .unwrap();
        Arc::new(DaemonState::open(layout).unwrap())
    }

    #[test]
    fn scope_build_timeout_defaults_and_rejects_invalid_values() {
        assert_eq!(resolve_scope_build_timeout(None), Duration::from_secs(870));
        assert_eq!(
            resolve_scope_build_timeout(Some("")),
            Duration::from_secs(870)
        );
        assert_eq!(
            resolve_scope_build_timeout(Some("0")),
            Duration::from_secs(870)
        );
        assert_eq!(
            resolve_scope_build_timeout(Some("12")),
            Duration::from_secs(12)
        );
    }

    fn test_entity(name: &str, path: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0x01; 32]),
                signature_hash: Hash256::from_bytes([0x02; 32]),
                behavior_hash: Hash256::from_bytes([0x03; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(kin_model::FilePathId::new(path)),
            span: Some(SourceSpan {
                file: kin_model::FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 20,
            }),
            signature: format!("def {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: Default::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn install_branch_file(state: &Arc<DaemonState>, rel_path: &str, content: &[u8]) {
        let branch_name = BranchName::new("main");
        let genesis = kin_core::build_genesis_change();
        state.graph.create_change(&genesis).unwrap();

        let blob_store = kin_blobs::BlobStore::new(state.layout.objects_dir()).unwrap();
        let blob_hash = blob_store.write(content).unwrap();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x77; 32])),
            parents: vec![genesis.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add test file".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId::new(rel_path),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(blob_hash),
            }],
            projected_files: vec![FilePathId::new(rel_path)],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        state.graph.create_change(&change).unwrap();
        state
            .graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: change.id,
            })
            .unwrap();
        kin_core::write_current_branch(&state.layout, &branch_name).unwrap();
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
        assert_eq!(json.build.sha, kin_buildinfo::get().sha);
        assert_eq!(json.build.dirty, kin_buildinfo::get().dirty);
        assert!(!json.build.built_at.is_empty());
        // Additive freshness marker present; 0 before any snapshot is committed.
        assert_eq!(json.graph_generation, 0);
    }

    #[tokio::test]
    async fn graph_commit_creates_missing_branch_for_first_hosted_publish() {
        let state = test_state();
        let entity = test_entity("served_fn", "src/lib.py");
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x83; 32]));
        let payload = serde_json::json!({
            "change": {
                "id": change_id,
                "parents": [],
                "timestamp": Timestamp::now(),
                "author": "tester",
                "message": "first hosted publish",
                "entity_deltas": [{ "Added": entity }],
                "relation_deltas": [],
                "artifact_deltas": [],
                "projected_files": [],
                "spec_link": null,
                "evidence": [],
                "risk_summary": null,
                "authored_on": "main",
            },
            "branch_name": "main",
        });
        let app = router(Arc::clone(&state));

        let response = app
            .clone()
            .oneshot(
                Request::post("/graph/commit")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let refs_path = format!("/repos/{}/refs", state.cached_repo_id);
        let refs_response = app
            .oneshot(Request::get(refs_path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(refs_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(refs_response.into_body(), 8192)
            .await
            .unwrap();
        let refs: RepoRefsResponse = serde_json::from_slice(&body).unwrap();
        let change_id_string = change_id.to_string();
        assert_eq!(refs.branch_name.as_deref(), Some("main"));
        assert_eq!(refs.head_ref.as_deref(), Some(change_id_string.as_str()));
        assert_eq!(state.graph.entity_count(), 1);
    }

    #[tokio::test]
    async fn health_surfaces_graph_generation_marker() {
        // /health must read and surface the persisted snapshot generation marker
        // (.kin/kindb/generation) so the MCP envelope can express graph_as_of.
        let state = test_state();
        let kindb = state.layout.root().join("kindb");
        std::fs::create_dir_all(&kindb).unwrap();
        std::fs::write(kindb.join("generation"), "7").unwrap();

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
        assert_eq!(
            json.graph_generation, 7,
            "/health must surface the persisted graph generation marker"
        );
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
    async fn graph_bootstrap_returns_snapshot_bytes() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/graph/bootstrap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let _snapshot = kin_db::GraphSnapshot::from_bytes(&body).unwrap();
    }

    #[tokio::test]
    async fn locate_endpoint_resolves_historical_ref_queries() {
        std::env::set_var("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "true");
        let state = test_state();
        let graph = state.graph.as_ref();
        let add_git_ref = "1111111111111111111111111111111111111111";
        let modify_git_ref = "2222222222222222222222222222222222222222";

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("handler", "src/lib.py");
        let mut entity_v2 = entity_v1.clone();
        entity_v2.name = "processor".to_string();
        entity_v2.signature = "def processor()".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x04; 32]);

        let add_id = kin_git::semantic_change_id_from_git_oid_hex(add_git_ref).unwrap();
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add handler".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let modify_id = kin_git::semantic_change_id_from_git_oid_hex(modify_git_ref).unwrap();
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "rename handler".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1,
                    new: entity_v2,
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let app = router(state);

        let historical = app
            .clone()
            .oneshot(
                Request::post("/locate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "text": "handler failure",
                            "explain": false,
                            "max_files": 10,
                            "max_files_explicit": true,
                            "reference": format!("git:{add_git_ref}"),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(historical.status(), StatusCode::OK);
        let historical_body = axum::body::to_bytes(historical.into_body(), 4096)
            .await
            .unwrap();
        let historical_json: kin_cli::commands::locate::LocateResult =
            serde_json::from_slice(&historical_body).unwrap();
        assert!(
            historical_json
                .files
                .iter()
                .any(|file| file.path == "src/lib.py"),
            "historical locate should resolve the pre-rename symbol"
        );

        let current = app
            .oneshot(
                Request::post("/locate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "text": "handler failure",
                            "explain": false,
                            "max_files": 10,
                            "max_files_explicit": true,
                            "reference": format!("git:{modify_git_ref}"),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);
        let current_body = axum::body::to_bytes(current.into_body(), 4096)
            .await
            .unwrap();
        let current_json: kin_cli::commands::locate::LocateResult =
            serde_json::from_slice(&current_body).unwrap();
        assert!(
            current_json
                .files
                .iter()
                .all(|file| file.path != "src/lib.py"),
            "current locate should not match the historical symbol name"
        );
        std::env::remove_var("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK");
    }

    #[tokio::test]
    async fn mcp_tools_call_semantic_search_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        let branch_name = BranchName::new("main");
        state
            .graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: kin_core::build_genesis_change().id,
            })
            .unwrap();
        kin_core::write_current_branch(&state.layout, &branch_name).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "semantic_search",
                            "arguments": {
                                "query": "handler",
                                "compact": true,
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
        assert_ne!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            kin_mcp::ContentBlock::Text { text } => text,
        };
        assert!(text.contains("handler"));
        assert!(text.contains("src/lib.py"));
    }

    async fn mcp_call(
        router: axum::Router,
        name: &str,
        arguments: serde_json::Value,
    ) -> kin_mcp::ToolCallResult {
        let response = router
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "name": name, "arguments": arguments }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn mcp_result_text(result: &kin_mcp::ToolCallResult) -> String {
        match result.content.first().unwrap() {
            kin_mcp::ContentBlock::Text { text } => text.clone(),
        }
    }

    #[tokio::test]
    async fn mcp_transaction_persists_across_calls() {
        // Regression: each /mcp/tools/call rebuilds a fresh SessionRegistry, so
        // without DaemonState-backed transaction persistence a transaction begun
        // in one call is gone by the next ("Transaction not found"). begin → stage
        // → validate are three separate HTTP calls and must share state.
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // 1. begin
        let begin = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_begin",
            serde_json::json!({ "session_id": "sess-1", "scope": "file:src/lib.rs" }),
        )
        .await;
        assert_ne!(begin.is_error, Some(true), "begin failed: {begin:?}");
        let begin_json: serde_json::Value = serde_json::from_str(&mcp_result_text(&begin)).unwrap();
        let tx_id = begin_json["transaction_id"].as_str().unwrap().to_string();

        // 2. stage onto the transaction from a SEPARATE call
        let stage = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({
                "transaction_id": tx_id,
                "operations": [{
                    "verb": "create",
                    "target": "",
                    "payload": { "Entity": test_entity("new_fn", "src/lib.rs") },
                    "description": ""
                }]
            }),
        )
        .await;
        assert_ne!(
            stage.is_error,
            Some(true),
            "stage must find the persisted transaction, got: {}",
            mcp_result_text(&stage)
        );
        let stage_json: serde_json::Value = serde_json::from_str(&mcp_result_text(&stage)).unwrap();
        assert_eq!(stage_json["staged_count"], 1);

        // 3. validate from yet another call — proves state carried again
        let validate = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_validate",
            serde_json::json!({ "transaction_id": tx_id }),
        )
        .await;
        assert_ne!(
            validate.is_error,
            Some(true),
            "validate must find the persisted transaction, got: {}",
            mcp_result_text(&validate)
        );
    }

    #[tokio::test]
    async fn mcp_transaction_stage_unknown_id_still_fails() {
        // Persistence must not paper over a genuinely missing transaction.
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let stage = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({
                "transaction_id": "00000000-0000-0000-0000-000000000000",
                "operations": []
            }),
        )
        .await;
        assert_eq!(stage.is_error, Some(true));
        assert!(mcp_result_text(&stage).contains("not found"));
    }

    #[tokio::test]
    async fn mcp_transaction_commit_lands_in_canonical_graph() {
        // End-to-end: begin → stage → commit across separate calls must apply the
        // staged entity to the canonical state.graph (commit is a mutating tool, so
        // it routes there rather than a session's read-only scoped view).
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let before = state.graph.entity_count();

        let begin = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_begin",
            serde_json::json!({ "session_id": "sess-1", "scope": "file:src/lib.rs" }),
        )
        .await;
        let begin_json: serde_json::Value = serde_json::from_str(&mcp_result_text(&begin)).unwrap();
        let tx_id = begin_json["transaction_id"].as_str().unwrap().to_string();

        let _stage = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({
                "transaction_id": tx_id,
                "operations": [{
                    "verb": "create",
                    "target": "",
                    "payload": { "Entity": test_entity("committed_fn", "src/lib.rs") },
                    "description": ""
                }]
            }),
        )
        .await;

        let commit = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_commit",
            serde_json::json!({ "transaction_id": tx_id }),
        )
        .await;
        assert_ne!(
            commit.is_error,
            Some(true),
            "commit failed: {}",
            mcp_result_text(&commit)
        );

        assert_eq!(
            state.graph.entity_count(),
            before + 1,
            "committed entity must land in the canonical graph"
        );
    }

    #[test]
    fn persist_does_not_clobber_concurrently_begun_transaction() {
        // Models the interleave: request A restores the store ({tx1}), then while
        // A is mid-dispatch request B begins tx2 and persists ({tx1, tx2}). When A
        // finally persists, its registry only ever saw {tx1}. A clear-then-reinsert
        // persist would drop tx2; merge-upsert must keep it.
        let state = test_state();

        // tx1 already durable.
        let registry_b = kin_mcp::SessionRegistry::new();
        let tx1 = registry_b.begin_transaction("sess", "file:a.rs").unwrap();
        persist_mcp_transactions(&state, &registry_b);

        // Request B begins tx2 on top of the current store and persists.
        let registry_b2 = mcp_session_registry_snapshot(&state).unwrap();
        let tx2 = registry_b2.begin_transaction("sess", "file:b.rs").unwrap();
        persist_mcp_transactions(&state, &registry_b2);

        // Request A — its registry was snapshotted back when only tx1 existed.
        let registry_a = kin_mcp::SessionRegistry::new();
        registry_a.replace_transactions(vec![tx1.clone()]);
        persist_mcp_transactions(&state, &registry_a);

        let store = state.mcp_transactions.lock().unwrap();
        assert!(
            store.contains_key(&tx2.transaction_id),
            "concurrently-begun tx2 must survive A's persist"
        );
        assert!(store.contains_key(&tx1.transaction_id));
    }

    #[tokio::test]
    async fn mcp_transaction_commit_evicts_from_durable_store() {
        // A committed transaction is terminal and must not linger in the store.
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let begin = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_begin",
            serde_json::json!({ "session_id": "sess-1", "scope": "file:src/lib.rs" }),
        )
        .await;
        let begin_json: serde_json::Value = serde_json::from_str(&mcp_result_text(&begin)).unwrap();
        let tx_id = begin_json["transaction_id"].as_str().unwrap().to_string();
        assert!(state.mcp_transactions.lock().unwrap().contains_key(&tx_id));

        let commit = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_commit",
            serde_json::json!({ "transaction_id": tx_id }),
        )
        .await;
        assert_ne!(commit.is_error, Some(true), "{}", mcp_result_text(&commit));
        assert!(
            !state.mcp_transactions.lock().unwrap().contains_key(&tx_id),
            "committed transaction must be evicted from the durable store"
        );
    }

    #[test]
    fn mcp_transaction_survives_daemon_restart() {
        // Staged-but-uncommitted transactions must survive a daemon
        // restart, not just HTTP calls — otherwise a mid-transaction bounce
        // silently drops the agent's staged work. Persist on one DaemonState,
        // re-open on the SAME layout (a restart), and assert the staged op +
        // body are restored intact.
        install_test_registry_override();
        let dir = std::env::temp_dir().join(format!("kin-daemon-tx-restart-{}", Uuid::new_v4()));
        let kin_dir = dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("objects")).unwrap();
        std::fs::create_dir_all(kin_dir.join("working")).unwrap();
        kin_core::manifest::KinManifest::new()
            .save(&kin_core::KinLayout::new(kin_dir.clone()).manifest_path())
            .unwrap();

        let tx_id;
        {
            let state =
                Arc::new(DaemonState::open(kin_core::KinLayout::new(kin_dir.clone())).unwrap());
            let registry = kin_mcp::SessionRegistry::new();
            let tx = registry
                .begin_transaction("sess-restart", "file:src/lib.rs")
                .unwrap();
            tx_id = tx.transaction_id.clone();
            let op = kin_mcp::McpMutationOperation {
                verb: "update".into(),
                target: String::new(),
                payload: None,
                body: Some("pub fn greet() {}".into()),
                description: "restart-durability".into(),
            };
            registry.stage_transaction(&tx_id, vec![op]).unwrap();
            persist_mcp_transactions(&state, &registry);
        } // state dropped — models daemon shutdown.

        // Re-open on the SAME layout — models the restart.
        let restarted = Arc::new(DaemonState::open(kin_core::KinLayout::new(kin_dir)).unwrap());
        let store = restarted
            .mcp_transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let restored = store
            .get(&tx_id)
            .expect("staged transaction must survive a daemon restart");
        assert_eq!(
            restored.staged_operations.len(),
            1,
            "staged operation must survive the restart"
        );
        assert_eq!(
            restored.staged_operations[0].body.as_deref(),
            Some("pub fn greet() {}"),
            "the staged body must survive the restart intact"
        );
    }

    #[tokio::test]
    async fn search_endpoint_uses_live_graph() {
        let state = test_state();
        let source = "def handler():\n    return 1\n";
        install_branch_file(&state, "src/lib.py", source.as_bytes());
        std::fs::create_dir_all(state.layout.working_dir().join("src")).unwrap();
        std::fs::write(
            state.layout.working_dir().join("src/lib.py"),
            "def handler():\n    return 'checkout drift'\n",
        )
        .unwrap();
        let mut entity = test_entity("handler", "src/lib.py");
        entity.span.as_mut().unwrap().end_byte = source.len();
        entity.span.as_mut().unwrap().end_line = 2;
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/search")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "query": "handler",
                            "semantic": false,
                            "show_body": true,
                            "body_limit": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::search::DaemonSearchResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.records.len(), 1);
        match result.records.first().unwrap() {
            kin_cli::commands::search::DaemonSearchRecord::Entity(entity) => {
                assert_eq!(entity.name, "handler");
                assert_eq!(entity.file.as_deref(), Some("src/lib.py"));
                assert_eq!(entity.body.as_deref(), Some("def handler():"));
                assert_eq!(entity.body_omitted_line_count, 1);
            }
            other => panic!("expected entity record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn search_endpoint_filters_test_role() {
        let state = test_state();
        let source_entity = test_entity("handler", "src/lib.py");
        let mut test_entity = test_entity("handler_test", "tests/test_lib.py");
        test_entity.role = EntityRole::Test;
        state.graph.upsert_entity(&source_entity).unwrap();
        state.graph.upsert_entity(&test_entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/search")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "query": "handler",
                            "kind": "test",
                            "semantic": false,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::search::DaemonSearchResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.records.len(), 1);
        match result.records.first().unwrap() {
            kin_cli::commands::search::DaemonSearchRecord::Entity(entity) => {
                assert_eq!(entity.name, "handler_test");
                assert_eq!(entity.file.as_deref(), Some("tests/test_lib.py"));
            }
            other => panic!("expected entity record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn support_endpoint_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(Request::get("/support").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["total_entities"], 1);
        assert_eq!(result["entity_counts"]["Function"], 1);
    }

    #[tokio::test]
    async fn command_status_endpoint_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        let branch_name = BranchName::new("main");
        state
            .graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: kin_core::build_genesis_change().id,
            })
            .unwrap();
        kin_core::write_current_branch(&state.layout, &branch_name).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/commands/status")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "json": false }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        let result: kin_cli::commands::status::CommandStatusResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.summary.entities, 1);
        assert!(result.text.contains("Entities: 1"));
    }

    #[tokio::test]
    async fn graph_command_endpoints_use_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        let graph_response = app
            .clone()
            .oneshot(
                Request::post("/commands/graph")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "command": "status" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(graph_response.status(), StatusCode::OK);
        let graph_body = axum::body::to_bytes(graph_response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let graph_result: kin_cli::commands::graph::GraphCommandResponse =
            serde_json::from_slice(&graph_body).unwrap();
        assert!(graph_result
            .lines
            .iter()
            .any(|line| line.contains("Entities: 1")));

        let overview_response = app
            .clone()
            .oneshot(
                Request::post("/commands/overview")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "json": false, "compact": true }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overview_response.status(), StatusCode::OK);
        let overview_body = axum::body::to_bytes(overview_response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let overview_result: kin_cli::commands::overview::OverviewResponse =
            serde_json::from_slice(&overview_body).unwrap();
        assert!(overview_result
            .lines
            .iter()
            .any(|line| line.contains("Entities: 1")));

        let verify_response = app
            .oneshot(
                Request::post("/commands/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "command": "summary" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_response.status(), StatusCode::OK);
        let verify_body = axum::body::to_bytes(verify_response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let verify_result: kin_cli::commands::verify::VerifyCommandResponse =
            serde_json::from_slice(&verify_body).unwrap();
        assert!(verify_result
            .lines
            .iter()
            .any(|line| line.contains("Repository Coverage:")));
    }

    #[tokio::test]
    async fn session_workspace_endpoint_materializes_live_graph() {
        let state = test_state();
        install_branch_file(&state, "src/lib.py", b"graph truth\n");
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state.clone());
        let session_dir = state.layout.root().join("runs/session-api");

        let response = app
            .oneshot(
                Request::post("/commands/session-workspace")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "session_dir": session_dir.display().to_string(),
                            "strategy": null,
                            "scope": null
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::session_workspace::SessionWorkspaceResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.source_kind, "blob-tree");
        assert_eq!(
            std::fs::read_to_string(session_dir.join("src/lib.py")).unwrap(),
            "graph truth\n"
        );
    }

    /// Serializes tests that mutate process-global env (`KIN_DAEMON_ALLOW_EXEC`,
    /// `KIN_DAEMON_AUTH_TOKEN`, `KIN_DAEMON_REQUIRE_TOKEN`) so their
    /// opposite expectations never race under the parallel test runner.
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[tokio::test]
    async fn exec_endpoint_runs_against_live_graph_workspace() {
        let _env = env_test_lock();
        std::env::set_var("KIN_DAEMON_ALLOW_EXEC", "1");

        let state = test_state();
        install_branch_file(&state, "src/lib.py", b"daemon exec\n");
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/commands/exec")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "command": "cat src/lib.py",
                            "keep": false,
                            "strategy": null,
                            "scope": null
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
        let result: kin_cli::commands::exec::ExecResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(result.stdout, "daemon exec\n");
        assert_eq!(result.exit_code, 0);
        assert!(!std::path::Path::new(&result.workspace_path).exists());

        std::env::remove_var("KIN_DAEMON_ALLOW_EXEC");
    }

    #[tokio::test]
    async fn branch_endpoint_mutates_live_graph() {
        let state = test_state();
        let branch_name = BranchName::new("main");
        state
            .graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: kin_core::build_genesis_change().id,
            })
            .unwrap();
        kin_core::write_current_branch(&state.layout, &branch_name).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state.clone());

        let response = app
            .oneshot(
                Request::post("/commands/branch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "command": "create", "name": "feature" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state
            .graph
            .get_branch(&BranchName::new("feature"))
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn work_endpoint_mutates_live_graph() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state.clone());
        let response = app
            .oneshot(
                Request::post("/work")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "op": "create",
                            "kind": "task",
                            "title": "daemon-owned work",
                            "description": null,
                            "scope": "file:src/lib.rs",
                            "priority": "high"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::work::WorkResponse = serde_json::from_slice(&body).unwrap();
        assert!(result.text.contains("Created task 'daemon-owned work'"));
        let items = state
            .graph
            .list_work_items(&kin_model::WorkFilter::default())
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(state.is_dirty());
    }

    #[tokio::test]
    async fn note_endpoint_mutates_live_graph() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state.clone());
        let response = app
            .oneshot(
                Request::post("/note")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "op": "add",
                            "target": "file:src/lib.rs",
                            "kind": "instruction",
                            "body": "daemon note"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::note::NoteResponse = serde_json::from_slice(&body).unwrap();
        assert!(result.text.contains("Added instruction annotation"));
        let annotations = state
            .graph
            .list_annotations(&AnnotationFilter::default())
            .unwrap();
        assert_eq!(annotations.len(), 1);
        assert!(state.is_dirty());
    }

    #[tokio::test]
    async fn context_endpoint_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/context")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                            "budget": "8k",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::context::ContextResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(
            result
                .lines
                .iter()
                .any(|line| line.contains("Context pack for 'handler'")),
            "context response should identify the daemon graph entity"
        );
    }

    #[tokio::test]
    async fn trace_endpoint_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/trace")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                            "json": false,
                            "compact": false,
                            "budget": "8k",
                            "max_lines": 20,
                            "nearby_limit": 2,
                            "transitive_limit": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::trace::TraceResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(
            result
                .lines
                .iter()
                .any(|line| line.contains("Trace for 'handler' -> handler")),
            "trace response should identify the daemon graph entity"
        );
    }

    #[tokio::test]
    async fn trace_endpoint_resolves_file_paths_to_graph_entities() {
        let state = test_state();
        state
            .graph
            .upsert_entity(&test_entity("handler", "src/lib.py"))
            .unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/trace")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "src/lib.py",
                            "json": false,
                            "compact": false,
                            "budget": "8k",
                            "max_lines": 20,
                            "nearby_limit": 2,
                            "transitive_limit": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::trace::TraceResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(result
            .lines
            .iter()
            .any(|line| line == "--- entities declared in src/lib.py ---"));
        assert!(result.lines.iter().any(|line| line.contains("handler")));
    }

    #[tokio::test]
    async fn trace_endpoint_file_path_without_graph_entities_returns_guidance() {
        let state = test_state();
        std::fs::create_dir_all(state.layout.working_dir().join("src")).unwrap();
        std::fs::write(
            state.layout.working_dir().join("src/lib.py"),
            "def handler():\n    return 1\n",
        )
        .unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/trace")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "src/lib.py",
                            "json": false,
                            "compact": false,
                            "budget": "8k",
                            "max_lines": 20,
                            "nearby_limit": 2,
                            "transitive_limit": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::trace::TraceResponse =
            serde_json::from_slice(&body).unwrap();
        let joined = result.lines.join("\n");
        assert!(
            joined.contains("expects an entity name, not a file path"),
            "untracked file path must return guidance, not a raw disk dump: {joined}"
        );
        assert!(
            !joined.contains("def handler"),
            "file body must not be served from disk: {joined}"
        );
    }

    #[tokio::test]
    async fn impact_endpoint_uses_live_graph() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/impact")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                            "depth": 2,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::impact::ImpactResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(
            result
                .lines
                .iter()
                .any(|line| line.contains("Impact analysis for 'handler'")),
            "impact response should identify the daemon graph entity"
        );
    }

    #[tokio::test]
    async fn review_endpoint_creates_review_in_live_graph() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::post("/review")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "op": "create",
                            "title": "Daemon-owned review",
                            "base": "main",
                            "head": "HEAD",
                            "description": "created through daemon",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::review::ReviewResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(result.text.contains("Created review"));

        let reviews = state
            .graph
            .list_reviews(&kin_model::review::ReviewFilter {
                states: None,
                reviewer: None,
            })
            .unwrap();
        assert_eq!(reviews.len(), 1);
        assert!(state.is_dirty());
    }

    #[tokio::test]
    async fn review_endpoint_lists_live_review_state() {
        let state = test_state();
        let execution = kin_cli::commands::review::execute_review_request(
            &state.layout,
            state.graph.as_ref(),
            kin_cli::commands::review::ReviewRequest::Create {
                title: "Listed review".to_string(),
                base: "main".to_string(),
                head: "HEAD".to_string(),
                description: None,
            },
        )
        .await
        .unwrap();
        assert!(execution.mutated);
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/review")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "op": "list",
                            "state": null,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::review::ReviewResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(result.text.contains("Listed review"));
        assert!(result.text.contains("1 review(s)"));
    }

    #[tokio::test]
    async fn embed_endpoint_uses_daemon_graph() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/embed")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "batch_size": 4,
                            "json": true,
                            "max_seconds": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let result: kin_cli::commands::embed::EmbedResponse =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.result.total_entities, 0);
        assert!(result
            .lines
            .iter()
            .any(|line| line.contains("No retrievable graph objects found")));
    }

    #[test]
    fn foreground_embed_batch_flush_defers_sidecar_while_queue_pending() {
        let state = test_state();
        state
            .graph
            .upsert_entity(&test_entity("needs_embedding", "src/lib.py"))
            .unwrap();
        state.save_snapshot().unwrap();

        let vector_path = kin_cli::backend::vector_index_path(&state.layout);
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors.save(&vector_path).unwrap();
        state.graph.load_vector_index(&vector_path).unwrap();
        state.graph.queue_missing_for_embedding();
        assert!(state.graph.pending_embeddings() > 0);

        std::fs::remove_file(&vector_path).unwrap();
        persist_foreground_embed_batch(state.as_ref()).unwrap();
        assert!(
            !vector_path.exists(),
            "foreground per-batch flush must defer the sidecar while work is pending"
        );
    }

    #[tokio::test]
    async fn blame_and_history_endpoints_use_daemon_graph() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let entity = test_entity("handler", "src/lib.py");
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        state
            .graph
            .create_change(&SemanticChange {
                id: change_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add handler".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();
        state.graph.upsert_entity(&entity).unwrap();
        state
            .graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: change_id,
            })
            .unwrap();
        kin_core::write_current_branch(&state.layout, &BranchName::new("main")).unwrap();

        let app = router(state);
        let blame_response = app
            .clone()
            .oneshot(
                Request::post("/blame")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blame_response.status(), StatusCode::OK);
        let blame_body = axum::body::to_bytes(blame_response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let blame: kin_cli::commands::blame::BlameResponse =
            serde_json::from_slice(&blame_body).unwrap();
        assert!(blame.lines.iter().any(|line| line.contains("Blame for")));
        assert!(blame.lines.iter().any(|line| line.contains("add handler")));

        let history_response = app
            .oneshot(
                Request::post("/history")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(history_response.status(), StatusCode::OK);
        let history_body = axum::body::to_bytes(history_response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let history: kin_cli::commands::history::HistoryResponse =
            serde_json::from_slice(&history_body).unwrap();
        assert!(history
            .lines
            .iter()
            .any(|line| line.contains("History for")));
        assert!(history
            .lines
            .iter()
            .any(|line| line.contains("add handler")));
    }

    #[tokio::test]
    async fn verify_run_endpoint_persists_daemon_graph_state() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        let work = WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: WorkKind::Task,
            title: "Verify handler".to_string(),
            description: "Ensure handler proof is recorded".to_string(),
            status: WorkStatus::InProgress,
            priority: Priority::Medium,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["handler proof recorded".to_string()],
            external_refs: vec![],
            created_by: IdentityRef::human("daemon-test"),
            created_at: Timestamp::now(),
        };
        state.graph.create_work_item(&work).unwrap();
        let test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "handler_test".to_string(),
            language: "rust".to_string(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Custom("printf".to_string()),
            file_origin: Some(FilePathId::new("tests/handler.rs")),
        };
        state.graph.create_test_case(&test).unwrap();
        state
            .graph
            .create_test_verifies_work(&test.test_id, &work.work_id)
            .unwrap();

        let app = router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::post("/verify/run")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "entity": "handler",
                            "runner": "printf",
                            "depth": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let result: kin_cli::commands::verify::VerifyRunResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(result
            .lines
            .iter()
            .any(|line| line.contains("VerificationRun recorded")));
        let runs = state.graph.list_runs_for_test(&test.test_id).unwrap();
        assert_eq!(runs.len(), 1);
    }

    #[tokio::test]
    async fn mcp_bootstrap_route_is_not_available() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/mcp/bootstrap").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        // 2 sessions: the daemon-system session registered at startup + the one we created.
        assert_eq!(sessions_json.len(), 2);
        assert!(sessions_json.iter().any(|s| s.session_id == session_id));

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

    // -----------------------------------------------------------------------
    // Health and readiness
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn health_includes_version_string() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("X-Kin-Daemon-Sha").unwrap(),
            kin_buildinfo::get().sha
        );
        assert!(response.headers().get("X-Kin-Daemon-Built-At").is_some());
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(!json.version.is_empty());
        assert_eq!(json.reconciliation_status, "idle");
    }

    #[tokio::test]
    async fn readiness_returns_200_when_initialized() {
        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(Request::get("/readiness").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Status endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn status_returns_working_copy_state() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: StatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.entity_adds, 0);
        assert_eq!(json.entity_mods, 0);
        assert_eq!(json.entity_removes, 0);
    }

    // -----------------------------------------------------------------------
    // Session endpoints
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_session_by_id() {
        let state = test_state();
        let session_id = state
            .coordinator
            .register_session(
                "test-vendor",
                "test-client",
                SessionTransport::Mcp,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::get(format!("/session/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let session: AgentSession = serde_json::from_slice(&body).unwrap();
        assert_eq!(session.vendor, "test-vendor");
    }

    #[tokio::test]
    async fn get_nonexistent_session_returns_404() {
        let state = test_state();
        let fake_id = kin_model::SessionId::new();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get(format!("/session/{fake_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_sessions_empty() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let sessions: Vec<AgentSession> = serde_json::from_slice(&body).unwrap();
        // DaemonState::open() now registers a daemon-system session for the
        // reconcile loop, so the list contains exactly that one session.
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].vendor, "kin-daemon");
    }

    #[tokio::test]
    async fn create_heartbeat_and_end_session() {
        let state = test_state();
        let app = router(state);

        let start_response = app
            .clone()
            .oneshot(
                Request::post("/session")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "vendor": "claude-code",
                            "client_name": "daemon-test",
                            "transport": "mcp",
                            "cwd": "/project",
                            "capabilities": {
                                "can_read": true,
                                "can_write": false,
                                "can_execute": false,
                                "can_branch": false,
                                "can_commit": false,
                                "max_concurrent_intents": 1
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_response.status(), StatusCode::OK);
        let start_body = axum::body::to_bytes(start_response.into_body(), 4096)
            .await
            .unwrap();
        let start_json: SessionStartResponse = serde_json::from_slice(&start_body).unwrap();
        assert_eq!(start_json.vendor, "claude-code");
        assert_eq!(start_json.status, "active");
        assert_eq!(start_json.client_name, "daemon-test");

        let heartbeat_response = app
            .clone()
            .oneshot(
                Request::post(format!("/session/{}/heartbeat", start_json.session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(heartbeat_response.status(), StatusCode::OK);
        let heartbeat_body = axum::body::to_bytes(heartbeat_response.into_body(), 4096)
            .await
            .unwrap();
        let heartbeat_json: SessionHeartbeatResponse =
            serde_json::from_slice(&heartbeat_body).unwrap();
        assert_eq!(heartbeat_json.status, "active");

        let end_response = app
            .clone()
            .oneshot(
                Request::delete(format!("/session/{}", start_json.session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(end_response.status(), StatusCode::OK);
        let end_body = axum::body::to_bytes(end_response.into_body(), 4096)
            .await
            .unwrap();
        let end_json: SessionEndResponse = serde_json::from_slice(&end_body).unwrap();
        assert_eq!(end_json.status, "ended");
    }

    // -----------------------------------------------------------------------
    // Intent endpoints
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_intent_creates_session_when_none_provided() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/main.rs",
                            "lock_type": "soft",
                            "task_description": "editing main"
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
        let json: RegisterIntentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "registered");
        assert!(!json.session_id.is_empty());
        assert!(!json.intent_id.is_empty());
    }

    #[tokio::test]
    async fn register_intent_with_existing_session() {
        let state = test_state();
        let session_id = state
            .coordinator
            .register_session(
                "test",
                "ci",
                SessionTransport::Cli,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scopes": ["file:src/lib.rs"],
                            "lock_type": "hard",
                            "task_description": "editing lib",
                            "session_id": session_id.to_string()
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
        let json: RegisterIntentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.session_id, session_id.to_string());
    }

    #[tokio::test]
    async fn register_intent_with_single_scope_still_works() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/main.rs",
                            "lock_type": "soft",
                            "task_description": "editing main"
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
        let json: RegisterIntentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "registered");
        assert!(!json.session_id.is_empty());
    }

    #[tokio::test]
    async fn release_intent_via_api() {
        let state = test_state();
        let session_id = state
            .coordinator
            .register_session(
                "test",
                "ci",
                SessionTransport::Mcp,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap();
        let entity_id = EntityId::new();
        let result = state
            .coordinator
            .register_intent(
                &session_id,
                vec![IntentScope::Entity(entity_id)],
                LockType::Soft,
                "task",
                None,
            )
            .unwrap();
        let intent_id = match result {
            crate::session_registry::IntentRegistrationResult::Registered { intent_id, .. } => {
                intent_id
            }
            _ => panic!("expected Registered"),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::delete(format!("/intent/{intent_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn release_nonexistent_intent_returns_404() {
        let state = test_state();
        let fake_id = kin_model::IntentId::new();
        let app = router(state);
        let response = app
            .oneshot(
                Request::delete(format!("/intent/{fake_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // Traffic endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn traffic_empty_scope() {
        let state = test_state();
        let entity_id = EntityId::new();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get(format!("/traffic/entity%3A{entity_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: TrafficResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.hard_blocks, 0);
        assert_eq!(json.soft_locks, 0);
        assert!(json.active_intents.is_empty());
    }

    // -----------------------------------------------------------------------
    // VFS endpoints
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn vfs_version_returns_zero_initially() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/vfs/version").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["version"], 0);
    }

    #[tokio::test]
    async fn vfs_tree_empty_graph() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/vfs/tree").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["files"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn vfs_stat_missing_path_returns_404() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/vfs/stat/nonexistent/path.rs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn vfs_read_missing_file_returns_404() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/vfs/read/nonexistent.rs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn vfs_read_rejects_projection_failures_instead_of_serving_raw_blob() {
        let entity_id = EntityId::new();
        let file_id = FilePathId::new("src/lib.rs");
        let layout = FileLayout {
            file_id: file_id.clone(),
            parse_completeness: Default::default(),
            imports: ImportSection {
                byte_range: 0..0,
                items: Vec::new(),
            },
            regions: vec![SourceRegion::EntityRef {
                entity_id,
                byte_range: 32..40,
            }],
        };
        let mut merged_bodies = HashMap::new();
        merged_bodies.insert(entity_id, b"new_body".to_vec());

        let err = project_vfs_overlay_bytes(&file_id, b"short", Some(&layout), &merged_bodies)
            .expect_err("invalid layouts must not fall back to raw blob bytes");

        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.1.contains("projection failed for src/lib.rs"));
    }

    // -----------------------------------------------------------------------
    // Spine endpoints
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spine_health_returns_ok() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/spine/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Spine should be initialized on DaemonState::open
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn spine_repos_returns_list() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/spine/repos").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["repos"].is_array());
    }

    #[tokio::test]
    async fn spine_resolve_unknown_entity() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/spine/resolve?name=NonexistentEntity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["results"].as_array().unwrap().is_empty());
    }

    fn spine_test_fingerprint() -> kin_model::SemanticFingerprint {
        let zero = kin_model::Hash256::from_bytes([0u8; 32]);
        kin_model::SemanticFingerprint {
            algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
            ast_hash: zero,
            signature_hash: zero,
            behavior_hash: zero,
            stability_score: 1.0,
        }
    }

    fn parse_consumer_source(file_path: &str, source: &str) -> kin_index::FileParseData {
        let registry = kin_parser::AdapterRegistry::new();
        let ext = std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .expect("file extension");
        let adapter = registry
            .get_by_extension(ext)
            .expect("language adapter for extension");
        let language = adapter.language_id();
        let file_id = FilePathId::new(file_path);
        let bytes = source.as_bytes();
        let tree = adapter.parse(bytes).expect("parse");
        let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
        let entities = output
            .entities
            .into_iter()
            .map(|e| e.into_entity_with_source(language, &file_id, Some(bytes)))
            .collect();
        kin_index::FileParseData {
            file_path: file_path.to_string(),
            entities,
            relations: output.relations,
            imports: output.imports,
        }
    }

    /// The daemon's /spine/xref and /spine/impact serve real cross-repo edges
    /// materialized from a parsed + linked fixture through the production refresh
    /// path, and fail loud rather than return an empty impact.
    #[tokio::test]
    async fn spine_impact_and_xref_serve_real_cross_repo_fixture() {
        let do_work_id = EntityId::new();
        let provider_entry = kin_spine::EntityEntry {
            repo_id: "provider".to_string(),
            entity_id: do_work_id,
            name: "do_work".to_string(),
            kind: kin_model::EntityKind::Function,
            signature: "fn do_work()".to_string(),
            fingerprint: spine_test_fingerprint(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(kin_model::EntityRole::Source),
        };

        let consumer = parse_consumer_source(
            "src/app.rs",
            "use provider::do_work;\n\npub fn run_task() {\n    do_work();\n}\n",
        );
        let consumer_entities = consumer.entities.clone();
        let consumer_relations = kin_index::link_cross_file(&[consumer]);
        let run_task_id = consumer_entities
            .iter()
            .find(|e| e.name == "run_task")
            .expect("run_task entity present")
            .id;

        let state = test_state();
        let spine = state.ensure_spine().expect("spine enabled in test");
        spine.register_repo("provider", vec![provider_entry], "");
        spine.refresh_cross_repo_edges(
            "consumer",
            &consumer_entities,
            &consumer_relations,
            &["provider".to_string()],
        );
        assert!(
            spine.edge_count() >= 1,
            "fixture must materialize a cross-repo edge (parse -> link -> spine)"
        );

        let app = router(state);

        let xref = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/spine/xref?repo=consumer&entity={}",
                    run_task_id.0
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(xref.status(), StatusCode::OK);
        let xbody: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(xref.into_body(), 65536).await.unwrap())
                .unwrap();
        let edges = xbody["edges"]
            .as_array()
            .expect("edges array in /spine/xref");
        assert!(
            !edges.is_empty(),
            "/spine/xref must return the cross-repo edge, not an empty list"
        );
        assert!(
            edges.iter().any(|e| e["dst_repo"] == "provider"),
            "the cross-repo edge must resolve to the provider repo, got {edges:?}"
        );
        assert_eq!(
            xbody["version"],
            serde_json::json!(kin_spine::SPINE_PAYLOAD_VERSION),
            "/spine/xref payload must carry the spine wire-format version"
        );

        let impact = app
            .oneshot(
                Request::get(format!(
                    "/spine/impact?repo=provider&entity={}&depth=5",
                    do_work_id.0
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(impact.status(), StatusCode::OK);
        let ibody: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(impact.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        let repos: Vec<&str> = ibody["repos_involved"]
            .as_array()
            .expect("repos_involved array in /spine/impact")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            repos.contains(&"consumer"),
            "federated impact of do_work must include the consumer repo (blast radius), got {repos:?}"
        );
        assert_eq!(
            ibody["version"],
            serde_json::json!(kin_spine::SPINE_PAYLOAD_VERSION),
            "/spine/impact payload must carry the spine wire-format version"
        );
    }

    /// The daemon's /spine endpoints serve a TRANSITIVE (2-hop) blast radius and
    /// MULTI-CONSUMER edges through the production refresh path: provider <-
    /// consumer <- downstream, plus a second consumer of provider. This is the
    /// FIR-1149 transitive/multi-consumer gate on top of the 1-hop fixture; it
    /// depends on refresh registering each repo's own entities so the next hop
    /// can resolve them.
    #[tokio::test]
    async fn spine_serves_transitive_2hop_and_multi_consumer_blast_radius() {
        let do_work_id = EntityId::new();
        let provider_entry = kin_spine::EntityEntry {
            repo_id: "provider".to_string(),
            entity_id: do_work_id,
            name: "do_work".to_string(),
            kind: kin_model::EntityKind::Function,
            signature: "fn do_work()".to_string(),
            fingerprint: spine_test_fingerprint(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(kin_model::EntityRole::Source),
        };

        // consumer: imports provider::do_work via run_task (the 1st hop).
        let consumer = parse_consumer_source(
            "src/app.rs",
            "use provider::do_work;\n\npub fn run_task() {\n    do_work();\n}\n",
        );
        let consumer_entities = consumer.entities.clone();
        let consumer_relations = kin_index::link_cross_file(&[consumer]);
        let run_task_id = consumer_entities
            .iter()
            .find(|e| e.name == "run_task")
            .expect("run_task entity present")
            .id;

        // consumer2: a SECOND consumer of provider::do_work (multi-consumer).
        let consumer2 = parse_consumer_source(
            "src/other.rs",
            "use provider::do_work;\n\npub fn other_task() {\n    do_work();\n}\n",
        );
        let consumer2_entities = consumer2.entities.clone();
        let consumer2_relations = kin_index::link_cross_file(&[consumer2]);

        // downstream: imports consumer::run_task (the 2nd hop).
        let downstream = parse_consumer_source(
            "src/top.rs",
            "use consumer::run_task;\n\npub fn orchestrate() {\n    run_task();\n}\n",
        );
        let downstream_entities = downstream.entities.clone();
        let downstream_relations = kin_index::link_cross_file(&[downstream]);
        let orchestrate_id = downstream_entities
            .iter()
            .find(|e| e.name == "orchestrate")
            .expect("orchestrate entity present")
            .id;

        let state = test_state();
        let spine = state.ensure_spine().expect("spine enabled in test");
        let registry = [
            "provider".to_string(),
            "consumer".to_string(),
            "consumer2".to_string(),
            "downstream".to_string(),
        ];
        spine.register_repo("provider", vec![provider_entry], "");
        // Each refresh registers the repo's own entities as resolution targets so
        // the next hop can bind to them — the behavior this gate proves. Refresh
        // in dependency order so each hop's targets are present.
        spine.refresh_cross_repo_edges(
            "consumer",
            &consumer_entities,
            &consumer_relations,
            &registry,
        );
        spine.refresh_cross_repo_edges(
            "consumer2",
            &consumer2_entities,
            &consumer2_relations,
            &registry,
        );
        spine.refresh_cross_repo_edges(
            "downstream",
            &downstream_entities,
            &downstream_relations,
            &registry,
        );

        let app = router(state);

        // 2-hop: /spine/xref for downstream's orchestrate resolves into consumer.
        let xref = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/spine/xref?repo=downstream&entity={}",
                    orchestrate_id.0
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(xref.status(), StatusCode::OK);
        let xbody: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(xref.into_body(), 65536).await.unwrap())
                .unwrap();
        let edges = xbody["edges"]
            .as_array()
            .expect("edges array in /spine/xref");
        assert!(
            edges.iter().any(|e| e["dst_repo"] == "consumer"),
            "2-hop: downstream must resolve a cross-repo edge into consumer, got {edges:?}"
        );

        // Multi-consumer + transitive: federated impact of provider::do_work
        // includes BOTH consumers AND the transitive downstream repo.
        let impact = app
            .oneshot(
                Request::get(format!(
                    "/spine/impact?repo=provider&entity={}&depth=5",
                    do_work_id.0
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(impact.status(), StatusCode::OK);
        let ibody: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(impact.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        let repos: Vec<&str> = ibody["repos_involved"]
            .as_array()
            .expect("repos_involved array in /spine/impact")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            repos.contains(&"consumer") && repos.contains(&"consumer2"),
            "multi-consumer: both consumers must appear in provider's blast radius, got {repos:?}"
        );
        assert!(
            repos.contains(&"downstream"),
            "transitive: the 2-hop downstream repo must appear in provider's blast radius, got {repos:?}"
        );
        // Bind the 1st-hop id so the helper is exercised end-to-end (and the
        // unused-variable lint stays quiet) — run_task anchors the chain.
        let _ = run_task_id;
    }

    #[tokio::test]
    async fn spine_ingest_route_rejects_body_repo_mismatch() {
        // The path `repo_id` is authoritative. A body `repo` that disagrees is
        // an orchestrator wiring bug and must be refused before any ingest, so
        // a mis-wired client can never load the wrong repo into the spine.
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/spine/repos/kin/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "repo": "kin-db",
                            "refreshCrossRepoEdges": true,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a body repo that disagrees with the path repo_id must be rejected"
        );
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("does not match"),
            "rejection must explain the path/body mismatch, got: {body}"
        );
    }

    #[tokio::test]
    async fn spine_ingest_route_requires_a_storage_backend() {
        // Without a configured StorageBackend (the local single-repo daemon),
        // the multi-repo ingest path has nowhere to load a repo's graph from and
        // must fail loud rather than silently serve an empty cross-repo graph.
        // The hosted pod always runs with a backend; this guards the misconfig.
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/spine/repos/kin/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "repo": "kin" })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "ingest without a storage backend must surface an error, not a 200"
        );
    }

    #[tokio::test]
    async fn spine_refresh_cross_repo_edges_route_is_wired_and_degrades_gracefully() {
        // The hosted orchestrator calls this final pass after every repo is
        // ingested so edges emanate from every repo, not just the anchor. Without
        // a storage backend (the local single-repo daemon) no repo graph can be
        // loaded, so the pass refreshes nothing — but it must still answer 200
        // with the camelCase contract the orchestrator reads, never a 500/panic.
        let state = test_state();
        let spine = state.ensure_spine().expect("spine enabled in test");
        // Register two repos' metadata so the pass has a non-empty repo set to
        // iterate over (their graphs are unavailable without a backend).
        spine.register_repo("kin", vec![], "");
        spine.register_repo("kin-db", vec![], "");
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/spine/refresh-cross-repo-edges")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            body.get("reposRefreshed").is_some(),
            "response must carry reposRefreshed, got {body}"
        );
        assert!(
            body.get("crossRepoEdges").is_some(),
            "response must carry crossRepoEdges, got {body}"
        );
        // No backend → no repo graph loadable → nothing refreshed, but a clean
        // 200 rather than a hard failure.
        assert_eq!(body["reposRefreshed"], serde_json::json!(0));
    }

    /// One gate proving the cross-repo blast radius is consistent across every
    /// kin-side surface that consumes the spine — the daemon HTTP API, the
    /// `kin xref`/`kin impact` CLI client code, and the MCP impact_analysis
    /// client code — over a single real parsed+linked fixture served by a real
    /// daemon socket.
    ///
    /// Each surface runs its OWN production client (not a re-implementation):
    /// the daemon HTTP contract via reqwest (the same one KinLab's fetch path
    /// uses), `kin_cli::backend::get_spine_{xref,impact}` (what `kin xref` /
    /// `kin impact` call), and `kin_mcp::handlers::common::fetch_spine_{xref,
    /// impact_typed}` (what MCP impact_analysis calls). All three resolve the
    /// daemon through `KIN_DAEMON_URL`, so they hit this in-process daemon.
    ///
    /// The hosted KinLab surface and cloud/Firestore restart-hydration are out
    /// of scope for this in-process daemon test.
    #[tokio::test]
    #[serial_test::serial]
    async fn spine_blast_radius_is_consistent_across_daemon_cli_and_mcp() {
        use kin_cli::backend::{get_spine_impact, get_spine_xref};
        use kin_mcp::handlers::common::{fetch_spine_impact_typed, fetch_spine_xref};

        // Fixture: provider exports do_work; consumer imports and calls it.
        let do_work_id = EntityId::new();
        let provider_entry = kin_spine::EntityEntry {
            repo_id: "provider".to_string(),
            entity_id: do_work_id,
            name: "do_work".to_string(),
            kind: kin_model::EntityKind::Function,
            signature: "fn do_work()".to_string(),
            fingerprint: spine_test_fingerprint(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(kin_model::EntityRole::Source),
        };
        let consumer = parse_consumer_source(
            "src/app.rs",
            "use provider::do_work;\n\npub fn run_task() {\n    do_work();\n}\n",
        );
        let consumer_entities = consumer.entities.clone();
        let consumer_relations = kin_index::link_cross_file(&[consumer]);
        let run_task_id = consumer_entities
            .iter()
            .find(|e| e.name == "run_task")
            .expect("run_task entity present")
            .id;

        let state = test_state();
        let layout = state.layout.clone();
        {
            let spine = state.ensure_spine().expect("spine enabled in test");
            spine.register_repo("provider", vec![provider_entry], "");
            spine.refresh_cross_repo_edges(
                "consumer",
                &consumer_entities,
                &consumer_relations,
                &["provider".to_string()],
            );
            assert!(
                spine.edge_count() >= 1,
                "fixture must materialize a cross-repo edge (parse -> link -> spine)"
            );
        }

        // Serve the real daemon router on an ephemeral loopback socket.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router(state)).await;
        });
        let base = format!("http://{addr}");
        std::env::set_var("KIN_DAEMON_URL", &base);

        let run_task_str = run_task_id.to_string();
        let do_work_str = do_work_id.to_string();

        // ── Surface 1: daemon HTTP (also the KinLab fetch contract). ──
        let http = reqwest::Client::new();
        let http_xref: serde_json::Value = http
            .get(format!("{base}/v1/spine/xref"))
            .query(&[("repo", "consumer"), ("entity", run_task_str.as_str())])
            .send()
            .await
            .expect("daemon xref request")
            .json()
            .await
            .expect("daemon xref json");
        let daemon_xref_to_provider = http_xref["edges"]
            .as_array()
            .map(|edges| edges.iter().any(|e| e["dst_repo"] == "provider"))
            .unwrap_or(false);
        assert!(
            daemon_xref_to_provider,
            "daemon /v1/spine/xref must resolve the consumer->provider edge: {http_xref}"
        );

        let http_impact: serde_json::Value = http
            .get(format!("{base}/v1/spine/impact"))
            .query(&[
                ("repo", "provider"),
                ("entity", do_work_str.as_str()),
                ("depth", "5"),
            ])
            .send()
            .await
            .expect("daemon impact request")
            .json()
            .await
            .expect("daemon impact json");
        let daemon_impact_hits_consumer = http_impact["repos_involved"]
            .as_array()
            .map(|repos| repos.iter().any(|r| r == "consumer"))
            .unwrap_or(false);
        assert!(
            daemon_impact_hits_consumer,
            "daemon /v1/spine/impact blast radius must include consumer: {http_impact}"
        );

        // ── Surface 2: the `kin xref` / `kin impact` CLI client code. ──
        let cli_xref = match get_spine_xref(&layout, "consumer", &run_task_id)
            .await
            .expect("CLI get_spine_xref call")
        {
            kin_spine::SpineQuery::Found(edges) => edges,
            other => panic!("CLI get_spine_xref expected Found, got {other:?}"),
        };
        let cli_xref_to_provider = cli_xref.iter().any(|e| e.dst_repo == "provider");
        assert!(
            cli_xref_to_provider,
            "kin xref CLI must resolve consumer->provider: {cli_xref:?}"
        );

        let cli_impact = match get_spine_impact(&layout, "provider", &do_work_id, 5)
            .await
            .expect("CLI get_spine_impact call")
        {
            kin_spine::SpineQuery::Found(impact) => impact,
            other => panic!("CLI get_spine_impact expected Found, got {other:?}"),
        };
        let cli_impact_hits_consumer = cli_impact.repos_involved.iter().any(|r| r == "consumer");
        assert!(
            cli_impact_hits_consumer,
            "kin impact CLI blast radius must include consumer: {:?}",
            cli_impact.repos_involved
        );

        // ── Surface 3: the MCP impact_analysis client code. ──
        let mcp_xref = match fetch_spine_xref("consumer", &run_task_id).await {
            kin_spine::SpineQuery::Found(body) => body,
            other => panic!("MCP fetch_spine_xref expected Found, got {other:?}"),
        };
        let mcp_xref_to_provider = mcp_xref["edges"]
            .as_array()
            .map(|edges| edges.iter().any(|e| e["dst_repo"] == "provider"))
            .unwrap_or(false);
        assert!(
            mcp_xref_to_provider,
            "MCP fetch_spine_xref must resolve consumer->provider: {mcp_xref}"
        );

        let mcp_impact = match fetch_spine_impact_typed("provider", &do_work_id, 5).await {
            kin_spine::SpineQuery::Found(impact) => impact,
            other => panic!("MCP fetch_spine_impact_typed expected Found, got {other:?}"),
        };
        let mcp_impact_hits_consumer = mcp_impact.repos_involved.iter().any(|r| r == "consumer");
        assert!(
            mcp_impact_hits_consumer,
            "MCP impact blast radius must include consumer: {:?}",
            mcp_impact.repos_involved
        );

        // ── Consistency: all three surfaces agree on the cross-repo result. ──
        assert_eq!(
            cli_impact.repos_involved.iter().any(|r| r == "consumer"),
            mcp_impact.repos_involved.iter().any(|r| r == "consumer"),
            "CLI and MCP must agree on the impacted repo set"
        );
        assert!(
            daemon_xref_to_provider && cli_xref_to_provider && mcp_xref_to_provider,
            "daemon, CLI, and MCP must all resolve the same consumer->provider xref"
        );

        std::env::remove_var("KIN_DAEMON_URL");
        server.abort();
    }

    /// Fail-loud contract: when a spine endpoint IS configured but the daemon
    /// answers non-2xx (e.g. `503` because the spine is disabled), every client
    /// surface must report the gap as `SpineQuery::Unavailable` — never collapse
    /// it into a silent empty result (the old `Ok(None)` swallow) nor a quiet
    /// `NotConfigured`. This is the cross-repo analogue of the graph-first
    /// "fail loud or report the gap" rule, enforced across CLI and MCP.
    #[tokio::test]
    #[serial_test::serial]
    async fn spine_clients_surface_unavailable_on_non_success_status() {
        use kin_cli::backend::{get_spine_impact, get_spine_xref};
        use kin_mcp::handlers::common::{fetch_spine_impact_typed, fetch_spine_xref};

        // A stand-in daemon that answers every route 503. No real graph and no
        // autostart — the clients reach it purely through KIN_DAEMON_URL.
        async fn always_unavailable() -> StatusCode {
            StatusCode::SERVICE_UNAVAILABLE
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, Router::new().fallback(always_unavailable)).await;
        });
        std::env::set_var("KIN_DAEMON_URL", format!("http://{addr}"));

        let layout = test_state().layout.clone();
        let repo = "consumer";
        let entity = EntityId::new();

        // ── CLI xref: configured-but-failing must be Unavailable, naming 503. ──
        match get_spine_xref(&layout, repo, &entity)
            .await
            .expect("CLI get_spine_xref call")
        {
            kin_spine::SpineQuery::Unavailable(reason) => {
                assert!(
                    reason.contains("503"),
                    "reason must name the status: {reason}"
                );
            }
            other => panic!("CLI xref must be Unavailable on 503, got {other:?}"),
        }

        // ── CLI impact: the surface migrated off the Ok(None) swallow. ──
        match get_spine_impact(&layout, repo, &entity, 5)
            .await
            .expect("CLI get_spine_impact call")
        {
            kin_spine::SpineQuery::Unavailable(reason) => {
                assert!(
                    reason.contains("503"),
                    "reason must name the status: {reason}"
                );
            }
            other => panic!("CLI impact must be Unavailable on 503, got {other:?}"),
        }

        // ── MCP xref + impact: same fail-loud contract. ──
        match fetch_spine_xref(repo, &entity).await {
            kin_spine::SpineQuery::Unavailable(_) => {}
            other => panic!("MCP xref must be Unavailable on 503, got {other:?}"),
        }
        match fetch_spine_impact_typed(repo, &entity, 5).await {
            kin_spine::SpineQuery::Unavailable(_) => {}
            other => panic!("MCP impact must be Unavailable on 503, got {other:?}"),
        }

        std::env::remove_var("KIN_DAEMON_URL");
        server.abort();
    }

    // -----------------------------------------------------------------------
    // Scope parsing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_intent_entity_scope() {
        let state = test_state();
        let entity_id = EntityId::new();
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": format!("entity:{entity_id}"),
                            "lock_type": "soft",
                            "task_description": "scope test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn register_intent_invalid_lock_type_returns_400() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/main.rs",
                            "lock_type": "invalid",
                            "task_description": "test"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_intent_with_nonexistent_session_returns_404() {
        let state = test_state();
        let fake_session = kin_model::SessionId::new();
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/lib.rs",
                            "lock_type": "soft",
                            "task_description": "test",
                            "session_id": fake_session.to_string()
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // API versioning (P2-2.2)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn v1_prefix_routes_to_same_handler() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "ok");
    }

    #[tokio::test]
    async fn responses_include_api_version_header() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers().get("X-Kin-API-Version").unwrap(), "1");
    }

    #[tokio::test]
    async fn v1_prefix_also_includes_api_version_header() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("X-Kin-API-Version").unwrap(), "1");
    }

    #[tokio::test]
    async fn bind_host_defaults_to_loopback() {
        assert_eq!(resolve_bind_host(None), "127.0.0.1");
        assert_eq!(resolve_bind_host(Some(String::new())), "127.0.0.1");
        assert_eq!(
            resolve_bind_host(Some(" 127.0.0.1 ".to_string())),
            "127.0.0.1"
        );
    }

    #[tokio::test]
    async fn non_loopback_binding_requires_auth_token() {
        let err = bind_listener("0.0.0.0", 0, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err
            .to_string()
            .contains("KIN_DAEMON_AUTH_TOKEN is required"));
    }

    #[tokio::test]
    async fn auth_token_protects_daemon_routes() {
        let state = test_state();
        let app = router_with_auth(state, Some("secret-token".to_string()));

        let rejected = app
            .clone()
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer realm=\"kin daemon\""
        );

        let accepted = app
            .oneshot(
                Request::get("/status")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn public_routes_remain_unauthenticated() {
        let state = test_state();
        let app = router_with_auth(state, Some("secret-token".to_string()));

        // These routes must be reachable without a Bearer token.
        // Some (like /ready) may return non-200 for uninitialized daemons,
        // but they must never return 401/403 — that would mean auth blocked them.
        for path in [
            "/health",
            "/ready",
            "/readiness",
            "/spine/health",
            "/v1/health",
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            assert!(
                status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                "path {path} returned {status} — public route should not require auth"
            );
        }
    }

    // The package registries are public services with their own
    // per-write gates; `daemon_auth` must be scoped to the daemon API and must
    // NOT wrap the registry routers, so a 0.0.0.0-bound (therefore daemon-token-
    // protected) daemon can still serve a public registry. `KIN_REGISTRY_*` env
    // is process-global and read by `router_with_auth` at construction, so the
    // env-touching publish test serializes on this `tokio::sync::Mutex` (held
    // across `.await`, so a std guard would trip `clippy::await_holding_lock`)
    // and restores the var via `RegistryEnvGuard`.
    static REGISTRY_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct RegistryEnvGuard(&'static str);
    impl Drop for RegistryEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    /// Build a minimal valid `.crate` blob (gzip-tar containing
    /// `{name}-{version}/Cargo.toml`) so the cargo publish path passes coordinate
    /// verification. Mirrors `kin_registry::cargo` test helpers, inlined here
    /// because those are private to that crate's test module.
    fn build_valid_crate(name: &str, version: &str) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        let cargo_toml =
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(cargo_toml.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{name}-{version}/Cargo.toml"),
                cargo_toml.as_bytes(),
            )
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[tokio::test]
    async fn registry_routes_public_even_with_daemon_auth_token() {
        // With a daemon auth token configured, the cargo registry's read routes
        // (config.json + a sparse-index lookup) must still answer WITHOUT any
        // Authorization header — `daemon_auth` is scoped to the daemon API only.
        let state = test_state();
        let app = router_with_auth(state, Some("secret-token".to_string()));

        for path in ["/registry/cargo/config.json", "/registry/cargo/se/rd/serde"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            // config.json -> 200; an unknown crate index -> 404. Neither may be
            // 401/403, which would mean daemon_auth wrongly gated the registry.
            assert!(
                status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                "registry path {path} returned {status} — registry must be public"
            );
        }

        // config.json specifically must be a clean 200 (it has no preconditions).
        let config = app
            .oneshot(
                Request::get("/registry/cargo/config.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(config.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn daemon_api_protected_while_registry_public_in_same_app() {
        // The security-critical invariant: in ONE token-configured
        // app, the daemon API stays protected (401 without bearer, 200 with it)
        // while the registry stays open (200 with no auth). Proves the layer
        // split gates exactly the daemon routes and nothing else.
        let state = test_state();
        let app = router_with_auth(state, Some("secret-token".to_string()));

        // Daemon API route: rejected without a bearer token.
        let rejected = app
            .clone()
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        // Daemon API route: accepted with the bearer token.
        let accepted = app
            .clone()
            .oneshot(
                Request::get("/status")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        // Registry route in the SAME app: open with no Authorization header.
        let registry = app
            .oneshot(
                Request::get("/registry/cargo/config.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registry.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cargo_publish_requires_registry_cargo_token_through_daemon_router() {
        // Cargo publish remains gated by KIN_REGISTRY_CARGO_TOKEN even with the
        // daemon API behind its own token: the registry's own publish gate is
        // preserved end-to-end through the full daemon router.
        let _lock = REGISTRY_ENV_LOCK.lock().await;

        let crate_body = build_valid_crate("demo", "0.1.0");
        let publish_uri = "/registry/cargo/api/v1/crates/publish?name=demo&version=0.1.0";

        // (1) No KIN_REGISTRY_CARGO_TOKEN configured -> publish fails closed
        // (503) even with a daemon token set and a Bearer header present.
        std::env::remove_var("KIN_REGISTRY_CARGO_TOKEN");
        let app = router_with_auth(test_state(), Some("daemon-token".to_string()));
        let disabled = app
            .oneshot(
                Request::post(publish_uri)
                    .header("authorization", "Bearer anything")
                    .body(Body::from(crate_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::SERVICE_UNAVAILABLE);

        // (2) KIN_REGISTRY_CARGO_TOKEN configured: publish without the matching
        // bearer -> 401 (the daemon token does NOT satisfy the registry gate).
        let _env = RegistryEnvGuard("KIN_REGISTRY_CARGO_TOKEN");
        std::env::set_var("KIN_REGISTRY_CARGO_TOKEN", "cargo-secret");
        let app = router_with_auth(test_state(), Some("daemon-token".to_string()));
        let unauthorized = app
            .oneshot(
                Request::post(publish_uri)
                    .body(Body::from(crate_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        // (3) Same config: publish WITH the matching cargo bearer -> 200.
        let app = router_with_auth(test_state(), Some("daemon-token".to_string()));
        let ok = app
            .oneshot(
                Request::post(publish_uri)
                    .header("authorization", "Bearer cargo-secret")
                    .body(Body::from(crate_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    fn test_packages_dir(state: &Arc<DaemonState>) -> std::path::PathBuf {
        let packages_dir = state.layout.root().join("packages");
        std::fs::create_dir_all(&packages_dir).unwrap();
        packages_dir
    }

    async fn spawn_registry_auth_server(
        status: StatusCode,
        body: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/v1/registry/npm/access",
            axum_get(move || {
                let body = body.clone();
                async move { (status, Json(body)) }
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            format!(
                "http://127.0.0.1:{}/api/v1/registry/npm/access",
                address.port()
            ),
            handle,
        )
    }

    #[tokio::test]
    async fn npm_registry_routes_require_bearer_auth_when_auth_is_enabled() {
        let state = test_state();
        let app = npm_registry_routes(
            &state,
            &test_packages_dir(&state),
            "https://kinlab.ai",
            Some(Arc::new(NpmRegistryAuthState {
                client: reqwest::Client::new(),
                introspection_url: "http://127.0.0.1:9/api/v1/registry/npm/access".to_string(),
            })),
        );

        let response = app
            .oneshot(
                Request::get("/registry/npm/@kin%2Fboundary-contracts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer realm=\"kinlab npm registry\""
        );
    }

    #[tokio::test]
    async fn npm_publish_records_authenticated_publisher() {
        let state = test_state();
        let (auth_url, auth_server) = spawn_registry_auth_server(
            StatusCode::OK,
            serde_json::json!({
                "subject": {
                    "userId": "user_123",
                    "email": "builder@firelock.ai",
                    "displayName": "Builder",
                    "actorKind": "human"
                },
                "credentialType": "pat",
                "orgIds": ["firelock-ai"],
                "scopes": ["packages:write"]
            }),
        )
        .await;

        let app = npm_registry_routes(
            &state,
            &test_packages_dir(&state),
            "https://kinlab.ai",
            Some(Arc::new(NpmRegistryAuthState {
                client: reqwest::Client::new(),
                introspection_url: auth_url,
            })),
        );

        let publish_payload = serde_json::json!({
            "_id": "@kin/boundary-contracts",
            "name": "@kin/boundary-contracts",
            "dist-tags": { "latest": "0.1.0" },
            "versions": {
                "0.1.0": {
                    "name": "@kin/boundary-contracts",
                    "version": "0.1.0"
                }
            },
            "_attachments": {
                "@kin/boundary-contracts-0.1.0.tgz": {
                    "content_type": "application/octet-stream",
                    "data": "ZmFrZS10YXJiYWxs",
                    "length": 12
                }
            }
        });

        let publish = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .header(header::AUTHORIZATION, "Bearer publish-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(publish_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(publish.status(), StatusCode::CREATED);

        let manifest_store = kin_registry::ManifestStore::new(state.layout.root());
        let versions = manifest_store
            .get_versions(Ecosystem::Npm, "@kin/boundary-contracts")
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].published_by, "builder@firelock.ai");

        auth_server.abort();
    }

    #[tokio::test]
    async fn host_and_origin_allowlist_validation() {
        let state = test_state();
        let app = router_with_auth(state, None);

        // 1. Host is loopback/localhost -> should succeed
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "127.0.0.1:4219")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 2. Host is forbidden (e.g. attacker.com) -> should fail with FORBIDDEN
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "attacker.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 3. Origin is loopback/localhost -> should succeed
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost:4219")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // 4. Origin is forbidden (e.g. attacker.com) -> should fail with FORBIDDEN
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://attacker.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 5. Origin is null -> should fail with FORBIDDEN
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "null")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn host_without_port_handles_ipv6_and_ports() {
        assert_eq!(host_without_port("localhost"), "localhost");
        assert_eq!(host_without_port("127.0.0.1:4219"), "127.0.0.1");
        assert_eq!(host_without_port("[::1]:4219"), "::1");
        assert_eq!(host_without_port("[::1]"), "::1");
        assert!(is_host_allowed(host_without_port("[::1]:4219")));
        assert!(!is_host_allowed(host_without_port("evil.example.com:4219")));
    }

    #[tokio::test]
    async fn host_validation_protects_non_public_routes_and_accepts_ipv6_loopback() {
        let state = test_state();
        let app = router(state);

        // A non-public route (POST /search) with a rebound Host is rejected
        // before the handler runs.
        let rejected = app
            .clone()
            .oneshot(
                Request::post("/search")
                    .header(header::HOST, "attacker.com")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "query": "x" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        // A bracketed IPv6 loopback Host with a port is accepted (not 403/400).
        let allowed = app
            .oneshot(
                Request::get("/status")
                    .header(header::HOST, "[::1]:4219")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
        assert_ne!(allowed.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn host_header_required_on_non_public_routes() {
        // Exercise the production missing-Host guard directly: a minimal router
        // with ONLY `validate_host_and_origin` (no cfg(test) loopback-Host
        // injector). A raw-socket client that omits Host to dodge the allowlist
        // must be rejected on sensitive routes, while public liveness routes
        // stay reachable for health probes.
        let app = Router::new()
            .route("/search", post(|| async { StatusCode::OK }))
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(validate_host_and_origin));

        // Missing Host on a sensitive (non-public) route -> rejected.
        let rejected = app
            .clone()
            .oneshot(Request::post("/search").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        // Missing Host on a public liveness route -> still allowed.
        let allowed = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        // A present loopback Host on the sensitive route -> allowed through.
        let ok = app
            .oneshot(
                Request::post("/search")
                    .header(header::HOST, "127.0.0.1:4219")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_surfaces_mass_deletion_blocked_attention() {
        // When the fs-sync guard has withheld a suspected mass-deletion wipe,
        // /health must surface a non-"ok" "attention" status and the boolean so
        // operators/clients can detect the held state (the graph is intact).
        let state = test_state();
        state
            .mass_deletion_blocked
            .store(true, std::sync::atomic::Ordering::Relaxed);
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
        assert_eq!(json.status, "attention");
        assert!(json.mass_deletion_blocked);
    }

    #[tokio::test]
    async fn health_surfaces_embed_worker_failed_attention() {
        // When the embedding worker has permanently stopped (#11), the daemon
        // stays UP and serving, but /health must surface a non-"ok" "attention"
        // status + the boolean so the embed-degraded state is never silent.
        let state = test_state();
        state
            .embed_worker_failed
            .store(true, std::sync::atomic::Ordering::Relaxed);
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
        assert_eq!(json.status, "attention");
        assert!(json.embed_worker_failed);
    }

    #[tokio::test]
    async fn command_exec_requires_capability_optin() {
        // Default install (no KIN_DAEMON_ALLOW_EXEC) must refuse shell exec even
        // for an initialized daemon — being initialized is not sufficient.
        let _env = env_test_lock();
        std::env::remove_var("KIN_DAEMON_ALLOW_EXEC");

        let state = test_state();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/commands/exec")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "command": "echo hi" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn loopback_token_provisioned_persisted_and_accepted() {
        let dir = std::env::temp_dir().join(format!("kin-daemon-token-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(dir.join(".kin"));

        let token = ensure_loopback_token(&layout).unwrap();
        assert!(!token.is_empty());
        // Re-provisioning returns the SAME persisted token, not a fresh one.
        assert_eq!(ensure_loopback_token(&layout).unwrap(), token);
        let on_disk = std::fs::read_to_string(loopback_token_path(&layout)).unwrap();
        assert_eq!(on_disk.trim(), token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(loopback_token_path(&layout))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "token file must be 0600");
        }

        // A request carrying the provisioned token is accepted; a tokenless one
        // is rejected on non-public routes.
        let state = test_state();
        let app = router_with_auth(state, Some(token.clone()));
        let accepted = app
            .clone()
            .oneshot(
                Request::get("/status")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        let rejected = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn resolve_serve_auth_token_gates_enforcement() {
        let _env = env_test_lock();
        std::env::remove_var("KIN_DAEMON_AUTH_TOKEN");
        std::env::remove_var("KIN_DAEMON_REQUIRE_TOKEN");

        let dir = std::env::temp_dir().join(format!("kin-daemon-serve-token-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(dir.join(".kin"));

        // Default: enforcement is OFF, so no token is enforced — this is what
        // keeps existing unauthenticated local clients (CLI, integration tests,
        // env-only MCP delegate) working. The file is still provisioned so they
        // can adopt it ahead of a future enforcement flip.
        assert!(resolve_serve_auth_token(&layout).is_none());
        let provisioned = std::fs::read_to_string(loopback_token_path(&layout)).unwrap();
        assert!(!provisioned.trim().is_empty());

        // Opt-in: enforcement returns the provisioned loopback token.
        std::env::set_var("KIN_DAEMON_REQUIRE_TOKEN", "1");
        assert_eq!(
            resolve_serve_auth_token(&layout).as_deref(),
            Some(provisioned.trim())
        );

        // An explicit KIN_DAEMON_AUTH_TOKEN override always wins over the gate.
        std::env::set_var("KIN_DAEMON_AUTH_TOKEN", "explicit-override");
        assert_eq!(
            resolve_serve_auth_token(&layout).as_deref(),
            Some("explicit-override")
        );

        std::env::remove_var("KIN_DAEMON_AUTH_TOKEN");
        std::env::remove_var("KIN_DAEMON_REQUIRE_TOKEN");
    }

    #[tokio::test]
    async fn mcp_semantic_locate_reports_coverage_without_hard_gate() {
        let state = test_state();
        let entity = test_entity("handler", "src/lib.py");
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        // No vector index is populated. The handler must still return a valid
        // payload with a coverage field instead of hard-gating to an error.
        let response = app
            .clone()
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "semantic_locate",
                            "arguments": { "query": "handler", "limit": 5 }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
        assert_ne!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            kin_mcp::ContentBlock::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(
            parsed.get("semantic_coverage").is_some(),
            "response must carry semantic_coverage"
        );
        assert!(
            parsed.get("results").and_then(|v| v.as_array()).is_some(),
            "response must carry a results array"
        );

        // A missing query is a per-call error, not a panic / 500.
        let bad = app
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "name": "semantic_locate", "arguments": {} }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::OK);
        let bad_body = axum::body::to_bytes(bad.into_body(), 16 * 1024)
            .await
            .unwrap();
        let bad_result: kin_mcp::ToolCallResult = serde_json::from_slice(&bad_body).unwrap();
        assert_eq!(bad_result.is_error, Some(true));
    }

    /// Call `semantic_locate` over the MCP dispatch route and return the
    /// parsed JSON payload (must not be a tool error).
    async fn call_semantic_locate(app: Router, arguments: serde_json::Value) -> serde_json::Value {
        let response = app
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "name": "semantic_locate", "arguments": arguments }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
        assert_ne!(result.is_error, Some(true), "tool call errored: {result:?}");
        let text = match result.content.first().unwrap() {
            kin_mcp::ContentBlock::Text { text } => text,
        };
        serde_json::from_str(text).unwrap()
    }

    // FIR parity gate: the MCP `semantic_locate` fused arm must serve the SAME
    // ranking as `POST /locate` — same pipeline, same order — so the agent
    // surface is the product ranker, not a weaker shadow of it.
    #[tokio::test]
    async fn mcp_semantic_locate_fused_matches_locate_endpoint_ranking() {
        let state = test_state();
        state
            .graph
            .upsert_entity(&test_entity("parse_config", "src/config.py"))
            .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("render_output", "src/render.py"))
            .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("parse_config_helper", "src/config_util.py"))
            .unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        let locate_response = app
            .clone()
            .oneshot(
                Request::post("/locate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&kin_cli::daemon_client::LocateRequest {
                            text: "parse config".to_string(),
                            explain: false,
                            max_files: 10,
                            max_files_explicit: true,
                            reference: None,
                            snippets: false,
                            snippet_lines: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(locate_response.status(), StatusCode::OK);
        let locate_body = axum::body::to_bytes(locate_response.into_body(), 256 * 1024)
            .await
            .unwrap();
        let locate_result: kin_cli::commands::locate::LocateResult =
            serde_json::from_slice(&locate_body).unwrap();
        let locate_files: Vec<String> = locate_result
            .files
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        assert!(
            !locate_files.is_empty(),
            "locate endpoint should rank at least one file"
        );

        let payload = call_semantic_locate(
            app,
            json!({
                "query": "parse config",
                "granularity": "file",
                "limit": 10,
                "pipeline": "fused"
            }),
        )
        .await;
        assert_eq!(payload["routing"], "fused-v1");
        let mcp_files: Vec<String> = payload["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| hit["file"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            mcp_files, locate_files,
            "fused semantic_locate must serve the same file ranking as POST /locate"
        );
    }

    // Entity-granularity fused hits must stay act-on-able: a real entity_id
    // (resolvable for get_entity_source), the file, a line span, and the
    // ranked score — matching the agent output contract.
    #[tokio::test]
    async fn mcp_semantic_locate_fused_entity_hits_are_act_on_able() {
        let state = test_state();
        let entity = test_entity("parse_config", "src/config.py");
        let expected_id = entity.id.to_string();
        state.graph.upsert_entity(&entity).unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        let payload = call_semantic_locate(
            app,
            json!({
                "query": "parse config",
                "limit": 5,
                "pipeline": "fused"
            }),
        )
        .await;
        assert_eq!(payload["routing"], "fused-v1");
        assert_eq!(payload["granularity"], "entity");
        assert!(
            payload.get("semantic_coverage").is_some(),
            "fused payload keeps the legacy semantic_coverage float"
        );
        let results = payload["results"].as_array().unwrap();
        assert!(!results.is_empty(), "expected at least one entity hit");
        let hit = &results[0];
        assert_eq!(hit["entity_id"], expected_id);
        assert_eq!(hit["name"], "parse_config");
        assert_eq!(hit["file"], "src/config.py");
        let start_line = hit["start_line"].as_u64().unwrap();
        let end_line = hit["end_line"].as_u64().unwrap();
        assert!(
            start_line >= 1 && end_line >= start_line,
            "1-based inclusive line span expected, got {start_line}..{end_line}"
        );
        assert!(hit["score"].as_f64().is_some());
        assert!(hit["kind"].as_str().is_some());
    }

    // The legacy cosine ranking stays reachable per-call, independent of the
    // daemon's profile — the A/B lever for benchmarks and the compat escape.
    #[tokio::test]
    async fn mcp_semantic_locate_pipeline_cosine_override_serves_legacy() {
        let state = test_state();
        state
            .graph
            .upsert_entity(&test_entity("handler", "src/lib.py"))
            .unwrap();
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let app = router(state);

        let payload = call_semantic_locate(
            app.clone(),
            json!({ "query": "handler", "pipeline": "cosine" }),
        )
        .await;
        assert_eq!(payload["routing"], "cosine-v0");

        // Unknown pipeline values fail loud, not silently defaulted.
        let response = app
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "semantic_locate",
                            "arguments": { "query": "handler", "pipeline": "warp" }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    // ---------------------------------------------------------------
    // Rung-3 write veto (KIN_WRITE_VETO) — wired apply-path behavior.
    //
    // These exercise the real `vfs_write_notify` handler in-process (no daemon
    // is spawned). `KIN_WRITE_VETO` is process-global, so the env-touching
    // tests serialize on `VETO_ENV_LOCK` and restore the variable via an RAII
    // guard so a leak never bleeds into another test. The lock is a
    // `tokio::sync::Mutex` so the guard can be safely held across the handler's
    // `.await` (a std `MutexGuard` would trip `clippy::await_holding_lock`).
    // ---------------------------------------------------------------

    static VETO_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct EnvVarGuard(&'static str);
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn veto_file_target(state: &Arc<DaemonState>, rel: &str) -> (FilePathId, String) {
        let abs = state.layout.working_dir().join(rel);
        let file_id = kin_index::normalize_file_path_id(&abs, state.layout.working_dir());
        (file_id, abs.to_string_lossy().into_owned())
    }

    fn write_disk_file(state: &Arc<DaemonState>, rel: &str, content: &str) {
        let abs = state.layout.working_dir().join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, content).unwrap();
    }

    fn register_foreign_session(state: &Arc<DaemonState>, name: &str) -> SessionId {
        state
            .coordinator
            .register_session(
                name,
                "task",
                SessionTransport::Mcp,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap()
    }

    async fn write_notify(app: Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = app
            .oneshot(
                Request::post("/vfs/write-notify")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn write_notify_enforce_foreign_hard_intent_returns_409() {
        let _lock = VETO_ENV_LOCK.lock().await;
        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        // The veto short-circuits before reconcile reads the file, so the file
        // need not exist on disk for the rejection path.
        let foreign = register_foreign_session(&state, "other-agent");
        state
            .coordinator
            .register_intent(
                &foreign,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "rewriting lib",
                None,
            )
            .unwrap();

        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::set_var("KIN_WRITE_VETO", "enforce");
        let (status, json) =
            write_notify(router(state), serde_json::json!({ "file_path": abs })).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"], "write_veto");
        assert_eq!(json["conflict_type"], "HardCollision");
        assert!(!json["blocking_intents"].as_array().unwrap().is_empty());
        assert_eq!(
            json["blocking_intents"][0]["session_id"],
            foreign.to_string()
        );
    }

    #[tokio::test]
    async fn write_notify_flag_off_keeps_soft_notification() {
        // Flag-off identity: with a foreign hard intent present, default
        // behavior is unchanged — the reconciler's own check still declines to
        // fold the write (reindexed:false) and NO 409 is produced.
        let _lock = VETO_ENV_LOCK.lock().await;
        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::remove_var("KIN_WRITE_VETO");

        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        write_disk_file(&state, "src/lib.py", "def foo():\n    return 1\n");
        let foreign = register_foreign_session(&state, "other-agent");
        state
            .coordinator
            .register_intent(
                &foreign,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "rewriting lib",
                None,
            )
            .unwrap();

        let (status, json) =
            write_notify(router(state), serde_json::json!({ "file_path": abs })).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["reindexed"], false);
    }

    #[tokio::test]
    async fn write_notify_enforce_own_intent_allows_write() {
        // Own-write guard at the handler: a session editing a file it has
        // itself hard-locked is allowed, and the write is folded into the graph.
        let _lock = VETO_ENV_LOCK.lock().await;
        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        write_disk_file(&state, "src/lib.py", "def foo():\n    return 1\n");
        let caller = register_foreign_session(&state, "me");
        state
            .coordinator
            .register_intent(
                &caller,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "editing my own file",
                None,
            )
            .unwrap();

        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::set_var("KIN_WRITE_VETO", "enforce");
        let (status, json) = write_notify(
            router(state),
            serde_json::json!({ "file_path": abs, "session_id": caller.to_string() }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["reindexed"], true);
    }

    #[tokio::test]
    async fn write_notify_enforce_foreign_soft_intent_allows_write() {
        // Soft intents are advisory: even under enforce, a foreign soft intent
        // never vetoes the write.
        let _lock = VETO_ENV_LOCK.lock().await;
        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        write_disk_file(&state, "src/lib.py", "def foo():\n    return 1\n");
        let foreign = register_foreign_session(&state, "other-agent");
        state
            .coordinator
            .register_intent(
                &foreign,
                vec![IntentScope::Artifact(file_id)],
                LockType::Soft,
                "watching lib",
                None,
            )
            .unwrap();

        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::set_var("KIN_WRITE_VETO", "enforce");
        let (status, json) =
            write_notify(router(state), serde_json::json!({ "file_path": abs })).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["reindexed"], true);
    }

    async fn file_changed(app: Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let resp = app
            .oneshot(
                Request::post("/vfs/file-changed")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn file_changed_enforce_foreign_hard_intent_returns_409() {
        // The veto must cover /vfs/file-changed too — otherwise enforce-mode is
        // trivially bypassable by choosing this endpoint over /vfs/write-notify.
        let _lock = VETO_ENV_LOCK.lock().await;
        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        let foreign = register_foreign_session(&state, "other-agent");
        state
            .coordinator
            .register_intent(
                &foreign,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "rewriting lib",
                None,
            )
            .unwrap();

        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::set_var("KIN_WRITE_VETO", "enforce");
        let (status, json) = file_changed(router(state), serde_json::json!({ "path": abs })).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"], "write_veto");
        assert!(!json["blocking_intents"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_changed_flag_off_keeps_soft_notification() {
        // Flag-off identity for the file-changed path: foreign hard intent
        // present, default behavior unchanged — soft 200 {status:"error"}, no 409.
        let _lock = VETO_ENV_LOCK.lock().await;
        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::remove_var("KIN_WRITE_VETO");

        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        write_disk_file(&state, "src/lib.py", "def foo():\n    return 1\n");
        let foreign = register_foreign_session(&state, "other-agent");
        state
            .coordinator
            .register_intent(
                &foreign,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "rewriting lib",
                None,
            )
            .unwrap();

        let (status, json) = file_changed(router(state), serde_json::json!({ "path": abs })).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "error");
    }

    #[tokio::test]
    async fn file_changed_enforce_own_intent_allows_write() {
        // The additive session_id field lets file-changed honor the own-write
        // guard: a session editing a file it has itself hard-locked is allowed.
        let _lock = VETO_ENV_LOCK.lock().await;
        let state = test_state();
        let (file_id, abs) = veto_file_target(&state, "src/lib.py");
        write_disk_file(&state, "src/lib.py", "def foo():\n    return 1\n");
        let caller = register_foreign_session(&state, "me");
        state
            .coordinator
            .register_intent(
                &caller,
                vec![IntentScope::Artifact(file_id)],
                LockType::Hard,
                "editing my own file",
                None,
            )
            .unwrap();

        let _env = EnvVarGuard("KIN_WRITE_VETO");
        std::env::set_var("KIN_WRITE_VETO", "enforce");
        let (status, json) = file_changed(
            router(state),
            serde_json::json!({ "path": abs, "session_id": caller.to_string() }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "reconciled");
    }
}
