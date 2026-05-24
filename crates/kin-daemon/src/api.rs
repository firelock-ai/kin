// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::state::DaemonEvent;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use kin_model::session::{Intent, IntentScope, IntentSummary, LockType};
use kin_model::{
    BranchName, ChangeStore, ContractId, EntityId, EntityStore, FileLayout, FilePathId,
    GraphNodeId, IntentId, ProvenanceStore, SessionCapabilities, SessionId, SessionStore,
    SessionTransport, WorkStore,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::info;
use uuid::Uuid;

use crate::state::DaemonState;

static BOOTSTRAP_EXPORTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

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
    response
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
        .route("/commands/graph", post(command_graph))
        .route("/commands/overview", post(command_overview))
        .route("/commands/dead-code", post(command_dead_code))
        .route("/commands/dead-code-seeded", post(command_dead_code_seeded))
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

    // Cargo registry
    let crates_dir = packages_dir.join("crates");
    std::fs::create_dir_all(&crates_dir).ok();
    let cargo_routes =
        kin_registry::cargo::cargo_routes(Arc::new(kin_registry::cargo::CargoRegistryState {
            manifest_store: kin_registry::ManifestStore::new(state.layout.root()),
            blobs_dir: crates_dir,
            base_url: base_url.clone(),
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

    // Merge daemon routes (with DaemonState) and registry routes (each with own state).
    let daemon_routes = Router::new()
        .merge(routes.clone())
        .nest("/v1", routes)
        .with_state(state);

    Router::new()
        .merge(daemon_routes)
        .merge(cargo_routes)
        .merge(npm_routes)
        .merge(oci_routes)
        .merge(go_routes)
        .layer(middleware::from_fn_with_state(
            DaemonAuthState { auth_token },
            daemon_auth,
        ))
        .layer(middleware::from_fn_with_state(
            activity_state,
            daemon_activity,
        ))
        .layer(middleware::from_fn(api_version_header))
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

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
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

    // Resolve the ref string to a SemanticChangeId
    let resolved =
        kin_cli::commands::ref_lookup::resolve_ref_importing_git_if_needed_for_locate_with_report(
            state.graph.as_ref(),
            &state.layout,
            Some(&req.ref_string),
        )
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    if resolved.hydrated_git_history {
        state.bump_version();
        state.save_snapshot().map_err(internal_error)?;
        state.mark_clean();
    }
    let head = resolved.head;

    // Build the historical graph at that ref, using cached OID mapping
    // for fast scope switching without re-walking the commit DAG.
    let oid_cache: Option<kin_core::ChangeOidCache> = {
        let needs_build = state.change_oid_cache.read().unwrap().is_none();
        if needs_build {
            if let Ok(repo) = gix::open(state.layout.working_dir()) {
                match kin_core::build_change_oid_cache(&repo) {
                    Ok(cache) => {
                        info!("built change OID cache for fast scope switching");
                        *state.change_oid_cache.write().unwrap() = Some(cache);
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to build change OID cache, falling back to per-call lookup");
                    }
                }
            }
        }
        state.change_oid_cache.read().unwrap().clone()
    };
    let historical = kin_core::build_graph_at_ref_with_repo(
        state.graph.as_ref(),
        state.blobs.as_ref(),
        &head,
        Some(state.layout.working_dir()),
        oid_cache.as_ref(),
    )
    .map_err(internal_error)?;

    // Refresh cochange relations from the historical change set so the
    // cached graph matches what run_with_graph_capture_at_ref() produces.
    let changes = kin_core::collect_changes_at_ref(&historical, &head)
        .map_err(|err| internal_error(err.to_string()))?;
    let _ = kin_cli::commands::cochange::refresh_from_changes(&historical, &changes);

    let cached_graph = Arc::new(historical);
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
                            && caller_session
                                .as_ref()
                                .map_or(true, |cs| &s.session_id != cs)
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
    graph
        .update_branch_head(&request.branch_name, &request.change.id)
        .map_err(internal_error)?;

    if let Some(audit) = &request.audit_event {
        graph.record_audit_event(audit).map_err(internal_error)?;
    }

    // Broadcast root hash change and mark dirty for background persistence.
    // The background persistence task will flush to disk asynchronously —
    // the CLI doesn't wait for disk I/O.
    state.bump_version();
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
    let response = kin_cli::commands::status::build_command_status_response(summary, request.json)
        .map_err(internal_error)?;
    Ok(Json(response))
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

    let response = kin_cli::commands::checkout::execute_checkout_request(
        &state.layout,
        state.graph.as_ref(),
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

    // Build entity deltas from the working copy overlay.
    // The reconcile loop has already applied file changes into the overlay
    // AND into the primary graph (via apply_overlay_to_graph), so entity_adds/mods/removes
    // reflect the full diff since the last commit.
    let working_copy = state.working_copy.read().await;
    let overlay = &working_copy.uncommitted_mutations;

    let mut entity_deltas = Vec::new();
    for entity in overlay.entity_adds.values() {
        entity_deltas.push(kin_model::EntityDelta::Added(entity.clone()));
    }
    for entity in overlay.entity_mods.values() {
        entity_deltas.push(kin_model::EntityDelta::Modified {
            old: entity.clone(), // Simplified — old is the current state
            new: entity.clone(),
        });
    }
    for id in &overlay.entity_removes {
        entity_deltas.push(kin_model::EntityDelta::Removed(*id));
    }

    let mut relation_deltas = Vec::new();
    for relation in overlay.relation_adds.values() {
        relation_deltas.push(kin_model::RelationDelta::Added(relation.clone()));
    }
    for id in &overlay.relation_removes {
        relation_deltas.push(kin_model::RelationDelta::Removed(*id));
    }

    let entity_count = entity_deltas.len();
    let relation_count = relation_deltas.len();

    // Collect unique files from entity origins and build artifact deltas.
    // These deltas are required for build_file_tree() to reconstruct the VFS
    // file tree from the change DAG — without them, /vfs/tree returns empty.
    let mut files = HashSet::new();
    for entity in overlay.entity_adds.values() {
        if let Some(ref fp) = entity.file_origin {
            files.insert(fp.0.clone());
        }
    }
    for entity in overlay.entity_mods.values() {
        if let Some(ref fp) = entity.file_origin {
            files.insert(fp.0.clone());
        }
    }
    let file_count = files.len();

    // Build artifact deltas: read each file, store in blob store, record hash.
    // These are required for build_file_tree() to reconstruct the VFS file tree.
    let mut artifact_deltas = Vec::new();
    for file_path in &files {
        let abs_path = state.layout.working_dir().join(file_path);
        if let Ok(content) = std::fs::read(&abs_path) {
            // Check if blob already exists (indicates file was previously committed).
            let content_digest = kin_blobs::digest(&content);
            let previously_existed = state.blobs.exists(&content_digest).unwrap_or(false);

            let blob_hash = state.blobs.write(&content).unwrap_or(content_digest);
            let content_hash = kin_model::Hash256::from_bytes(blob_hash.0);

            let kind = if previously_existed {
                kin_model::ArtifactDeltaKind::Modified
            } else {
                kin_model::ArtifactDeltaKind::Added
            };

            artifact_deltas.push(kin_model::ArtifactDelta {
                file_id: FilePathId::new(file_path),
                kind,
                old_hash: None,
                new_hash: Some(content_hash),
            });
        }
    }

    drop(working_copy);

    // --- Lease enforcement gate (same as /graph/commit) ---
    {
        use kin_model::session::IntentScope;

        let scopes: Vec<IntentScope> = entity_deltas
            .iter()
            .map(|d| match d {
                kin_model::EntityDelta::Added(e) => IntentScope::Entity(e.id),
                kin_model::EntityDelta::Modified { new, .. } => IntentScope::Entity(new.id),
                kin_model::EntityDelta::Removed(id) => IntentScope::Entity(*id),
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
                            && caller_session
                                .as_ref()
                                .map_or(true, |cs| &s.session_id != cs)
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
    let change = kin_model::SemanticChange {
        id: kin_core::compute_change_id(&request.message, &branch.head),
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
        )
    } else {
        // Use scoped graph if session has a temporal scope, otherwise HEAD.
        let graph = resolve_session_graph(&state, session_id.as_ref()).await;

        // When a session scope is active, discover historical test artifact
        // priority files to match the ref-scoped path's behavior.
        let scope_ref_string = if let Some(sid) = session_id.as_ref() {
            state
                .get_session_scope(sid)
                .await
                .map(|(ref_str, _, _, _)| ref_str)
        } else {
            None
        };
        let extra_priority_files = scope_ref_string
            .map(|ref_str| {
                kin_cli::commands::locate::discover_historical_test_artifact_priority_files(
                    &state.layout,
                    &ref_str,
                    &req.text,
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
        kin_cli::commands::locate::run_with_graph_capture_with_priority_files_and_vector_source(
            graph.as_ref(),
            Some(state.layout.working_dir()),
            &req.text,
            req.explain,
            req.max_files,
            req.max_files_explicit,
            extra_priority_files,
            vector_source,
        )
    }
    .map_err(internal_error)?;
    Ok(Json(result))
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
        let _guard = state_for_embed
            .embedding_work
            .lock()
            .map_err(|_| "embedding work lock poisoned".to_string())?;
        let result = kin_cli::commands::embed::build_embed_response(
            &state_for_embed.layout,
            state_for_embed.graph.as_ref(),
            &req,
        )
        .map_err(|error| format!("embed build failed: {error:#}"))?;
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

    let state_for_reconcile = Arc::clone(&state);
    let summary = tokio::task::spawn_blocking(move || {
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
    .map_err(internal_error)?;
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
    )
}

fn mcp_session_registry_snapshot(
    state: &DaemonState,
) -> Result<kin_mcp::SessionRegistry, (StatusCode, String)> {
    let sessions = state.coordinator.list_sessions().map_err(internal_error)?;
    let intents = state.graph.list_all_intents().map_err(internal_error)?;
    let registry = kin_mcp::SessionRegistry::new();
    registry.replace_agent_sessions_and_intents(sessions, intents);
    Ok(registry)
}

/// POST /mcp/tools/call — execute an MCP tool against daemon-owned graph state.
///
/// MCP stdio processes are transport shims only. They forward graph-backed
/// tools here so query and mutation authority remains in the repo daemon.
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
        let result = match kin_cli::commands::graph::build_graph_source_response(
            &state.layout,
            graph.as_ref(),
            entity_id,
        ) {
            Ok(response) => match response.source {
                Some(source) => match serde_json::to_string_pretty(&source) {
                    Ok(json) => kin_mcp::ToolCallResult::text(json),
                    Err(error) => kin_mcp::ToolCallResult::error(error.to_string()),
                },
                None => kin_mcp::ToolCallResult::error(
                    "graph source response missing source".to_string(),
                ),
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
        let Some(query) = query else {
            return Ok(Json(kin_mcp::ToolCallResult::error(
                "missing required parameter: query".to_string(),
            )));
        };
        let req = kin_cli::commands::dead_code::DeadCodeSeededRequest { query, limit };
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

    let sessions = mcp_session_registry_snapshot(&state)?;

    let result = match kin_mcp::handlers::handle_tool_call(
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

    if mutates && result.is_error != Some(true) {
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: None,
            new_root_hash: format!("mcp-tool:{}", request.name),
        });
    }

    Ok(Json(result))
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
                state.bump_version(); // marks dirty for background persistence
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
                        });
                    }
                    for id in modified {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: crate::state::ChangeType::Modified,
                            file_path: Some(request.file_path.clone()),
                        });
                    }
                    for id in removed {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: crate::state::ChangeType::Deleted,
                            file_path: Some(request.file_path.clone()),
                        });
                    }
                    count
                }
                _ => 0,
            };

            drop(wc);
            drop(reconciler);

            if entity_count > 0 {
                state.bump_version(); // marks dirty for background persistence
                if let Err(e) = state.rebuild_projection().await {
                    tracing::warn!(error = %e, "failed to rebuild projection after write-notify");
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

    Ok(Json(impact))
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

    Ok(Json(json!({ "edges": edges })))
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
    let auth_token = auth_token_from_env();
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

    #[tokio::test]
    async fn exec_endpoint_runs_against_live_graph_workspace() {
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
    async fn trace_endpoint_renders_file_paths_in_daemon() {
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
        assert!(result.lines.iter().any(|line| line == "--- src/lib.py ---"));
        assert!(result.lines.iter().any(|line| line.contains("def handler")));
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
}
