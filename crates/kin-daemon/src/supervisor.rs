// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Central local daemon supervisor.
//!
//! The supervisor is intentionally not a graph authority. It owns process
//! discovery and routing for repo-scoped graph daemons, while each repo daemon
//! remains the single writer for its repo graph.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::DaemonState;

const SUPERVISOR_PID_FILE: &str = "supervisor.pid";
const SUPERVISOR_PORT_FILE: &str = "supervisor.port";
const SUPERVISOR_TOKEN_FILE: &str = "supervisor.token";
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TTL: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoDaemonRegistration {
    pub repo_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub instance_id: String,
    pub repo_root: String,
    pub pid: u32,
    pub port: u16,
    pub endpoint: String,
    #[serde(default)]
    pub graph_entity_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredRepoDaemon {
    pub repo_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub instance_id: String,
    pub repo_root: String,
    pub pid: u32,
    pub port: u16,
    pub endpoint: String,
    #[serde(default)]
    pub graph_entity_count: Option<usize>,
    pub registered_at: String,
    pub last_heartbeat_at: String,
    #[serde(skip)]
    last_heartbeat_elapsed_ms: u64,
}

#[derive(Debug, Serialize)]
struct SupervisorHealthResponse {
    status: &'static str,
    version: &'static str,
    pid: u32,
    uptime_seconds: u64,
    repo_daemon_count: usize,
    idle_seconds: u64,
}

#[derive(Debug, Serialize)]
struct RouteResponse {
    repo_id: String,
    display_name: String,
    endpoint: String,
    repo_root: String,
    pid: u32,
    port: u16,
    graph_entity_count: Option<usize>,
    last_heartbeat_at: String,
}

#[derive(Debug, Deserialize)]
struct DeregisterQuery {
    #[serde(default)]
    instance_id: Option<String>,
}

pub struct SupervisorState {
    started_at: Instant,
    last_activity_ms: AtomicU64,
    repo_daemons: RwLock<BTreeMap<String, RegisteredRepoDaemon>>,
}

impl SupervisorState {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            repo_daemons: RwLock::new(BTreeMap::new()),
        }
    }

    fn touch(&self) {
        self.last_activity_ms.store(
            self.started_at.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
    }

    fn idle_duration(&self) -> Duration {
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        self.started_at
            .elapsed()
            .saturating_sub(Duration::from_millis(last_ms))
    }

    fn elapsed_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }

    async fn prune_unhealthy_daemons(&self) -> usize {
        let now_ms = self.elapsed_ms();
        let mut repos = self.repo_daemons.write().await;
        let before = repos.len();
        repos.retain(|repo_id, daemon| {
            let alive = is_process_alive(daemon.pid);
            let fresh =
                Duration::from_millis(now_ms.saturating_sub(daemon.last_heartbeat_elapsed_ms))
                    <= HEARTBEAT_TTL;
            if !alive {
                debug!(repo_id = %repo_id, pid = daemon.pid, "pruning dead repo daemon");
            }
            if alive && !fresh {
                debug!(repo_id = %repo_id, pid = daemon.pid, "pruning stale repo daemon route");
            }
            alive && fresh
        });
        before.saturating_sub(repos.len())
    }
}

fn supervisor_dir() -> PathBuf {
    kin_core::registry::registry_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".kin"))
}

fn supervisor_pid_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_PID_FILE)
}

fn supervisor_port_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_PORT_FILE)
}

fn write_supervisor_endpoint_files(port: u16) {
    let dir = supervisor_dir();
    let _ = std::fs::create_dir_all(&dir);
    let pid_tmp = dir.join(format!("{SUPERVISOR_PID_FILE}.tmp"));
    if std::fs::write(&pid_tmp, std::process::id().to_string()).is_ok() {
        let _ = std::fs::rename(pid_tmp, supervisor_pid_path());
    }
    // Written atomically (temp + rename) so a CLI polling the port file during
    // the supervisor→CLI port handshake never parses a torn or partial value.
    let port_tmp = dir.join(format!("{SUPERVISOR_PORT_FILE}.tmp"));
    if std::fs::write(&port_tmp, port.to_string()).is_ok() {
        let _ = std::fs::rename(port_tmp, supervisor_port_path());
    }
}

fn remove_supervisor_endpoint_files_if_current_process() {
    let pid_path = supervisor_pid_path();
    let belongs_to_current = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
        == Some(std::process::id());
    if !belongs_to_current {
        return;
    }
    let _ = std::fs::remove_file(pid_path);
    let _ = std::fs::remove_file(supervisor_port_path());
}

pub fn supervisor_url_from_files() -> Option<String> {
    let pid = std::fs::read_to_string(supervisor_pid_path())
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if !is_process_alive(pid) {
        let _ = std::fs::remove_file(supervisor_pid_path());
        let _ = std::fs::remove_file(supervisor_port_path());
        return None;
    }
    let port = std::fs::read_to_string(supervisor_port_path())
        .ok()?
        .trim()
        .parse::<u16>()
        .ok()?;
    Some(format!("http://127.0.0.1:{port}"))
}

fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn canonical_path_string(path: impl Into<PathBuf>) -> String {
    let path = path.into();
    path.canonicalize().unwrap_or(path).display().to_string()
}

fn repo_route_id_for_path(path: &Path) -> String {
    let canonical = canonical_path_string(path);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("local-{}", &hex::encode(digest)[..16])
}

fn repo_display_name_for_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn instance_id_for(pid: u32, port: u16) -> String {
    format!("pid-{pid}-port-{port}")
}

fn display_name_for_payload(payload: &RepoDaemonRegistration) -> String {
    if !payload.display_name.trim().is_empty() {
        return payload.display_name.clone();
    }
    repo_display_name_for_path(Path::new(&payload.repo_root))
}

fn instance_id_for_payload(payload: &RepoDaemonRegistration) -> String {
    if !payload.instance_id.trim().is_empty() {
        return payload.instance_id.clone();
    }
    instance_id_for(payload.pid, payload.port)
}

fn repo_registration_payload(state: &DaemonState, port: u16) -> RepoDaemonRegistration {
    let working_dir = state.layout.working_dir();
    let pid = std::process::id();
    RepoDaemonRegistration {
        repo_id: repo_route_id_for_path(working_dir),
        display_name: repo_display_name_for_path(working_dir),
        instance_id: instance_id_for(pid, port),
        repo_root: canonical_path_string(working_dir),
        pid,
        port,
        endpoint: format!("http://127.0.0.1:{port}"),
        graph_entity_count: Some(state.graph.entity_count()),
    }
}

async fn post_registration(
    client: &reqwest::Client,
    supervisor_url: &str,
    payload: &RepoDaemonRegistration,
) -> Result<(), reqwest::Error> {
    client
        .post(format!(
            "{}/daemons/register",
            supervisor_url.trim_end_matches('/')
        ))
        .json(payload)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn post_heartbeat(
    client: &reqwest::Client,
    supervisor_url: &str,
    payload: &RepoDaemonRegistration,
) -> Result<(), reqwest::Error> {
    client
        .post(format!(
            "{}/daemons/{}/heartbeat",
            supervisor_url.trim_end_matches('/'),
            payload.repo_id
        ))
        .json(payload)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn delete_registration(
    client: &reqwest::Client,
    supervisor_url: &str,
    payload: &RepoDaemonRegistration,
) -> Result<(), reqwest::Error> {
    client
        .delete(format!(
            "{}/daemons/{}?instance_id={}",
            supervisor_url.trim_end_matches('/'),
            payload.repo_id,
            payload.instance_id
        ))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub async fn repo_daemon_registration_loop(
    state: Arc<DaemonState>,
    port: u16,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut registered = false;
    let mut payload = repo_registration_payload(&state, port);
    let mut supervisor_url = std::env::var("KIN_SUPERVISOR_URL")
        .ok()
        .or_else(supervisor_url_from_files);

    let mut interval = tokio::time::interval(DEFAULT_HEARTBEAT_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                payload.graph_entity_count = Some(state.graph.entity_count());
                if supervisor_url.is_none() {
                    supervisor_url = std::env::var("KIN_SUPERVISOR_URL")
                        .ok()
                        .or_else(supervisor_url_from_files);
                }
                let Some(current_supervisor_url) = supervisor_url.as_deref() else {
                    debug!(repo_id = %payload.repo_id, "no Kin supervisor endpoint found yet; retrying discovery");
                    continue;
                };

                let result = if registered {
                    post_heartbeat(&client, current_supervisor_url, &payload).await
                } else {
                    post_registration(&client, current_supervisor_url, &payload).await
                };

                match result {
                    Ok(()) => {
                        if !registered {
                            info!(repo_id = %payload.repo_id, display_name = %payload.display_name, supervisor_url = %current_supervisor_url, "registered repo daemon with supervisor");
                        }
                        registered = true;
                    }
                    Err(error) => {
                        let status = error.status();
                        warn!(error = %error, repo_id = %payload.repo_id, "supervisor registration heartbeat failed");
                        if status != Some(reqwest::StatusCode::CONFLICT) {
                            registered = false;
                            supervisor_url = std::env::var("KIN_SUPERVISOR_URL")
                                .ok()
                                .or_else(supervisor_url_from_files);
                        }
                    }
                }
            }
            _ = cancel_rx.changed() => {
                break;
            }
        }
        if *cancel_rx.borrow() {
            break;
        }
    }

    if registered {
        if let Some(supervisor_url) = supervisor_url {
            if let Err(error) = delete_registration(&client, &supervisor_url, &payload).await {
                warn!(error = %error, repo_id = %payload.repo_id, "failed to deregister repo daemon from supervisor");
            }
        }
    }
}

// ===== Control-plane hardening =====
//
// The supervisor is a local control plane (process discovery + routing for repo
// daemons). It MUST be guarded exactly like the per-repo daemon HTTP surface
// (`api.rs`): a DNS-rebinding Host/Origin guard plus an optional loopback bearer
// token. The helpers below mirror `api.rs` one-for-one, swapping the
// `KIN_DAEMON_*` env vars for `KIN_SUPERVISOR_*` and the `daemon.token` file for
// `supervisor.token`, so the two surfaces stay symmetric.

/// `.kin/supervisor.token` — auto-provisioned per-install loopback token, under
/// the given supervisor directory.
fn supervisor_token_path(dir: &Path) -> PathBuf {
    dir.join(SUPERVISOR_TOKEN_FILE)
}

/// Strip an optional `:port` suffix from a Host/authority value, correctly
/// handling bracketed IPv6 literals like `[::1]:4319` (returns `::1`). Mirrors
/// `api::host_without_port`.
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

/// Whether `host` is an allowed Host/Origin for the supervisor. Loopback is
/// always allowed; a non-loopback `KIN_SUPERVISOR_BIND_HOST` is allowed only for
/// the host the operator explicitly bound to (or a wildcard bind). Mirrors
/// `api::is_host_allowed`, keyed on `KIN_SUPERVISOR_BIND_HOST`.
fn is_host_allowed(host: &str) -> bool {
    let host = host.trim();
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return true;
    }
    if let Ok(bind_host) = std::env::var("KIN_SUPERVISOR_BIND_HOST") {
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

/// Liveness routes that stay reachable without a Host header or bearer token so
/// health-probe tooling is unaffected. Mirrors `api::is_public_route`.
fn is_public_route(path: &str) -> bool {
    matches!(path, "/health" | "/readiness")
}

/// DNS-rebinding defense: reject forged `Host` and cross-origin requests.
/// Byte-for-byte the same policy as `api::validate_host_and_origin`.
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
    // liveness routes (/health, /readiness) stay reachable without a Host so
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

    // 2. Validate Origin header if present.
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
        HeaderValue::from_static("Bearer realm=\"kin supervisor\""),
    );
    response
}

#[derive(Clone)]
struct SupervisorAuthState {
    auth_token: Option<String>,
}

/// Bearer-token guard for the supervisor control plane. No-ops when no token is
/// enforced and on public liveness routes; otherwise requires a matching
/// `Authorization: Bearer <token>`. Mirrors `api::daemon_auth`.
async fn supervisor_auth(
    State(auth_state): State<SupervisorAuthState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
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

fn resolve_auth_token(auth_token: Option<String>) -> Option<String> {
    auth_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn auth_token_from_env() -> Option<String> {
    resolve_auth_token(std::env::var("KIN_SUPERVISOR_AUTH_TOKEN").ok())
}

/// Load the per-install supervisor loopback token, generating and persisting one
/// (mode 0600 on unix) on first run. Mirrors `api::ensure_loopback_token`.
fn ensure_loopback_token(dir: &Path) -> std::io::Result<String> {
    let path = supervisor_token_path(dir);
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

/// Whether the supervisor should ENFORCE the per-install loopback token.
/// Opt-in via `KIN_SUPERVISOR_REQUIRE_TOKEN`, mirroring the repo daemon's
/// `KIN_DAEMON_REQUIRE_TOKEN`. The Host/Origin guard is always active regardless.
fn loopback_token_enforced() -> bool {
    std::env::var("KIN_SUPERVISOR_REQUIRE_TOKEN")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Resolve the auth token the serving supervisor enforces: an explicit
/// `KIN_SUPERVISOR_AUTH_TOKEN` override always wins. Otherwise the per-install
/// loopback token is auto-provisioned under `.kin/` (so local clients can adopt
/// it) but only returned for enforcement when `KIN_SUPERVISOR_REQUIRE_TOKEN`
/// is set. Mirrors `api::resolve_serve_auth_token`.
fn resolve_serve_auth_token(dir: &Path) -> Option<String> {
    if let Some(env_token) = auth_token_from_env() {
        return Some(env_token);
    }
    match ensure_loopback_token(dir) {
        Ok(token) => loopback_token_enforced().then_some(token),
        Err(error) => {
            warn!(
                %error,
                "failed to provision supervisor loopback auth token; supervisor will run without bearer auth"
            );
            None
        }
    }
}

/// Public router used by tests and callers that do not enforce a token. Mirrors
/// `api::router` delegating to `router_with_auth(state, None)`.
pub fn router(state: Arc<SupervisorState>) -> Router {
    router_with_auth(state, None)
}

fn router_with_auth(state: Arc<SupervisorState>, auth_token: Option<String>) -> Router {
    let app = Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/repos", get(list_repos))
        .route("/repos/{repo_id}/route", get(route_repo))
        .route("/daemons", get(list_repos))
        .route("/daemons/register", post(register_daemon))
        .route("/daemons/{repo_id}/heartbeat", post(heartbeat_daemon))
        .route("/daemons/{repo_id}", delete(deregister_daemon))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            SupervisorAuthState { auth_token },
            supervisor_auth,
        ))
        .layer(middleware::from_fn(validate_host_and_origin));

    // Synthetic in-process tower test requests (`Request::get("/…")`) omit the
    // Host header that every real HTTP/1.1 client — and the production
    // `axum::serve` path — always sends. Without it the
    // `validate_host_and_origin` missing-Host guard would 403 the entire unit
    // suite. This cfg(test)-only shim restores that realism by defaulting an
    // absent Host to loopback; it layers OUTSIDE (runs before) the guard and is
    // compiled out of production and integration builds. The guard's
    // missing-Host behaviour is covered directly by
    // `supervisor_host_header_required_on_non_public_routes`.
    #[cfg(test)]
    let app = app.layer(middleware::from_fn(inject_loopback_host_in_tests));

    app
}

/// Test-only: default an absent `Host` header to loopback so synthetic tower
/// requests survive the `validate_host_and_origin` missing-Host guard. Never
/// compiled into production builds (`#[cfg(test)]`). Mirrors the api.rs shim.
#[cfg(test)]
async fn inject_loopback_host_in_tests(
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !request.headers().contains_key(header::HOST) {
        request
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static("127.0.0.1"));
    }
    next.run(request).await
}

async fn health(State(state): State<Arc<SupervisorState>>) -> impl IntoResponse {
    state.touch();
    state.prune_unhealthy_daemons().await;
    let repo_daemon_count = state.repo_daemons.read().await.len();
    Json(SupervisorHealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        repo_daemon_count,
        idle_seconds: state.idle_duration().as_secs(),
    })
}

async fn readiness() -> impl IntoResponse {
    StatusCode::OK
}

async fn list_repos(State(state): State<Arc<SupervisorState>>) -> impl IntoResponse {
    state.touch();
    state.prune_unhealthy_daemons().await;
    let repos: Vec<RegisteredRepoDaemon> =
        state.repo_daemons.read().await.values().cloned().collect();
    Json(repos)
}

async fn route_repo(
    AxumPath(repo_id): AxumPath<String>,
    State(state): State<Arc<SupervisorState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state.touch();
    state.prune_unhealthy_daemons().await;
    let repos = state.repo_daemons.read().await;
    let Some(repo) = repos.get(&repo_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no daemon registered for repo {repo_id}"),
        ));
    };
    if !is_process_alive(repo.pid) {
        drop(repos);
        let mut repos = state.repo_daemons.write().await;
        repos.remove(&repo_id);
        return Err((
            StatusCode::NOT_FOUND,
            format!("daemon for repo {repo_id} is no longer alive"),
        ));
    }
    Ok(Json(RouteResponse {
        repo_id,
        display_name: repo.display_name.clone(),
        endpoint: repo.endpoint.clone(),
        repo_root: repo.repo_root.clone(),
        pid: repo.pid,
        port: repo.port,
        graph_entity_count: repo.graph_entity_count,
        last_heartbeat_at: repo.last_heartbeat_at.clone(),
    }))
}

async fn register_daemon(
    State(state): State<Arc<SupervisorState>>,
    Json(payload): Json<RepoDaemonRegistration>,
) -> impl IntoResponse {
    state.touch();
    state.prune_unhealthy_daemons().await;
    let now = chrono::Utc::now().to_rfc3339();
    let heartbeat_ms = state.elapsed_ms();
    let instance_id = instance_id_for_payload(&payload);
    let mut repos = state.repo_daemons.write().await;
    if let Some(existing) = repos.get(&payload.repo_id) {
        if existing.instance_id != instance_id {
            return (StatusCode::CONFLICT, Json(existing.clone()));
        }
    }
    let record = RegisteredRepoDaemon {
        repo_id: payload.repo_id.clone(),
        display_name: display_name_for_payload(&payload),
        instance_id,
        repo_root: payload.repo_root,
        pid: payload.pid,
        port: payload.port,
        endpoint: payload.endpoint,
        graph_entity_count: payload.graph_entity_count,
        registered_at: now.clone(),
        last_heartbeat_at: now,
        last_heartbeat_elapsed_ms: heartbeat_ms,
    };
    repos.insert(payload.repo_id, record.clone());
    (StatusCode::OK, Json(record))
}

async fn heartbeat_daemon(
    AxumPath(repo_id): AxumPath<String>,
    State(state): State<Arc<SupervisorState>>,
    Json(payload): Json<RepoDaemonRegistration>,
) -> impl IntoResponse {
    state.touch();
    state.prune_unhealthy_daemons().await;
    let now = chrono::Utc::now().to_rfc3339();
    let heartbeat_ms = state.elapsed_ms();
    let instance_id = instance_id_for_payload(&payload);
    let mut repos = state.repo_daemons.write().await;
    if let Some(existing) = repos.get(&repo_id) {
        if existing.instance_id != instance_id {
            return (StatusCode::CONFLICT, Json(existing.clone()));
        }
    }
    let record = repos
        .entry(repo_id.clone())
        .or_insert_with(|| RegisteredRepoDaemon {
            repo_id: repo_id.clone(),
            display_name: display_name_for_payload(&payload),
            instance_id: instance_id.clone(),
            repo_root: payload.repo_root.clone(),
            pid: payload.pid,
            port: payload.port,
            endpoint: payload.endpoint.clone(),
            graph_entity_count: payload.graph_entity_count,
            registered_at: now.clone(),
            last_heartbeat_at: now.clone(),
            last_heartbeat_elapsed_ms: heartbeat_ms,
        });
    record.display_name = display_name_for_payload(&payload);
    record.instance_id = instance_id;
    record.repo_root = payload.repo_root;
    record.pid = payload.pid;
    record.port = payload.port;
    record.endpoint = payload.endpoint;
    record.graph_entity_count = payload.graph_entity_count;
    record.last_heartbeat_at = now;
    record.last_heartbeat_elapsed_ms = heartbeat_ms;
    (StatusCode::OK, Json(record.clone()))
}

async fn deregister_daemon(
    AxumPath(repo_id): AxumPath<String>,
    Query(query): Query<DeregisterQuery>,
    State(state): State<Arc<SupervisorState>>,
) -> impl IntoResponse {
    state.touch();
    let mut repos = state.repo_daemons.write().await;
    let removed = match repos.get(&repo_id) {
        Some(existing)
            if query
                .instance_id
                .as_deref()
                .is_some_and(|instance_id| instance_id == existing.instance_id) =>
        {
            repos.remove(&repo_id).is_some()
        }
        Some(_) => false,
        None => false,
    };
    Json(serde_json::json!({
        "repo_id": repo_id,
        "removed": removed
    }))
}

pub async fn run_supervisor(port: u16, idle_timeout: Option<Duration>) -> std::io::Result<()> {
    let state = Arc::new(SupervisorState::new());

    let bind_host = std::env::var("KIN_SUPERVISOR_BIND_HOST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let addr: SocketAddr = format!("{bind_host}:{port}")
        .parse::<SocketAddr>()
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;

    // Resolve the bearer token the control plane enforces, then refuse to expose
    // the supervisor beyond loopback without one — mirrors `api::bind_listener`,
    // which rejects a non-loopback daemon bind that has no auth token. The
    // Host/Origin guard is always active; the token is the second layer for
    // non-browser local/LAN callers.
    let auth_token = resolve_serve_auth_token(&supervisor_dir());
    if !addr.ip().is_loopback() && auth_token.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "KIN_SUPERVISOR_AUTH_TOKEN (or KIN_SUPERVISOR_REQUIRE_TOKEN) is required when binding the supervisor to a non-loopback host",
        ));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_port = listener.local_addr()?.port();
    write_supervisor_endpoint_files(bound_port);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    if let Some(idle_timeout) = idle_timeout {
        let idle_state = Arc::clone(&state);
        let idle_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            let check_interval =
                Duration::from_millis(((idle_timeout.as_millis() / 4).clamp(250, 5_000)) as u64);
            loop {
                tokio::time::sleep(check_interval).await;
                idle_state.prune_unhealthy_daemons().await;
                if !idle_state.repo_daemons.read().await.is_empty() {
                    continue;
                }
                if idle_state.idle_duration() >= idle_timeout {
                    info!("supervisor idle timeout reached, shutting down");
                    let _ = idle_shutdown.send(true);
                    break;
                }
            }
        });
    }

    // Machine-wide rogue/misbehaving daemon reaper. Runs independently of idle
    // shutdown: even a long-lived supervisor backstops the machine by reaping
    // demonstrably-misbehaving repo daemons it never spawned. Disabled entirely
    // via KIN_SUPERVISOR_REAP_DISABLE.
    spawn_rogue_daemon_reaper(Arc::clone(&state), shutdown_rx.clone());

    #[cfg(unix)]
    {
        let signal_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sigterm) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = sigterm.recv().await;
                let _ = signal_shutdown.send(true);
            }
        });
    }
    {
        let signal_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = signal_shutdown.send(true);
            }
        });
    }

    info!(port = bound_port, "kin supervisor listening");
    let result = axum::serve(listener, router_with_auth(state, auth_token))
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    remove_supervisor_endpoint_files_if_current_process();
    result
}

// ===== Machine-wide rogue/misbehaving daemon reaper =====
//
// The supervisor backstops the whole machine: it sweeps for repo-scoped
// kin-daemon processes (regardless of who launched them) and reaps only the
// demonstrably-misbehaving ones, always logging pid + repo + reason. The
// graceful step is SIGTERM (the daemon flushes and exits cleanly on it), then
// SIGKILL if it does not exit within the grace window.

/// How often the reaper sweeps the machine.
const REAPER_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// Timeout for a single repo-daemon `/health` probe.
const REAPER_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Grace period between SIGTERM and SIGKILL when reaping.
const REAPER_SIGTERM_GRACE: Duration = Duration::from_secs(5);
/// CPU usage percent (may exceed 100 on multicore) above which a daemon counts
/// as "pinned" for a sweep.
const REAPER_DEFAULT_CPU_PINNED_PERCENT: f32 = 80.0;
/// Default consecutive pinned sweeps before the CPU heuristic fires.
const REAPER_DEFAULT_CPU_PINNED_SWEEPS: u32 = 2;
/// Default slack (in seconds) a daemon's start_time may lag the deployed binary
/// mtime before it counts as stale — absorbs clock/filesystem timestamp jitter.
const REDEPLOY_DEFAULT_GRACE_SECS: u64 = 2;
/// Sentinel env var carried across the self-re-exec boundary, recording the
/// binary mtime the supervisor already re-execed into. Breaks the re-exec loop:
/// execve preserves the process start_time, so a supervisor that predates its
/// rebuilt binary stays stale after re-exec; without this sentinel it would
/// re-exec on every sweep forever.
const SUPERVISOR_REEXECED_FOR_MTIME_ENV: &str = "KIN_SUPERVISOR_REEXECED_FOR_MTIME";

/// Health classification of a discovered repo daemon.
#[derive(Debug, Clone, PartialEq)]
enum DaemonHealth {
    /// `/health` responded 2xx; carries observed activity.
    Healthy(DaemonActivity),
    /// `/health` failed, timed out, or returned non-2xx.
    Unhealthy,
    /// No port was discoverable, so health could not be probed.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonActivity {
    /// In-flight requests, event subscribers, or external (non-daemon) sessions.
    has_clients: bool,
    /// Reconciliation is actively running (not idle).
    reconciling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapReason {
    /// Orphaned (reparented to init) and the health probe failed/timed out.
    OrphanedUnhealthy,
    /// Orphaned, healthy but idle (no clients, not reconciling), and CPU-pinned
    /// across enough consecutive sweeps — the busy-spinner case.
    OrphanedBusyNoClients,
    /// Orphaned duplicate of a registered, healthy daemon on the same repo root.
    DuplicateOrphanTwin,
}

/// Why a healthy-but-invisible daemon is being adopted into the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptReason {
    /// No registry entry existed for this repo root.
    Unregistered,
    /// A registry entry for this repo root existed but named a dead pid; the live
    /// healthy daemon replaces it.
    HealStaleEntry,
}

/// Why a healthy idle daemon is being rolled over to pick up a fresh build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedeployReason {
    /// The on-disk binary was rebuilt after this process started (its start_time
    /// predates the binary mtime), so the daemon is running stale code.
    StaleBinary,
}

/// How a discovered daemon relates to the supervisor's registry entry (if any)
/// for the same repo root. Computed per sweep from a registry snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryRelation {
    /// No registry entry exists for this repo root.
    Unregistered,
    /// The registry entry for this repo root names THIS pid.
    RegisteredSelf,
    /// A registry entry exists for this repo root but names a *different* pid that
    /// is no longer alive — a stale entry to heal.
    StaleDifferentPid,
    /// A registry entry exists for this repo root naming a *different*, still-alive
    /// pid — a live twin owns the route.
    LiveTwin,
}

#[derive(Debug, Clone, PartialEq)]
enum DaemonDecision {
    Keep,
    Reap(ReapReason),
    Adopt(AdoptReason),
    Redeploy(RedeployReason),
}

/// Which heuristics beyond the always-on safe criterion are enabled, and how the
/// CPU heuristic is tuned. Controlled by `KIN_SUPERVISOR_REAP_*`.
#[derive(Debug, Clone, Copy)]
struct ReapPolicy {
    cpu_heuristic_enabled: bool,
    duplicate_reap_enabled: bool,
    /// Self-healing adoption of healthy-but-invisible daemons. On by default.
    adopt_enabled: bool,
    /// Build-aware rolling redeploy of healthy idle daemons running a stale
    /// binary. On by default.
    redeploy_enabled: bool,
    /// Supervisor self-re-exec into a freshly built binary when its own image is
    /// stale. On by default.
    reexec_enabled: bool,
    cpu_pinned_percent: f32,
    cpu_pinned_min_sweeps: u32,
    /// Slack allowed between a daemon's start_time and the deployed binary mtime
    /// before it counts as stale.
    redeploy_grace_secs: u64,
}

impl Default for ReapPolicy {
    fn default() -> Self {
        Self {
            cpu_heuristic_enabled: true,
            duplicate_reap_enabled: true,
            adopt_enabled: true,
            redeploy_enabled: true,
            reexec_enabled: true,
            cpu_pinned_percent: REAPER_DEFAULT_CPU_PINNED_PERCENT,
            cpu_pinned_min_sweeps: REAPER_DEFAULT_CPU_PINNED_SWEEPS,
            redeploy_grace_secs: REDEPLOY_DEFAULT_GRACE_SECS,
        }
    }
}

impl ReapPolicy {
    fn from_env() -> Self {
        let mut policy = Self::default();
        if env_flag_falsey("KIN_SUPERVISOR_REAP_CPU") {
            policy.cpu_heuristic_enabled = false;
        }
        if env_flag_falsey("KIN_SUPERVISOR_REAP_DUPLICATE") {
            policy.duplicate_reap_enabled = false;
        }
        if env_flag_truthy("KIN_SUPERVISOR_ADOPT_DISABLE") {
            policy.adopt_enabled = false;
        }
        if env_flag_truthy("KIN_SUPERVISOR_REDEPLOY_DISABLE") {
            policy.redeploy_enabled = false;
        }
        if env_flag_truthy("KIN_SUPERVISOR_REEXEC_DISABLE") {
            policy.reexec_enabled = false;
        }
        if let Some(grace) = std::env::var("KIN_SUPERVISOR_REDEPLOY_GRACE")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            policy.redeploy_grace_secs = grace;
        }
        if let Some(percent) = std::env::var("KIN_SUPERVISOR_REAP_CPU_PERCENT")
            .ok()
            .and_then(|v| v.trim().parse::<f32>().ok())
            .filter(|v| *v > 0.0)
        {
            policy.cpu_pinned_percent = percent;
        }
        if let Some(sweeps) = std::env::var("KIN_SUPERVISOR_REAP_CPU_SWEEPS")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|v| *v >= 1)
        {
            policy.cpu_pinned_min_sweeps = sweeps;
        }
        policy
    }
}

/// True when `key` is set to an explicitly falsey value (`0/false/no/off`).
fn env_flag_falsey(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::trim),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

/// True when `key` is set to an explicitly truthy value (`1/true/yes/on`).
fn env_flag_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// True when the deployed binary mtime is strictly newer than the process
/// start_time plus `grace_secs` — i.e. the binary was rebuilt after the process
/// started and the slack window has elapsed. The boundary is exclusive: a
/// daemon whose mtime equals `start_time + grace_secs` is NOT stale. Returns
/// false when the deployed mtime is unknown (cannot prove staleness).
fn is_daemon_stale(start_time: u64, deployed_mtime: Option<u64>, grace_secs: u64) -> bool {
    deployed_mtime.is_some_and(|m| m > start_time.saturating_add(grace_secs))
}

/// Whether the supervisor should re-exec into its own freshly built binary. True
/// only when the binary is stale AND we have not already re-execed into this
/// exact mtime. execve preserves the process start_time, so a stale supervisor
/// stays stale after re-exec; `reexeced_for_mtime` (the
/// `KIN_SUPERVISOR_REEXECED_FOR_MTIME` sentinel inherited across the exec) records
/// the mtime we last re-execed into, so a match means the fresh build is already
/// running and we must stop — otherwise the supervisor re-execs every sweep. A
/// later rebuild bumps the mtime past the sentinel, re-arming a single re-exec.
fn should_reexec_self(
    start_time: u64,
    self_exe_mtime: u64,
    grace_secs: u64,
    reexeced_for_mtime: Option<u64>,
) -> bool {
    is_daemon_stale(start_time, Some(self_exe_mtime), grace_secs)
        && reexeced_for_mtime != Some(self_exe_mtime)
}

/// Observed facts about one discovered repo daemon, fed to the classifier.
#[derive(Debug, Clone)]
struct DaemonObservation {
    pid: u32,
    repo_root: String,
    /// Reparented to init (ppid == 1): its launching CLI has exited.
    orphaned: bool,
    health: DaemonHealth,
    /// Consecutive sweeps this pid has been CPU-pinned.
    cpu_pinned_sweeps: u32,
    /// How this daemon relates to the registry entry for its repo root.
    registry: RegistryRelation,
    /// The deployed binary was rebuilt after this process started — it is running
    /// stale code and is a redeploy candidate.
    stale_binary: bool,
}

/// Decide what to do with a discovered daemon: reap a demonstrably-misbehaving
/// one, redeploy a healthy idle one running a stale binary, adopt a
/// healthy-but-invisible one to restore registry visibility, or keep it
/// untouched. Pure function over observed facts — the unit-tested core.
///
/// Invariants:
/// - A daemon doing real work (active clients or active reconciliation) is NEVER
///   reaped, even if unregistered — but it MAY still be adopted to restore
///   visibility (adoption never reaps).
/// - The safe reap criterion (orphaned + unhealthy) is always enabled.
/// - The CPU-pinned and duplicate-twin reap criteria are policy-gated.
/// - Reaping always wins over redeploy, which wins over adoption. The only
///   healthy reap path is the orphaned idle busy-spinner; a daemon matching it is
///   reaped, not redeployed or adopted.
/// - Only a HEALTHY, IDLE daemon running a stale binary is redeployed. An ACTIVE
///   stale daemon is deferred (never redeployed) — killing it would interrupt
///   live work; it rolls over once it goes idle. Redeploy is independent of
///   registry relation, so it wins over adoption for an idle stale daemon (no
///   point adopting one we are about to roll over).
/// - Adoption only ever targets a HEALTHY daemon with a non-empty repo root, and
///   never clobbers a live twin that owns the route (split-brain safety).
fn classify_daemon(obs: &DaemonObservation, policy: &ReapPolicy) -> DaemonDecision {
    // Absolute guard (#4): a daemon serving clients or actively reconciling is
    // never a reap candidate, regardless of registration or orphan status. It can
    // still fall through to the adoption path below to restore visibility.
    let active = matches!(
        &obs.health,
        DaemonHealth::Healthy(activity) if activity.has_clients || activity.reconciling
    );

    if !active {
        // (a) Safe criterion, always on: orphaned and its health probe failed.
        if obs.orphaned && obs.health == DaemonHealth::Unhealthy {
            return DaemonDecision::Reap(ReapReason::OrphanedUnhealthy);
        }

        // (c) Orphaned, IDLE duplicate twin of a registered, alive daemon on the
        //     same repo root. Split-brain safety: active twins were already
        //     excluded by the `!active` guard, so only the idle twin is reaped.
        if policy.duplicate_reap_enabled
            && obs.orphaned
            && obs.registry == RegistryRelation::LiveTwin
        {
            return DaemonDecision::Reap(ReapReason::DuplicateOrphanTwin);
        }

        // (b) Orphaned busy-spinner: healthy but idle (ensured by `!active`)
        //     and CPU-pinned across enough consecutive sweeps.
        if policy.cpu_heuristic_enabled
            && obs.orphaned
            && matches!(obs.health, DaemonHealth::Healthy(_))
            && obs.cpu_pinned_sweeps >= policy.cpu_pinned_min_sweeps
        {
            return DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients);
        }

        // Build-aware rolling redeploy: a healthy IDLE daemon (idleness ensured
        // by `!active`) running a stale binary is killed so it respawns on demand
        // into the fresh build. Reaped above first, so reap wins; placed before the
        // adopt block below, so redeploy wins over adoption for idle stale daemons.
        if policy.redeploy_enabled
            && obs.stale_binary
            && matches!(obs.health, DaemonHealth::Healthy(_))
        {
            return DaemonDecision::Redeploy(RedeployReason::StaleBinary);
        }
    }

    // Self-healing adoption: a HEALTHY daemon with a valid repo root that the
    // registry does not already track as itself becomes visible again. Recovers
    // after a supervisor restart that lost its in-memory registry while daemons
    // keep serving. Unhealthy/Unknown daemons are never adopted.
    if policy.adopt_enabled
        && matches!(obs.health, DaemonHealth::Healthy(_))
        && !obs.repo_root.trim().is_empty()
    {
        match obs.registry {
            RegistryRelation::Unregistered => {
                return DaemonDecision::Adopt(AdoptReason::Unregistered);
            }
            RegistryRelation::StaleDifferentPid => {
                return DaemonDecision::Adopt(AdoptReason::HealStaleEntry);
            }
            // Already tracked as itself, or a live twin owns the route: leave the
            // registry untouched. Never clobber a live twin — both stay alive.
            RegistryRelation::RegisteredSelf | RegistryRelation::LiveTwin => {}
        }
    }

    DaemonDecision::Keep
}

#[cfg(unix)]
fn spawn_rogue_daemon_reaper(
    state: Arc<SupervisorState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if env_flag_truthy("KIN_SUPERVISOR_REAP_DISABLE") {
        info!("rogue-daemon reaper disabled via KIN_SUPERVISOR_REAP_DISABLE");
        return;
    }
    let policy = ReapPolicy::from_env();
    info!(?policy, "rogue-daemon reaper enabled");
    tokio::spawn(async move {
        let self_pid = std::process::id();
        let client = reqwest::Client::new();
        let mut sys = sysinfo::System::new();
        // pid -> consecutive CPU-pinned sweep count.
        let mut pinned_sweeps: HashMap<u32, u32> = HashMap::new();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(REAPER_SWEEP_INTERVAL) => {}
                _ = shutdown_rx.changed() => break,
            }
            if *shutdown_rx.borrow() {
                break;
            }
            reaper_sweep(
                &state,
                &client,
                &mut sys,
                &mut pinned_sweeps,
                self_pid,
                policy,
            )
            .await;
        }
        info!("rogue-daemon reaper shutting down");
    });
}

#[cfg(not(unix))]
fn spawn_rogue_daemon_reaper(
    _state: Arc<SupervisorState>,
    _shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
}

/// One discovered repo-scoped daemon process from the machine-wide scan.
#[cfg(unix)]
struct DiscoveredDaemon {
    pid: u32,
    ppid: Option<u32>,
    repo_root: String,
    port: Option<u16>,
    cpu_usage: f32,
    /// Process start time, seconds since the Unix epoch.
    start_time: u64,
    /// Path to the executable image this process is running, if discoverable.
    exe_path: Option<std::path::PathBuf>,
}

#[cfg(unix)]
async fn reaper_sweep(
    state: &SupervisorState,
    client: &reqwest::Client,
    sys: &mut sysinfo::System,
    pinned_sweeps: &mut HashMap<u32, u32>,
    self_pid: u32,
    policy: ReapPolicy,
) {
    let discovered = enumerate_repo_daemons(sys, self_pid);

    // Supervisor self-identity, read from the just-refreshed process table: the
    // binary it is executing, that binary's mtime, and its own start_time. These
    // scope the redeploy decision to the supervisor's OWN build lineage so a
    // release supervisor never rolls over unrelated debug daemons (and vice versa).
    let self_proc = sys.process(sysinfo::Pid::from_u32(self_pid));
    let self_exe = self_proc.and_then(|p| p.exe()).map(|p| p.to_path_buf());
    let self_exe_mtime = self_exe.as_deref().and_then(file_mtime_secs);
    let self_start = self_proc.map(|p| p.start_time());

    // Self-re-exec: if the supervisor's own binary was rebuilt after it started,
    // replace its process image in place (same PID) with the fresh build before
    // touching any child. `reexec_self` only returns on failure; on error we log
    // and fall through to best-effort child redeploy on the still-running old image.
    if policy.reexec_enabled {
        if let (Some(start), Some(mtime)) = (self_start, self_exe_mtime) {
            let reexeced_for_mtime = std::env::var(SUPERVISOR_REEXECED_FOR_MTIME_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok());
            if should_reexec_self(start, mtime, policy.redeploy_grace_secs, reexeced_for_mtime) {
                warn!("supervisor binary is stale — re-execing into new build");
                let error = reexec_self(mtime);
                warn!(error = %error, "supervisor self-re-exec failed; continuing on current binary");
            }
        }
    }

    // Update CPU-pinned streaks; forget pids that vanished.
    let live_pids: HashSet<u32> = discovered.iter().map(|d| d.pid).collect();
    pinned_sweeps.retain(|pid, _| live_pids.contains(pid));
    for daemon in &discovered {
        let counter = pinned_sweeps.entry(daemon.pid).or_insert(0);
        if daemon.cpu_usage >= policy.cpu_pinned_percent {
            *counter = counter.saturating_add(1);
        } else {
            *counter = 0;
        }
    }

    // Snapshot the registry as canonical repo_root -> registered pid.
    let registry: HashMap<String, u32> = {
        let repos = state.repo_daemons.read().await;
        repos
            .values()
            .map(|d| (canonical_path_string(Path::new(&d.repo_root)), d.pid))
            .collect()
    };

    for daemon in &discovered {
        let health = match daemon.port {
            Some(port) => probe_daemon_health(client, port).await,
            None => DaemonHealth::Unknown,
        };
        // Classify this daemon's relationship to the registry entry (if any) for
        // its repo root: itself, a live twin, a stale (dead-pid) entry, or absent.
        let registry_relation = match registry.get(&daemon.repo_root) {
            None => RegistryRelation::Unregistered,
            Some(&registered_pid) if registered_pid == daemon.pid => {
                RegistryRelation::RegisteredSelf
            }
            Some(&registered_pid) if is_process_alive(registered_pid) => RegistryRelation::LiveTwin,
            Some(_) => RegistryRelation::StaleDifferentPid,
        };
        // Scope staleness to the supervisor's own binary lineage: only compare
        // against the deployed mtime when the child runs the SAME binary the
        // supervisor does. A child on a different build is never our redeploy
        // target (deployed_mtime stays None, so it is never stale).
        let deployed_mtime = if same_binary(daemon.exe_path.as_deref(), self_exe.as_deref()) {
            self_exe_mtime
        } else {
            None
        };
        let stale_binary = is_daemon_stale(
            daemon.start_time,
            deployed_mtime,
            policy.redeploy_grace_secs,
        );
        let observation = DaemonObservation {
            pid: daemon.pid,
            repo_root: daemon.repo_root.clone(),
            orphaned: daemon.ppid == Some(1),
            health,
            cpu_pinned_sweeps: pinned_sweeps.get(&daemon.pid).copied().unwrap_or(0),
            registry: registry_relation,
            stale_binary,
        };
        match classify_daemon(&observation, &policy) {
            DaemonDecision::Reap(reason) => {
                reap_daemon(&observation, reason).await;
                pinned_sweeps.remove(&daemon.pid);
            }
            DaemonDecision::Redeploy(reason) => {
                redeploy_daemon(&observation, reason).await;
                pinned_sweeps.remove(&daemon.pid);
            }
            DaemonDecision::Adopt(reason) => {
                adopt_daemon(state, daemon, reason).await;
            }
            DaemonDecision::Keep => {
                // Surface a persistent split-brain: two live daemons claim one
                // repo root and at least one is actively serving. We keep both
                // alive (never reap an active daemon) but the operator should know.
                if registry_relation == RegistryRelation::LiveTwin {
                    if let DaemonHealth::Healthy(activity) = &observation.health {
                        if activity.has_clients || activity.reconciling {
                            warn!(
                                pid = daemon.pid,
                                repo = %daemon.repo_root,
                                "two live daemons claim one repo_root; keeping both (split-brain) — not reaping active daemon"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Adopt a healthy, routable daemon into the registry so the supervisor can route
/// to it again. Restores visibility after a supervisor restart drops the in-memory
/// registry while daemons keep serving, or replaces a stale (dead-pid) entry with
/// the live daemon now serving the same repo root.
///
/// The synthesized `instance_id` matches what the daemon's own registration loop
/// produces (`pid-<pid>-port-<port>`), so the daemon's next heartbeat reconciles
/// with the adopted entry instead of conflicting with it.
#[cfg(unix)]
async fn adopt_daemon(state: &SupervisorState, daemon: &DiscoveredDaemon, reason: AdoptReason) {
    // A routable entry needs a port. Health is only `Healthy` when a port was
    // probed, so an Adopt decision implies `Some` here; guard defensively anyway.
    let Some(port) = daemon.port else {
        return;
    };
    let repo_root = daemon.repo_root.clone();
    let repo_id = repo_route_id_for_path(Path::new(&repo_root));
    let now = chrono::Utc::now().to_rfc3339();
    let heartbeat_ms = state.elapsed_ms();

    let mut repos = state.repo_daemons.write().await;
    // Re-check under the write lock: a fresh self-registration (or another live
    // daemon) may have raced in since the registry snapshot. Never clobber a live
    // entry owned by a different pid.
    if let Some(existing) = repos.get(&repo_id) {
        if existing.pid != daemon.pid && is_process_alive(existing.pid) {
            return;
        }
    }
    let record = RegisteredRepoDaemon {
        repo_id: repo_id.clone(),
        display_name: repo_display_name_for_path(Path::new(&repo_root)),
        instance_id: instance_id_for(daemon.pid, port),
        repo_root: repo_root.clone(),
        pid: daemon.pid,
        port,
        endpoint: format!("http://127.0.0.1:{port}"),
        graph_entity_count: None,
        registered_at: now.clone(),
        last_heartbeat_at: now,
        last_heartbeat_elapsed_ms: heartbeat_ms,
    };
    info!(
        pid = daemon.pid,
        repo = %repo_root,
        repo_id = %repo_id,
        reason = ?reason,
        "adopting healthy repo daemon into supervisor registry"
    );
    repos.insert(repo_id, record);
}

/// Enumerate repo-scoped kin-daemon processes (those with `--repo`), excluding
/// the supervisor itself and the current process.
#[cfg(unix)]
fn enumerate_repo_daemons(sys: &mut sysinfo::System, self_pid: u32) -> Vec<DiscoveredDaemon> {
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut found = Vec::new();
    for (pid, process) in sys.processes() {
        let pid = pid.as_u32();
        if pid == self_pid {
            continue;
        }
        let args: Vec<&str> = process
            .cmd()
            .iter()
            .filter_map(|arg| arg.to_str())
            .collect();
        let name = process.name().to_str().unwrap_or_default();
        let looks_like_daemon = name.contains("kin-daemon")
            || args.first().is_some_and(|arg| arg.contains("kin-daemon"));
        if !looks_like_daemon {
            continue;
        }
        if args.iter().any(|arg| *arg == "--supervisor") {
            continue;
        }
        let Some(repo_root) = arg_value(&args, "--repo") else {
            continue;
        };
        let port = arg_value(&args, "--port").and_then(|value| value.parse::<u16>().ok());
        found.push(DiscoveredDaemon {
            pid,
            ppid: process.parent().map(|parent| parent.as_u32()),
            repo_root: canonical_path_string(Path::new(repo_root)),
            port,
            cpu_usage: process.cpu_usage(),
            start_time: process.start_time(),
            exe_path: process.exe().map(|p| p.to_path_buf()),
        });
    }
    found
}

/// Extract a CLI flag value, supporting both `--flag value` and `--flag=value`.
#[cfg(unix)]
fn arg_value<'a>(args: &'a [&'a str], flag: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if *arg == flag {
            return iter.next().copied();
        }
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}

/// Modification time of `path` as whole seconds since the Unix epoch. `None` if
/// the file is unreadable or has an unrepresentable timestamp.
#[cfg(unix)]
fn file_mtime_secs(path: &std::path::Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Whether two executable paths resolve to the same on-disk binary, comparing by
/// canonicalized path (falling back to the raw path when canonicalization fails).
/// `None` on either side is treated as "not the same binary".
#[cfg(unix)]
fn same_binary(a: Option<&std::path::Path>, b: Option<&std::path::Path>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let ca = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
            let cb = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
            ca == cb
        }
        _ => false,
    }
}

/// Probe a repo daemon's unauthenticated `/health` endpoint and classify it.
#[cfg(unix)]
async fn probe_daemon_health(client: &reqwest::Client, port: u16) -> DaemonHealth {
    let url = format!("http://127.0.0.1:{port}/health");
    let response = match client
        .get(&url)
        .timeout(REAPER_HEALTH_PROBE_TIMEOUT)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response,
        Ok(_) => return DaemonHealth::Unhealthy,
        Err(_) => return DaemonHealth::Unhealthy,
    };
    let Ok(body) = response.json::<serde_json::Value>().await else {
        return DaemonHealth::Unhealthy;
    };
    let count = |key: &str| {
        body.get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let has_clients = count("active_request_count")
        + count("event_subscriber_count")
        + count("external_session_count")
        > 0;
    let reconciling = body
        .get("reconciliation_status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|status| !status.eq_ignore_ascii_case("idle"));
    DaemonHealth::Healthy(DaemonActivity {
        has_clients,
        reconciling,
    })
}

/// Gracefully terminate a daemon: SIGTERM, then SIGKILL if it survives the grace
/// window. Shared by reaping (misbehaving daemons) and redeploy (stale idle
/// daemons that respawn on demand). `action` names the intent for the logs.
#[cfg(unix)]
async fn graceful_terminate(pid: u32, repo_root: &str, action: &str, reason: &str) {
    warn!(
        pid,
        repo = %repo_root,
        reason,
        "{action} (SIGTERM)"
    );
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let start = Instant::now();
    while start.elapsed() < REAPER_SIGTERM_GRACE {
        if !is_process_alive(pid) {
            info!(
                pid,
                repo = %repo_root,
                "daemon exited gracefully after SIGTERM"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if is_process_alive(pid) {
        warn!(
            pid,
            repo = %repo_root,
            reason,
            "daemon survived SIGTERM grace — sending SIGKILL"
        );
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

/// Reap a daemon: graceful SIGTERM, then SIGKILL if it survives the grace window.
#[cfg(unix)]
async fn reap_daemon(observation: &DaemonObservation, reason: ReapReason) {
    graceful_terminate(
        observation.pid,
        &observation.repo_root,
        "reaping misbehaving repo daemon",
        &format!("{reason:?}"),
    )
    .await;
}

/// Redeploy a stale idle daemon: terminate it so it respawns on demand into the
/// fresh build. Uses the same graceful ladder as reaping.
#[cfg(unix)]
async fn redeploy_daemon(observation: &DaemonObservation, reason: RedeployReason) {
    graceful_terminate(
        observation.pid,
        &observation.repo_root,
        "redeploying stale repo daemon",
        &format!("{reason:?}"),
    )
    .await;
}

/// Replace the supervisor's process image in place (same PID) with a fresh exec
/// of its own binary and original arguments. On success this never returns; the
/// returned `io::Error` is the exec failure. Loop-free: execve preserves the
/// process start_time, so the re-execed image stays stale against `self_exe_mtime`
/// — to avoid re-execing every sweep we stamp `self_exe_mtime` into the
/// `KIN_SUPERVISOR_REEXECED_FOR_MTIME` sentinel, which the fresh process inherits
/// and `should_reexec_self` reads to skip a redundant re-exec.
#[cfg(unix)]
fn reexec_self(self_exe_mtime: u64) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return error,
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::Command::new(exe)
        .args(args)
        .env(
            SUPERVISOR_REEXECED_FOR_MTIME_ENV,
            self_exe_mtime.to_string(),
        )
        .exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_payload(instance_id: &str, port: u16) -> RepoDaemonRegistration {
        RepoDaemonRegistration {
            repo_id: "demo".to_string(),
            display_name: "demo".to_string(),
            instance_id: instance_id.to_string(),
            repo_root: "/tmp/demo".to_string(),
            pid: std::process::id(),
            port,
            endpoint: format!("http://127.0.0.1:{port}"),
            graph_entity_count: Some(12),
        }
    }

    fn old_supervisor_state() -> Arc<SupervisorState> {
        Arc::new(SupervisorState {
            started_at: Instant::now() - HEARTBEAT_TTL - Duration::from_millis(100),
            last_activity_ms: AtomicU64::new(0),
            repo_daemons: RwLock::new(BTreeMap::new()),
        })
    }

    async fn register_repo(
        app: Router,
        payload: &RepoDaemonRegistration,
    ) -> axum::response::Response {
        tower::ServiceExt::oneshot(
            app,
            axum::http::Request::post("/daemons/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn force_stale_route(state: &SupervisorState, repo_id: &str) {
        let mut repos = state.repo_daemons.write().await;
        repos.get_mut(repo_id).unwrap().last_heartbeat_elapsed_ms = 0;
    }

    #[tokio::test]
    async fn supervisor_register_route_and_deregister() {
        let state = Arc::new(SupervisorState::new());
        let payload = repo_payload("instance-a", 49152);

        let app = router(Arc::clone(&state));
        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::get("/repos/demo/route")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::delete("/daemons/demo?instance_id=instance-a")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.repo_daemons.read().await.is_empty());
    }

    #[tokio::test]
    async fn supervisor_register_rejects_conflicting_live_instance() {
        let state = Arc::new(SupervisorState::new());
        let payload = repo_payload("instance-a", 49152);
        let conflicting = RepoDaemonRegistration {
            instance_id: "instance-b".to_string(),
            port: 49153,
            endpoint: "http://127.0.0.1:49153".to_string(),
            ..payload.clone()
        };

        let app = router(Arc::clone(&state));
        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = register_repo(app, &conflicting).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let repos = state.repo_daemons.read().await;
        let registered = repos.get("demo").unwrap();
        assert_eq!(registered.instance_id, "instance-a");
        assert_eq!(registered.endpoint, "http://127.0.0.1:49152");
    }

    #[tokio::test]
    async fn supervisor_register_replaces_stale_conflicting_instance() {
        let state = old_supervisor_state();
        let payload = repo_payload("instance-a", 49152);
        let replacement = RepoDaemonRegistration {
            instance_id: "instance-b".to_string(),
            port: 49153,
            endpoint: "http://127.0.0.1:49153".to_string(),
            graph_entity_count: Some(24),
            ..payload.clone()
        };

        let app = router(Arc::clone(&state));
        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        force_stale_route(&state, "demo").await;

        let response = register_repo(app, &replacement).await;
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        let registered = repos.get("demo").unwrap();
        assert_eq!(registered.instance_id, "instance-b");
        assert_eq!(registered.endpoint, "http://127.0.0.1:49153");
        assert_eq!(registered.graph_entity_count, Some(24));
    }

    #[tokio::test]
    async fn supervisor_deregister_ignores_wrong_or_missing_instance() {
        let state = Arc::new(SupervisorState::new());
        let payload = repo_payload("instance-a", 49152);

        let app = router(Arc::clone(&state));
        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::delete("/daemons/demo?instance_id=instance-b")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.repo_daemons.read().await.contains_key("demo"));

        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::delete("/daemons/demo")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        let registered = repos.get("demo").unwrap();
        assert_eq!(registered.instance_id, "instance-a");
    }

    #[tokio::test]
    async fn supervisor_route_list_and_health_prune_stale_routes() {
        let state = old_supervisor_state();
        let payload = repo_payload("instance-a", 49152);
        let app = router(Arc::clone(&state));

        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        force_stale_route(&state, "demo").await;
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::get("/repos/demo/route")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(state.repo_daemons.read().await.is_empty());

        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        force_stale_route(&state, "demo").await;
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::get("/repos")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.repo_daemons.read().await.is_empty());

        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        force_stale_route(&state, "demo").await;
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::get("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.repo_daemons.read().await.is_empty());
    }

    #[tokio::test]
    async fn supervisor_heartbeat_refreshes_route_before_ttl_prune() {
        let state = old_supervisor_state();
        let payload = repo_payload("instance-a", 49152);
        let refreshed = RepoDaemonRegistration {
            graph_entity_count: Some(99),
            ..payload.clone()
        };

        let app = router(Arc::clone(&state));
        let response = register_repo(app.clone(), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        let previous_heartbeat = {
            let repos = state.repo_daemons.read().await;
            repos.get("demo").unwrap().last_heartbeat_elapsed_ms
        };

        tokio::time::sleep(Duration::from_millis(2)).await;
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::post("/daemons/demo/heartbeat")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&refreshed).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        let registered = repos.get("demo").unwrap();
        assert!(registered.last_heartbeat_elapsed_ms > previous_heartbeat);
        assert_eq!(registered.graph_entity_count, Some(99));
    }

    /// Default observation: an already-registered daemon (the neutral case that
    /// triggers neither reaping nor adoption). Individual tests override
    /// `registry` to exercise the unregistered/stale/twin paths.
    fn observation(health: DaemonHealth, orphaned: bool) -> DaemonObservation {
        DaemonObservation {
            pid: 4242,
            repo_root: "/tmp/demo".to_string(),
            orphaned,
            health,
            cpu_pinned_sweeps: 0,
            registry: RegistryRelation::RegisteredSelf,
            stale_binary: false,
        }
    }

    fn healthy(has_clients: bool, reconciling: bool) -> DaemonHealth {
        DaemonHealth::Healthy(DaemonActivity {
            has_clients,
            reconciling,
        })
    }

    #[test]
    fn reaper_never_reaps_daemon_with_active_clients() {
        // Active clients win over every reap criterion. Even a live twin claiming
        // the same repo root is kept (split-brain safety: never reap an active
        // daemon, and never clobber the live twin that owns the route).
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(true, false), true);
        obs.cpu_pinned_sweeps = 10;
        obs.registry = RegistryRelation::LiveTwin;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_never_reaps_reconciling_daemon() {
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, true), true);
        obs.cpu_pinned_sweeps = 10;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_orphaned_unhealthy_by_default() {
        let policy = ReapPolicy::default();
        let obs = observation(DaemonHealth::Unhealthy, true);
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedUnhealthy)
        );
    }

    #[test]
    fn reaper_keeps_non_orphaned_unhealthy() {
        // A daemon with a live parent (not reparented to init) is left alone
        // even if its health probe momentarily fails.
        let policy = ReapPolicy::default();
        let obs = observation(DaemonHealth::Unhealthy, false);
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_orphaned_idle_cpu_spinner() {
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = REAPER_DEFAULT_CPU_PINNED_SWEEPS;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients)
        );
    }

    #[test]
    fn reaper_keeps_spinner_below_sweep_threshold() {
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = REAPER_DEFAULT_CPU_PINNED_SWEEPS - 1;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_keeps_spinner_when_cpu_heuristic_disabled() {
        let policy = ReapPolicy {
            cpu_heuristic_enabled: false,
            ..ReapPolicy::default()
        };
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = 99;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_keeps_non_orphaned_cpu_spinner() {
        // Busy but with a live parent: not a runaway orphan, leave it alone.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), false);
        obs.cpu_pinned_sweeps = 99;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_orphaned_duplicate_twin() {
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unknown, true);
        obs.registry = RegistryRelation::LiveTwin;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::DuplicateOrphanTwin)
        );
    }

    #[test]
    fn reaper_keeps_duplicate_twin_when_disabled() {
        let policy = ReapPolicy {
            duplicate_reap_enabled: false,
            ..ReapPolicy::default()
        };
        let mut obs = observation(DaemonHealth::Unknown, true);
        obs.registry = RegistryRelation::LiveTwin;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_keeps_unknown_health_without_twin() {
        // Orphaned but unprobeable and not a duplicate — a healthy persistent
        // daemon is orphaned by design, so default to keep.
        let policy = ReapPolicy::default();
        let obs = observation(DaemonHealth::Unknown, true);
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_keeps_healthy_registered_daemon() {
        // The registered (RegisteredSelf), healthy, idle daemon itself: not a
        // reap candidate and already tracked, so neither reaped nor adopted.
        let policy = ReapPolicy::default();
        let obs = observation(healthy(false, false), true);
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_adopts_unregistered_healthy_daemon() {
        // Healthy daemon serving but absent from the registry (e.g. supervisor
        // restarted and lost its in-memory map): adopt to restore visibility.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Adopt(AdoptReason::Unregistered)
        );
    }

    #[test]
    fn reaper_adopts_unregistered_healthy_daemon_even_when_not_orphaned() {
        // Orphan status only gates reaping, not adoption: a live-parented healthy
        // daemon missing from the registry is still adopted.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), false);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Adopt(AdoptReason::Unregistered)
        );
    }

    #[test]
    fn reaper_adopts_active_unregistered_daemon() {
        // An active (serving) unregistered daemon is adopted, never reaped: the
        // active guard blocks reaping while adoption restores its route.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(true, false), true);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Adopt(AdoptReason::Unregistered)
        );
    }

    #[test]
    fn reaper_heals_stale_dead_registry_entry() {
        // Registry entry for this repo root names a dead pid; the live healthy
        // daemon serving the same root replaces it.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::StaleDifferentPid;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Adopt(AdoptReason::HealStaleEntry)
        );
    }

    #[test]
    fn reaper_keeps_already_registered_healthy_daemon() {
        // Already tracked as itself: no adoption (idempotent), no reaping.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::RegisteredSelf;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_does_not_adopt_unhealthy_daemon() {
        // Unhealthy, unregistered, but NOT orphaned: not adopted (adoption needs
        // a healthy probe) and not reaped (reaping needs orphan + unhealthy).
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unhealthy, false);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_does_not_adopt_unknown_health_daemon() {
        // Unknown health (no probeable port): never adopted, even if unregistered.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unknown, true);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_rather_than_adopts_orphaned_unhealthy_unregistered() {
        // Reaping wins over adoption: an orphaned, unhealthy, unregistered daemon
        // is reaped (and unhealthy is not adoptable anyway).
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unhealthy, true);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedUnhealthy)
        );
    }

    #[test]
    fn reaper_reaps_rather_than_adopts_orphaned_idle_spinner_unregistered() {
        // Reaping wins over adoption for the one healthy reap path: an orphaned,
        // idle, CPU-pinned unregistered daemon is reaped, not adopted.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::Unregistered;
        obs.cpu_pinned_sweeps = REAPER_DEFAULT_CPU_PINNED_SWEEPS;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients)
        );
    }

    #[test]
    fn reaper_does_not_adopt_when_disabled() {
        let policy = ReapPolicy {
            adopt_enabled: false,
            ..ReapPolicy::default()
        };
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::Unregistered;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_does_not_adopt_empty_repo_root() {
        // A valid repo root is required to synthesize a routable registration.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::Unregistered;
        obs.repo_root = String::new();
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_keeps_idle_live_twin_when_duplicate_reap_disabled() {
        // Idle orphaned live twin, but duplicate reap disabled: not reaped, and a
        // live twin owns the route so it is not adopted either.
        let policy = ReapPolicy {
            duplicate_reap_enabled: false,
            ..ReapPolicy::default()
        };
        let mut obs = observation(healthy(false, false), true);
        obs.registry = RegistryRelation::LiveTwin;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reap_policy_defaults_enable_all_criteria() {
        let policy = ReapPolicy::default();
        assert!(policy.cpu_heuristic_enabled);
        assert!(policy.duplicate_reap_enabled);
        assert!(policy.adopt_enabled);
        assert_eq!(
            policy.cpu_pinned_min_sweeps,
            REAPER_DEFAULT_CPU_PINNED_SWEEPS
        );
        assert_eq!(policy.cpu_pinned_percent, REAPER_DEFAULT_CPU_PINNED_PERCENT);
    }

    #[test]
    fn reap_policy_defaults_enable_redeploy_and_reexec() {
        let policy = ReapPolicy::default();
        assert!(policy.redeploy_enabled);
        assert!(policy.reexec_enabled);
        assert_eq!(policy.redeploy_grace_secs, REDEPLOY_DEFAULT_GRACE_SECS);
    }

    #[test]
    fn stale_when_binary_newer_than_start_plus_grace() {
        // mtime strictly past start + grace: rebuilt after the process started.
        assert!(is_daemon_stale(100, Some(103), 2));
    }

    #[test]
    fn not_stale_at_exact_grace_boundary() {
        // mtime == start + grace is the exclusive boundary: not yet stale.
        assert!(!is_daemon_stale(100, Some(102), 2));
    }

    #[test]
    fn not_stale_when_binary_older_than_start() {
        // The running process is newer than the on-disk binary: never stale.
        assert!(!is_daemon_stale(100, Some(50), 2));
    }

    #[test]
    fn not_stale_when_deployed_mtime_unknown() {
        // Staleness cannot be proven without a deployed mtime.
        assert!(!is_daemon_stale(100, None, 2));
    }

    #[test]
    fn grace_shifts_staleness_boundary() {
        // Same start/mtime: stale under a small grace, absorbed by a larger one.
        assert!(is_daemon_stale(100, Some(105), 2));
        assert!(!is_daemon_stale(100, Some(105), 5));
        assert!(!is_daemon_stale(100, Some(105), 10));
    }

    #[test]
    fn reexec_when_stale_and_no_sentinel() {
        // First encounter of a fresh build: stale, sentinel absent -> re-exec.
        assert!(should_reexec_self(100, 105, 2, None));
    }

    #[test]
    fn no_reexec_when_sentinel_matches_current_mtime() {
        // Loop break: execve preserved start_time so we are still stale, but the
        // sentinel proves we already re-execed into this exact build -> stop.
        assert!(!should_reexec_self(100, 105, 2, Some(105)));
    }

    #[test]
    fn reexec_again_after_a_newer_rebuild() {
        // A later rebuild bumps the mtime past the sentinel -> re-arm one re-exec.
        assert!(should_reexec_self(100, 110, 2, Some(105)));
    }

    #[test]
    fn no_reexec_when_not_stale_regardless_of_sentinel() {
        // Binary not newer than start + grace: never re-exec, sentinel or not.
        assert!(!should_reexec_self(100, 101, 2, None));
        assert!(!should_reexec_self(100, 101, 2, Some(50)));
    }

    #[test]
    fn redeploy_healthy_idle_stale_daemon() {
        // (a) The core case: healthy, idle, stale binary -> rolled over.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), false);
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Redeploy(RedeployReason::StaleBinary)
        );
    }

    #[test]
    fn does_not_redeploy_active_stale_daemon() {
        // (b) An active (serving) stale daemon is deferred: killing it would
        // interrupt live work. RegisteredSelf -> neither reaped, redeployed, nor
        // adopted; it rolls over once it goes idle.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(true, false), false);
        obs.stale_binary = true;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn active_stale_unregistered_is_adopted_not_redeployed() {
        // (b) An active stale daemon is never redeployed, but an unregistered one
        // is still adopted to restore its route.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(true, false), false);
        obs.registry = RegistryRelation::Unregistered;
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Adopt(AdoptReason::Unregistered)
        );
    }

    #[test]
    fn reap_wins_over_redeploy_for_orphaned_unhealthy_stale() {
        // (c) Reaping precedence: an orphaned, unhealthy, stale daemon is reaped.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unhealthy, true);
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedUnhealthy)
        );
    }

    #[test]
    fn reap_wins_over_redeploy_for_orphaned_idle_spinner_stale() {
        // (c) Reaping precedence on the one healthy reap path: an orphaned, idle,
        // CPU-pinned, stale daemon is reaped, not redeployed.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = REAPER_DEFAULT_CPU_PINNED_SWEEPS;
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients)
        );
    }

    #[test]
    fn does_not_redeploy_when_disabled() {
        // (d) Redeploy gated off: a healthy idle stale daemon is left alone.
        let policy = ReapPolicy {
            redeploy_enabled: false,
            ..ReapPolicy::default()
        };
        let mut obs = observation(healthy(false, false), false);
        obs.stale_binary = true;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn does_not_redeploy_unhealthy_stale_daemon() {
        // (e) Redeploy requires a healthy probe; an unhealthy (non-orphan) stale
        // daemon is kept (and is not reapable: reaping needs orphan + unhealthy).
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unhealthy, false);
        obs.stale_binary = true;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn redeploy_independent_of_registry_registered_self() {
        // (f) Redeploy ignores registry relation: a healthy idle stale daemon
        // already tracked as itself is still rolled over.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), false);
        obs.registry = RegistryRelation::RegisteredSelf;
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Redeploy(RedeployReason::StaleBinary)
        );
    }

    #[test]
    fn redeploy_wins_over_adopt_for_unregistered_idle_stale() {
        // (g) Redeploy precedence over adoption: no point adopting an idle stale
        // daemon we are about to roll over.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), false);
        obs.registry = RegistryRelation::Unregistered;
        obs.stale_binary = true;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Redeploy(RedeployReason::StaleBinary)
        );
    }

    #[cfg(unix)]
    #[test]
    fn same_binary_true_for_equal_paths() {
        let path = std::path::Path::new("/usr/bin/kin-daemon");
        assert!(same_binary(Some(path), Some(path)));
    }

    #[cfg(unix)]
    #[test]
    fn same_binary_false_for_different_paths() {
        assert!(!same_binary(
            Some(std::path::Path::new("/usr/bin/kin-daemon")),
            Some(std::path::Path::new("/usr/local/bin/kin-daemon")),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn same_binary_false_when_either_side_is_none() {
        let path = std::path::Path::new("/usr/bin/kin-daemon");
        assert!(!same_binary(None, Some(path)));
        assert!(!same_binary(Some(path), None));
        assert!(!same_binary(None, None));
    }

    // ===== Control-plane hardening =====

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Serialize tests that mutate process-global `KIN_SUPERVISOR_*` env so they
    /// cannot race. Shares one lock with every other env-mutating test in this
    /// binary (see `crate::test_env_lock`).
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock()
    }

    #[tokio::test]
    async fn supervisor_host_and_origin_allowlist_validation() {
        // Loopback Host/Origin pass; a forged Host, a cross-origin Origin, and a
        // null Origin are all rejected — the same policy as the repo daemon.
        let app = router(Arc::new(SupervisorState::new()));

        let ok = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "127.0.0.1:7421")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let forged_host = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "attacker.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forged_host.status(), StatusCode::FORBIDDEN);

        let cross_origin = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://attacker.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);

        let loopback_origin = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "http://localhost:7421")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(loopback_origin.status(), StatusCode::OK);

        let null_origin = app
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "null")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(null_origin.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn supervisor_host_header_required_on_non_public_routes() {
        // Exercise the production missing-Host guard directly: a minimal router
        // with ONLY `validate_host_and_origin` (no cfg(test) loopback-Host
        // injector). A raw-socket client that omits Host to dodge the allowlist
        // must be rejected on sensitive routes, while public liveness routes
        // stay reachable for health probes.
        let app = Router::new()
            .route("/repos", get(|| async { StatusCode::OK }))
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(validate_host_and_origin));

        let rejected = app
            .clone()
            .oneshot(Request::get("/repos").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        let with_host = app
            .oneshot(
                Request::get("/repos")
                    .header(header::HOST, "127.0.0.1:7421")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(with_host.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn supervisor_bearer_token_protects_control_routes() {
        // With a token enforced: a tokenless / wrong-token request to a control
        // route is 401 (with a Bearer challenge); the matching token passes; and
        // public liveness routes stay reachable without any token.
        let token = "supervisor-secret-token";
        let app = router_with_auth(Arc::new(SupervisorState::new()), Some(token.to_string()));

        let missing = app
            .clone()
            .oneshot(Request::get("/repos").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer realm=\"kin supervisor\"")
        );

        let wrong = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::AUTHORIZATION, "Bearer not-the-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let ok = app
            .clone()
            .oneshot(
                Request::get("/repos")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // Public liveness route reachable without a token.
        let health = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn supervisor_no_token_means_no_auth_required() {
        // Default (no token enforced): control routes are reachable without a
        // bearer token — this is what keeps the normal local flow working. The
        // Host/Origin guard still applies (covered above).
        let app = router(Arc::new(SupervisorState::new()));
        let res = app
            .oneshot(Request::get("/repos").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn supervisor_is_host_allowed_honors_bind_host_env() {
        let _env = env_test_lock();
        std::env::remove_var("KIN_SUPERVISOR_BIND_HOST");

        // Loopback always allowed; arbitrary hosts rejected by default.
        assert!(is_host_allowed("127.0.0.1"));
        assert!(is_host_allowed("localhost"));
        assert!(is_host_allowed("::1"));
        assert!(!is_host_allowed("attacker.com"));
        assert!(!is_host_allowed("10.0.0.5"));

        // An explicit non-loopback bind host is allowed only for that host.
        std::env::set_var("KIN_SUPERVISOR_BIND_HOST", "10.0.0.5");
        assert!(is_host_allowed("10.0.0.5"));
        assert!(!is_host_allowed("attacker.com"));

        // A wildcard bind allows any host (operator opted into exposure).
        std::env::set_var("KIN_SUPERVISOR_BIND_HOST", "0.0.0.0");
        assert!(is_host_allowed("attacker.com"));

        std::env::remove_var("KIN_SUPERVISOR_BIND_HOST");
    }

    #[test]
    fn supervisor_host_without_port_handles_ipv6() {
        assert_eq!(host_without_port("127.0.0.1:7421"), "127.0.0.1");
        assert_eq!(host_without_port("localhost"), "localhost");
        assert_eq!(host_without_port("[::1]:7421"), "::1");
        assert_eq!(host_without_port("[::1]"), "::1");
    }

    #[tokio::test]
    async fn supervisor_loopback_token_provisioned_persisted_and_enforced() {
        let _env = env_test_lock();
        std::env::remove_var("KIN_SUPERVISOR_AUTH_TOKEN");
        std::env::remove_var("KIN_SUPERVISOR_REQUIRE_TOKEN");

        // Hermetic per-test supervisor directory, passed explicitly to the token
        // helpers so the assertions never depend on the process-global
        // `KIN_REGISTRY_PATH` (which other tests in this binary mutate
        // concurrently). Mirrors `api::resolve_serve_auth_token_gates_enforcement`.
        let dir = std::env::temp_dir().join(format!("kin-supervisor-token-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // First provisioning persists a token; re-provisioning returns the SAME
        // token (mode 0600 on unix).
        let token = ensure_loopback_token(&dir).unwrap();
        assert!(!token.is_empty());
        assert_eq!(ensure_loopback_token(&dir).unwrap(), token);
        let on_disk = std::fs::read_to_string(supervisor_token_path(&dir)).unwrap();
        assert_eq!(on_disk.trim(), token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(supervisor_token_path(&dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "supervisor token file must be 0600");
        }

        // Default: enforcement OFF — the file is provisioned but not required, so
        // existing unauthenticated local clients keep working.
        assert!(resolve_serve_auth_token(&dir).is_none());

        // Opt-in via KIN_SUPERVISOR_REQUIRE_TOKEN returns the provisioned token.
        std::env::set_var("KIN_SUPERVISOR_REQUIRE_TOKEN", "1");
        assert_eq!(
            resolve_serve_auth_token(&dir).as_deref(),
            Some(token.as_str())
        );

        // An explicit KIN_SUPERVISOR_AUTH_TOKEN override always wins.
        std::env::set_var("KIN_SUPERVISOR_AUTH_TOKEN", "explicit-override");
        assert_eq!(
            resolve_serve_auth_token(&dir).as_deref(),
            Some("explicit-override")
        );

        std::env::remove_var("KIN_SUPERVISOR_AUTH_TOKEN");
        std::env::remove_var("KIN_SUPERVISOR_REQUIRE_TOKEN");
    }
}
