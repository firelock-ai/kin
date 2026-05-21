// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Central local daemon supervisor.
//!
//! The supervisor is intentionally not a graph authority. It owns process
//! discovery and routing for repo-scoped graph daemons, while each repo daemon
//! remains the single writer for its repo graph.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::state::DaemonState;

const SUPERVISOR_PID_FILE: &str = "supervisor.pid";
const SUPERVISOR_PORT_FILE: &str = "supervisor.port";
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
    let _ = std::fs::write(supervisor_port_path(), port.to_string());
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

pub fn router(state: Arc<SupervisorState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/repos", get(list_repos))
        .route("/repos/{repo_id}/route", get(route_repo))
        .route("/daemons", get(list_repos))
        .route("/daemons/register", post(register_daemon))
        .route("/daemons/{repo_id}/heartbeat", post(heartbeat_daemon))
        .route("/daemons/{repo_id}", delete(deregister_daemon))
        .with_state(state)
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
    let result = axum::serve(listener, router(state))
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
}
