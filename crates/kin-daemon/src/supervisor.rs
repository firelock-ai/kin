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
}

/// Which heuristics beyond the always-on safe criterion are enabled, and how the
/// CPU heuristic is tuned. Controlled by `KIN_SUPERVISOR_REAP_*`.
#[derive(Debug, Clone, Copy)]
struct ReapPolicy {
    cpu_heuristic_enabled: bool,
    duplicate_reap_enabled: bool,
    /// Self-healing adoption of healthy-but-invisible daemons. On by default.
    adopt_enabled: bool,
    cpu_pinned_percent: f32,
    cpu_pinned_min_sweeps: u32,
}

impl Default for ReapPolicy {
    fn default() -> Self {
        Self {
            cpu_heuristic_enabled: true,
            duplicate_reap_enabled: true,
            adopt_enabled: true,
            cpu_pinned_percent: REAPER_DEFAULT_CPU_PINNED_PERCENT,
            cpu_pinned_min_sweeps: REAPER_DEFAULT_CPU_PINNED_SWEEPS,
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
}

/// Decide what to do with a discovered daemon: reap a demonstrably-misbehaving
/// one, adopt a healthy-but-invisible one to restore registry visibility, or keep
/// it untouched. Pure function over observed facts — the unit-tested core.
///
/// Invariants:
/// - A daemon doing real work (active clients or active reconciliation) is NEVER
///   reaped, even if unregistered — but it MAY still be adopted to restore
///   visibility (adoption never reaps).
/// - The safe reap criterion (orphaned + unhealthy) is always enabled.
/// - The CPU-pinned and duplicate-twin reap criteria are policy-gated.
/// - Reaping always wins over adoption. The only healthy reap path is the
///   orphaned idle busy-spinner; a daemon matching it is reaped, not adopted.
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

        // (b) Orphaned busy-spinner: healthy but idle (guaranteed by `!active`)
        //     and CPU-pinned across enough consecutive sweeps.
        if policy.cpu_heuristic_enabled
            && obs.orphaned
            && matches!(obs.health, DaemonHealth::Healthy(_))
            && obs.cpu_pinned_sweeps >= policy.cpu_pinned_min_sweeps
        {
            return DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients);
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
            reaper_sweep(&state, &client, &mut sys, &mut pinned_sweeps, self_pid, policy).await;
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
            Some(&registered_pid) if is_process_alive(registered_pid) => {
                RegistryRelation::LiveTwin
            }
            Some(_) => RegistryRelation::StaleDifferentPid,
        };
        let observation = DaemonObservation {
            pid: daemon.pid,
            repo_root: daemon.repo_root.clone(),
            orphaned: daemon.ppid == Some(1),
            health,
            cpu_pinned_sweeps: pinned_sweeps.get(&daemon.pid).copied().unwrap_or(0),
            registry: registry_relation,
        };
        match classify_daemon(&observation, &policy) {
            DaemonDecision::Reap(reason) => {
                reap_daemon(&observation, reason).await;
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
        let args: Vec<&str> = process.cmd().iter().filter_map(|arg| arg.to_str()).collect();
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
    let count = |key: &str| body.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let has_clients =
        count("active_request_count") + count("event_subscriber_count") + count("external_session_count")
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

/// Reap a daemon: graceful SIGTERM, then SIGKILL if it survives the grace window.
#[cfg(unix)]
async fn reap_daemon(observation: &DaemonObservation, reason: ReapReason) {
    warn!(
        pid = observation.pid,
        repo = %observation.repo_root,
        reason = ?reason,
        "reaping misbehaving repo daemon (SIGTERM)"
    );
    unsafe {
        libc::kill(observation.pid as libc::pid_t, libc::SIGTERM);
    }
    let start = Instant::now();
    while start.elapsed() < REAPER_SIGTERM_GRACE {
        if !is_process_alive(observation.pid) {
            info!(
                pid = observation.pid,
                repo = %observation.repo_root,
                "reaped daemon exited gracefully after SIGTERM"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if is_process_alive(observation.pid) {
        warn!(
            pid = observation.pid,
            repo = %observation.repo_root,
            reason = ?reason,
            "daemon survived SIGTERM grace — sending SIGKILL"
        );
        unsafe {
            libc::kill(observation.pid as libc::pid_t, libc::SIGKILL);
        }
    }
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
        assert_eq!(policy.cpu_pinned_min_sweeps, REAPER_DEFAULT_CPU_PINNED_SWEEPS);
        assert_eq!(policy.cpu_pinned_percent, REAPER_DEFAULT_CPU_PINNED_PERCENT);
    }
}
