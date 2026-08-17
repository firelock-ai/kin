// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Central local daemon supervisor.
//!
//! The supervisor is intentionally not a graph authority. It owns process
//! discovery and routing for repo-scoped graph daemons, while each repo daemon
//! remains the single writer for its repo graph.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::{HashMap, HashSet};
use std::io::{Seek, SeekFrom, Write};
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
use axum::{Extension, Json, Router};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::state::DaemonState;

const SUPERVISOR_PID_FILE: &str = "supervisor.pid";
const SUPERVISOR_PORT_FILE: &str = "supervisor.port";
const SUPERVISOR_OWNER_FILE: &str = "supervisor.owner";
const SUPERVISOR_TOKEN_FILE: &str = "supervisor.token";
const SUPERVISOR_LIFECYCLE_FILE: &str = "supervisor.lifecycle";
const SUPERVISOR_SINGLETON_FILE: &str = "supervisor.lock";
const SUPERVISOR_LIFECYCLE_BUDGET: Duration = Duration::from_secs(5);
const SUPERVISOR_LIFECYCLE_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TTL: Duration = Duration::from_secs(20);
/// Ceiling for the retry backoff a repo daemon applies while it cannot reach a
/// supervisor. Bounded rather than terminal: the supervisor is deliberately
/// transient — it self-terminates once idle and the next CLI call starts a fresh
/// one on a new port — so "no supervisor answering" is a recoverable condition,
/// never a reason to stop trying.
const MAX_REGISTRATION_BACKOFF: Duration = Duration::from_secs(60);

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
    /// The managed Kin home this daemon runs under, as
    /// `kin_core::registry::managed_kin_home` resolved it in this process.
    ///
    /// The supervisor is machine-wide, so one registry legitimately holds
    /// daemons from several homes. This is what lets a census partition them
    /// and lets a home-scoped stop tell its own daemons from a neighbour's. A
    /// daemon registered by a binary predating the field sends nothing, and an
    /// empty value stays empty rather than being resolved from the
    /// supervisor's environment, which is a different process's home.
    #[serde(default)]
    pub kin_home: String,
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
    /// See [`RepoDaemonRegistration::kin_home`]. Empty means "not recorded",
    /// which is never the same answer as "matches the caller".
    #[serde(default)]
    pub kin_home: String,
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

#[derive(Debug)]
struct SupervisorLock {
    file: std::fs::File,
}

impl Drop for SupervisorLock {
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
        let _ = self.file.flush();
    }
}

fn acquire_supervisor_lifecycle_guard(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let deadline = Instant::now() + SUPERVISOR_LIFECYCLE_BUDGET;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(SUPERVISOR_LIFECYCLE_FILE))?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "timed out waiting for supervisor lifecycle authority",
                    ));
                }
                std::thread::sleep(
                    SUPERVISOR_LIFECYCLE_RETRY_INTERVAL
                        .min(deadline.saturating_duration_since(now)),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn stamp_supervisor_lock_owner(file: &mut std::fs::File) {
    if file.set_len(0).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    if write!(file, "{}", std::process::id()).is_ok() {
        let _ = file.flush();
    }
}

fn recorded_supervisor_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(SUPERVISOR_PID_FILE))
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

fn acquire_supervisor_lock(dir: &Path) -> std::io::Result<SupervisorLock> {
    let _lifecycle = acquire_supervisor_lifecycle_guard(dir)?;

    // A compatible older supervisor does not know supervisor.lock, so its live
    // PID record remains an independent mixed-version exclusion signal.
    if let Some(pid) = recorded_supervisor_pid(dir) {
        if pid != std::process::id() && kin_cli::daemon_client::process_liveness(pid).may_be_alive()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("kin supervisor pid {pid} may still be running"),
            ));
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(SUPERVISOR_SINGLETON_FILE))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            stamp_supervisor_lock_owner(&mut file);
            Ok(SupervisorLock { file })
        }
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "another kin supervisor holds the per-user singleton",
            ))
        }
        Err(error) => Err(error),
    }
}

fn write_supervisor_endpoint_files(
    dir: &Path,
    _supervisor_lock: &SupervisorLock,
    port: u16,
) -> std::io::Result<()> {
    let _lifecycle = acquire_supervisor_lifecycle_guard(dir)?;
    let pid_tmp = dir.join(format!("{SUPERVISOR_PID_FILE}.tmp"));
    let port_tmp = dir.join(format!("{SUPERVISOR_PORT_FILE}.tmp"));
    let owner_tmp = dir.join(format!("{SUPERVISOR_OWNER_FILE}.tmp"));
    let pid_path = dir.join(SUPERVISOR_PID_FILE);
    let port_path = dir.join(SUPERVISOR_PORT_FILE);
    let owner_path = dir.join(SUPERVISOR_OWNER_FILE);
    let result = (|| {
        let owner = kin_cli::daemon_client::EndpointOwnerRecord::current().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot publish supervisor endpoint without process-incarnation identity",
            )
        })?;
        std::fs::write(&pid_tmp, std::process::id().to_string())?;
        std::fs::write(&port_tmp, port.to_string())?;
        std::fs::write(
            &owner_tmp,
            serde_json::to_vec(&owner).map_err(std::io::Error::other)?,
        )?;
        // Ownership is visible before the bare PID. Readers either observe a
        // complete attributed endpoint or an incomplete publication they must
        // preserve; they never observe a new PID with no incarnation record.
        std::fs::rename(&owner_tmp, &owner_path)?;
        std::fs::rename(&pid_tmp, &pid_path)?;
        std::fs::rename(&port_tmp, &port_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(pid_tmp);
        let _ = std::fs::remove_file(port_tmp);
        let _ = std::fs::remove_file(owner_tmp);
        if recorded_supervisor_pid(dir) == Some(std::process::id()) {
            let _ = std::fs::remove_file(pid_path);
            let _ = std::fs::remove_file(port_path);
            let _ = std::fs::remove_file(owner_path);
        }
    }
    result
}

fn remove_supervisor_endpoint_files_if_current_process(dir: &Path, port: u16) {
    let Ok(_lifecycle) = acquire_supervisor_lifecycle_guard(dir) else {
        warn!("preserving supervisor endpoint because lifecycle authority is unavailable");
        return;
    };
    let pid_path = dir.join(SUPERVISOR_PID_FILE);
    let port_path = dir.join(SUPERVISOR_PORT_FILE);
    let owner_path = dir.join(SUPERVISOR_OWNER_FILE);
    let belongs_to_current = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
        == Some(std::process::id());
    let same_port = std::fs::read_to_string(&port_path)
        .ok()
        .and_then(|content| content.trim().parse::<u16>().ok())
        == Some(port);
    if !(belongs_to_current && same_port) {
        return;
    }
    let owner_belongs_to_current = std::fs::read_to_string(&owner_path)
        .ok()
        .and_then(|raw| {
            serde_json::from_str::<kin_cli::daemon_client::EndpointOwnerRecord>(&raw).ok()
        })
        .is_some_and(|owner| {
            owner.identity().pid() == std::process::id()
                && matches!(
                    kin_cli::daemon_client::process_identity_is_current(owner.identity()),
                    Ok(true)
                )
        });
    if !owner_belongs_to_current {
        warn!("preserving supervisor endpoint because its owner sidecar is missing or changed");
        return;
    }
    let _ = std::fs::remove_file(owner_path);
    let _ = std::fs::remove_file(pid_path);
    let _ = std::fs::remove_file(port_path);
}

pub fn supervisor_url_from_files() -> Option<String> {
    supervisor_url_from_dir(&supervisor_dir())
}

/// Endpoint recorded by a live supervisor under `dir`.
///
/// This read-only discovery path never retires endpoint files. The CLI owns
/// conditional retirement under supervisor.lifecycle plus supervisor.lock.
fn supervisor_url_from_dir(dir: &Path) -> Option<String> {
    let pid_path = dir.join(SUPERVISOR_PID_FILE);
    let port_path = dir.join(SUPERVISOR_PORT_FILE);
    let pid = std::fs::read_to_string(&pid_path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if !is_process_alive(pid) {
        return None;
    }
    let port = std::fs::read_to_string(&port_path)
        .ok()?
        .trim()
        .parse::<u16>()
        .ok()?;
    Some(format!("http://127.0.0.1:{port}"))
}

fn supervisor_url_from_env() -> Option<String> {
    std::env::var("KIN_SUPERVISOR_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Endpoint the registration loop should talk to next, where `failing` is the
/// endpoint the previous attempt could not reach.
///
/// An explicit `KIN_SUPERVISOR_URL` normally wins. It stops winning once it
/// fails: the CLI sets that variable on every daemon it spawns, and a repo
/// daemon outlives many supervisors because each one exits on idle and its
/// successor binds a different port. The inherited value then names a port that
/// is dead for the rest of the daemon's life, while the endpoint files a live
/// supervisor rewrites on every start name the successor. Preferring the files
/// after a failure is what lets a daemon re-register instead of heartbeating a
/// dead port forever.
fn resolve_supervisor_url(
    env_url: Option<String>,
    dir: &Path,
    failing: Option<&str>,
) -> Option<String> {
    let recorded = supervisor_url_from_dir(dir);
    if let (Some(failing), Some(recorded)) = (failing, recorded.as_deref()) {
        if recorded != failing {
            return Some(recorded.to_string());
        }
    }
    env_url.or(recorded)
}

fn discover_supervisor_url(failing: Option<&str>) -> Option<String> {
    resolve_supervisor_url(supervisor_url_from_env(), &supervisor_dir(), failing)
}

fn is_process_alive(pid: u32) -> bool {
    kin_cli::daemon_client::is_process_alive(pid)
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

/// The managed home a registering daemon reports, trimmed and never guessed.
///
/// An older daemon sends nothing here. The supervisor deliberately does not
/// substitute its own resolved home: the supervisor is machine-wide and its
/// environment says nothing about the environment its workers were launched
/// with, so filling the gap would manufacture exactly the false match this
/// field exists to prevent.
fn kin_home_for_payload(payload: &RepoDaemonRegistration) -> String {
    payload.kin_home.trim().to_string()
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
        kin_home: kin_core::registry::managed_kin_home_id(&kin_core::registry::managed_kin_home()),
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

/// How a registration or heartbeat attempt failed, at the granularity the log
/// state machine treats as "the same condition".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationFailure {
    /// The endpoint never answered: connection refused, timeout, transport
    /// error. In this topology that usually means the supervisor idled out.
    Unreachable,
    /// The supervisor answered and refused the registration.
    Rejected(u16),
}

impl RegistrationFailure {
    fn from_error(error: &reqwest::Error) -> Self {
        match error.status() {
            Some(status) => Self::Rejected(status.as_u16()),
            None => Self::Unreachable,
        }
    }
}

/// Whether an observed failure is new information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationReport {
    /// First observation of this condition.
    Transition,
    /// Same endpoint, same failure as the last reported condition; `repeats`
    /// identical observations have gone unreported since.
    Unchanged { repeats: u64 },
}

impl RegistrationReport {
    fn repeats(self) -> u64 {
        match self {
            Self::Transition => 0,
            Self::Unchanged { repeats } => repeats,
        }
    }
}

/// Severity a registration failure is reported at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationLogLevel {
    Warn,
    Info,
    Debug,
}

/// The severity decision, isolated so it can be falsified directly.
///
/// A transition is worth reporting; an unchanged condition is not, however long
/// it lasts. A supervisor that answers and refuses is a defect worth a warning;
/// a supervisor that is simply absent is an ordinary fact of this topology and
/// reports once at INFO.
fn registration_log_level(
    report: RegistrationReport,
    failure: RegistrationFailure,
) -> RegistrationLogLevel {
    match (report, failure) {
        (RegistrationReport::Unchanged { .. }, _) => RegistrationLogLevel::Debug,
        (RegistrationReport::Transition, RegistrationFailure::Rejected(_)) => {
            RegistrationLogLevel::Warn
        }
        (RegistrationReport::Transition, RegistrationFailure::Unreachable) => {
            RegistrationLogLevel::Info
        }
    }
}

/// Reports supervisor registration failures on TRANSITION only.
///
/// The attempt runs on a timer, so a condition that persists — the common one
/// being a supervisor that has idled out — would otherwise re-log at WARN for as
/// long as the daemon lives. A stream that always warns carries no more
/// information than one that never warns, and it buries the warnings that do
/// mean something. This reports entry into a condition and stays quiet while it
/// holds, so a changed endpoint, a changed failure, or a recovery is still
/// visible immediately.
#[derive(Debug, Default)]
struct RegistrationReporter {
    current: Option<(String, RegistrationFailure)>,
    repeats: u64,
}

impl RegistrationReporter {
    fn observe_failure(
        &mut self,
        endpoint: &str,
        failure: RegistrationFailure,
    ) -> RegistrationReport {
        let unchanged = matches!(
            &self.current,
            Some((seen_endpoint, seen_failure))
                if seen_endpoint.as_str() == endpoint && *seen_failure == failure
        );
        if unchanged {
            self.repeats += 1;
            return RegistrationReport::Unchanged {
                repeats: self.repeats,
            };
        }
        self.current = Some((endpoint.to_string(), failure));
        self.repeats = 0;
        RegistrationReport::Transition
    }

    /// Clear the failure state. Returns the number of unreported repeats when
    /// this success ends a failing streak, so the recovery log carries the
    /// volume the quiet period hid.
    fn observe_success(&mut self) -> Option<u64> {
        let repeats = self.repeats;
        self.repeats = 0;
        self.current.take().map(|_| repeats)
    }
}

/// Retry backoff, doubled per consecutive failure and capped. Only ever applied
/// after a failed attempt: a registered daemon keeps heartbeating at
/// [`DEFAULT_HEARTBEAT_INTERVAL`], well inside the supervisor's
/// [`HEARTBEAT_TTL`].
fn next_registration_delay(current: Duration) -> Duration {
    current
        .max(DEFAULT_HEARTBEAT_INTERVAL)
        .saturating_mul(2)
        .min(MAX_REGISTRATION_BACKOFF)
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
    let mut supervisor_url = discover_supervisor_url(None);
    let mut reporter = RegistrationReporter::default();
    // Sleeping between attempts rather than ticking a fixed-rate interval:
    // `tokio::time::interval` replays every tick missed while the runtime was
    // busy, so a daemon starved by a long hydration wakes up and fires the whole
    // backlog back-to-back. A sleep cannot accumulate one. The first attempt
    // still runs immediately, matching the interval's immediate first tick.
    let mut delay = Duration::ZERO;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = cancel_rx.changed() => {
                break;
            }
        }
        if *cancel_rx.borrow() {
            break;
        }

        payload.graph_entity_count = Some(state.graph.entity_count());
        if supervisor_url.is_none() {
            supervisor_url = discover_supervisor_url(None);
        }
        let Some(current_supervisor_url) = supervisor_url.clone() else {
            debug!(repo_id = %payload.repo_id, "no Kin supervisor endpoint found yet; retrying discovery");
            delay = next_registration_delay(delay);
            continue;
        };

        let result = if registered {
            post_heartbeat(&client, &current_supervisor_url, &payload).await
        } else {
            post_registration(&client, &current_supervisor_url, &payload).await
        };

        match result {
            Ok(()) => {
                let recovered = reporter.observe_success();
                if !registered {
                    info!(
                        repo_id = %payload.repo_id,
                        display_name = %payload.display_name,
                        supervisor_url = %current_supervisor_url,
                        unreported_failures = recovered.unwrap_or(0),
                        "registered repo daemon with supervisor"
                    );
                } else if let Some(unreported) = recovered {
                    info!(
                        repo_id = %payload.repo_id,
                        supervisor_url = %current_supervisor_url,
                        unreported_failures = unreported,
                        "supervisor heartbeat recovered"
                    );
                }
                registered = true;
                delay = DEFAULT_HEARTBEAT_INTERVAL;
            }
            Err(error) => {
                let failure = RegistrationFailure::from_error(&error);
                let report = reporter.observe_failure(&current_supervisor_url, failure);
                match registration_log_level(report, failure) {
                    RegistrationLogLevel::Warn => warn!(
                        error = %error,
                        repo_id = %payload.repo_id,
                        supervisor_url = %current_supervisor_url,
                        "kin supervisor refused repo daemon registration"
                    ),
                    RegistrationLogLevel::Info => info!(
                        error = %error,
                        repo_id = %payload.repo_id,
                        supervisor_url = %current_supervisor_url,
                        "kin supervisor endpoint is not answering; repo daemon will retry with backoff"
                    ),
                    RegistrationLogLevel::Debug => debug!(
                        error = %error,
                        repo_id = %payload.repo_id,
                        supervisor_url = %current_supervisor_url,
                        repeats = report.repeats(),
                        "supervisor registration condition unchanged"
                    ),
                }

                if failure != RegistrationFailure::Rejected(reqwest::StatusCode::CONFLICT.as_u16())
                {
                    registered = false;
                    supervisor_url = discover_supervisor_url(Some(current_supervisor_url.as_str()));
                }
                // A different endpoint is a different condition: try it at the
                // base cadence instead of inheriting the dead one's backoff.
                delay = if supervisor_url.as_deref() == Some(current_supervisor_url.as_str()) {
                    next_registration_delay(delay)
                } else {
                    DEFAULT_HEARTBEAT_INTERVAL
                };
            }
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

#[derive(Clone)]
struct SupervisorShutdownControl(Option<tokio::sync::watch::Sender<bool>>);

async fn request_supervisor_shutdown(
    Extension(control): Extension<SupervisorShutdownControl>,
    Json(expected): Json<kin_cli::daemon_client::ProcessIdentity>,
) -> Response {
    let current = match kin_cli::daemon_client::current_process_identity() {
        Ok(current) => current,
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("current process identity unavailable: {error}")})),
            )
                .into_response()
        }
    };
    if current != expected {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "supervisor process incarnation changed"})),
        )
            .into_response();
    }
    let Some(shutdown) = control.0 else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "cooperative shutdown is unavailable"})),
        )
            .into_response();
    };
    match shutdown.send(true) {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"stopping": true}))).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("shutdown channel closed: {error}")})),
        )
            .into_response(),
    }
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
    router_with_auth_and_shutdown(state, auth_token, None)
}

fn router_with_auth_and_shutdown(
    state: Arc<SupervisorState>,
    auth_token: Option<String>,
    shutdown: Option<tokio::sync::watch::Sender<bool>>,
) -> Router {
    let app = Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/shutdown", post(request_supervisor_shutdown))
        .route("/repos", get(list_repos))
        .route("/repos/{repo_id}/route", get(route_repo))
        .route("/daemons", get(list_repos))
        .route("/daemons/register", post(register_daemon))
        .route("/daemons/{repo_id}/heartbeat", post(heartbeat_daemon))
        .route("/daemons/{repo_id}", delete(deregister_daemon))
        .with_state(state)
        .layer(Extension(SupervisorShutdownControl(shutdown)))
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
    let display_name = display_name_for_payload(&payload);
    let kin_home = kin_home_for_payload(&payload);
    let mut repos = state.repo_daemons.write().await;
    if let Some(existing) = repos.get(&payload.repo_id) {
        if existing.instance_id != instance_id {
            return (StatusCode::CONFLICT, Json(existing.clone()));
        }
    }
    let record = RegisteredRepoDaemon {
        repo_id: payload.repo_id.clone(),
        display_name,
        instance_id,
        repo_root: payload.repo_root,
        pid: payload.pid,
        port: payload.port,
        endpoint: payload.endpoint,
        graph_entity_count: payload.graph_entity_count,
        kin_home,
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
    let display_name = display_name_for_payload(&payload);
    let kin_home = kin_home_for_payload(&payload);
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
            display_name: display_name.clone(),
            instance_id: instance_id.clone(),
            repo_root: payload.repo_root.clone(),
            pid: payload.pid,
            port: payload.port,
            endpoint: payload.endpoint.clone(),
            graph_entity_count: payload.graph_entity_count,
            kin_home: kin_home.clone(),
            registered_at: now.clone(),
            last_heartbeat_at: now.clone(),
            last_heartbeat_elapsed_ms: heartbeat_ms,
        });
    record.display_name = display_name;
    record.instance_id = instance_id;
    record.repo_root = payload.repo_root;
    record.pid = payload.pid;
    record.port = payload.port;
    record.endpoint = payload.endpoint;
    record.graph_entity_count = payload.graph_entity_count;
    record.kin_home = kin_home;
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
    let state_dir = supervisor_dir();
    let startup = kin_cli::daemon_client::validate_supervisor_runtime_startup(&state_dir)?;
    let supervisor_lock = Arc::new(acquire_supervisor_lock(&state_dir)?);
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
    write_supervisor_endpoint_files(&state_dir, &supervisor_lock, bound_port)?;
    if let Err(error) = startup.acknowledge() {
        remove_supervisor_endpoint_files_if_current_process(&state_dir, bound_port);
        return Err(error);
    }
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

    // The supervisor is stopped LAST in a `kin daemon stop --all` sweep, and
    // until now it was the one identity in that sweep with no hard bound on how
    // long stopping it could take. Its only shutdown paths are the tokio task
    // below and axum's graceful shutdown, which waits for in-flight connections
    // to finish; a request against a wedged repo daemon therefore holds the
    // supervisor open with nothing to end it. The CLI then reports a timeout
    // for a supervisor that was never going to exit, and a stop that worked on
    // every worker still fails.
    //
    // Same backstop the repo daemon uses: arming is runtime-independent, and
    // the watchdog is a plain OS thread that force-exits at grace.
    crate::daemon::install_shutdown_signal_handler();
    crate::daemon::spawn_shutdown_escalation_watchdog(
        || false,
        shutdown_rx.clone(),
        crate::daemon::shutdown_escalation_grace(),
    );

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
    let result = axum::serve(
        listener,
        router_with_auth_and_shutdown(state, auth_token, Some(shutdown_tx.clone())),
    )
    .with_graceful_shutdown(async move {
        while !*shutdown_rx.borrow() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await;
    remove_supervisor_endpoint_files_if_current_process(&state_dir, bound_port);
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
#[cfg(unix)]
const REAPER_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// Timeout for a single repo-daemon `/health` probe.
#[cfg(unix)]
const REAPER_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Grace period between SIGTERM and SIGKILL when reaping.
#[cfg(unix)]
const REAPER_SIGTERM_GRACE: Duration = Duration::from_secs(5);
/// CPU usage percent (may exceed 100 on multicore) above which a daemon counts
/// as "pinned" for a sweep.
#[cfg(any(unix, test))]
const REAPER_DEFAULT_CPU_PINNED_PERCENT: f32 = 80.0;
/// Default consecutive pinned sweeps before the CPU heuristic fires.
#[cfg(any(unix, test))]
const REAPER_DEFAULT_CPU_PINNED_SWEEPS: u32 = 2;
/// Consecutive sweeps a daemon must show zero persisted progress — no growth in
/// its repo `daemon.log` — before an unreachable or CPU-pinned daemon becomes
/// reap-eligible. 4 sweeps × 15s = a minute of zero persisted progress while
/// unreachable, long enough that a merely-busy daemon that missed a probe
/// deadline is never mistaken for a wedged one.
#[cfg(any(unix, test))]
const REAPER_STALL_SWEEPS: u32 = 4;
/// Default slack (in seconds) a daemon's start_time may lag the deployed binary
/// mtime before it counts as stale — absorbs clock/filesystem timestamp jitter.
#[cfg(any(unix, test))]
const REDEPLOY_DEFAULT_GRACE_SECS: u64 = 2;
/// Sentinel env var carried across the self-re-exec boundary, recording the
/// binary mtime the supervisor already re-execed into. Breaks the re-exec loop:
/// execve preserves the process start_time, so a supervisor that predates its
/// rebuilt binary stays stale after re-exec; without this sentinel it would
/// re-exec on every sweep forever.
#[cfg(unix)]
const SUPERVISOR_REEXECED_FOR_MTIME_ENV: &str = "KIN_SUPERVISOR_REEXECED_FOR_MTIME";

/// Health classification of a discovered repo daemon.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq)]
enum DaemonHealth {
    /// `/health` responded 2xx; carries observed activity.
    Healthy(DaemonActivity),
    /// The daemon ANSWERED but the answer was broken: a served non-success HTTP
    /// status, or a 2xx body that could not be parsed. It is responding, just
    /// wrong — a genuinely broken daemon.
    Unhealthy,
    /// The `/health` probe could not reach the daemon at all: it timed out or the
    /// connection failed. A daemon pinned doing real work can miss a probe
    /// deadline, so this is treated as "no answer yet", not proof of breakage.
    Unreachable,
    /// No port was discoverable, so health could not be probed.
    Unknown,
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonActivity {
    /// In-flight requests, event subscribers, or external (non-daemon) sessions.
    has_clients: bool,
    /// Reconciliation is actively running (not idle).
    reconciling: bool,
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapReason {
    /// Orphaned (reparented to init) and the daemon ANSWERED its health probe
    /// with a broken response (non-success status or unparseable body).
    OrphanedUnhealthy,
    /// Orphaned and UNREACHABLE (probe timed out or the connection failed) across
    /// the full stall window with zero persisted progress — a wedged daemon,
    /// distinguished from a merely-busy one that keeps advancing its log.
    OrphanedUnreachableStalled,
    /// Orphaned, healthy but idle (no clients, not reconciling), CPU-pinned across
    /// enough consecutive sweeps, AND showing no persisted progress across the
    /// stall window — the busy-spinner case, never a daemon still advancing work.
    OrphanedBusyNoClients,
    /// Orphaned duplicate of a registered, healthy daemon on the same repo root.
    DuplicateOrphanTwin,
}

/// Why a healthy-but-invisible daemon is being adopted into the registry.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptReason {
    /// No registry entry existed for this repo root.
    Unregistered,
    /// A registry entry for this repo root existed but named a dead pid; the live
    /// healthy daemon replaces it.
    HealStaleEntry,
}

/// Why a healthy idle daemon is being rolled over to pick up a fresh build.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedeployReason {
    /// The on-disk binary was rebuilt after this process started (its start_time
    /// predates the binary mtime), so the daemon is running stale code.
    StaleBinary,
}

/// How a discovered daemon relates to the supervisor's registry entry (if any)
/// for the same repo root. Computed per sweep from a registry snapshot.
#[cfg(any(unix, test))]
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

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq)]
enum DaemonDecision {
    Keep,
    Reap(ReapReason),
    Adopt(AdoptReason),
    Redeploy(RedeployReason),
}

/// Which heuristics beyond the always-on safe criterion are enabled, and how the
/// CPU heuristic is tuned. Controlled by `KIN_SUPERVISOR_REAP_*`.
#[cfg(any(unix, test))]
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

#[cfg(any(unix, test))]
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

#[cfg(unix)]
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
#[cfg(unix)]
fn env_flag_falsey(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::trim),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

/// True when `key` is set to an explicitly truthy value (`1/true/yes/on`).
#[cfg(unix)]
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
#[cfg(any(unix, test))]
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
#[cfg(any(unix, test))]
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
#[cfg(any(unix, test))]
#[derive(Debug, Clone)]
struct DaemonObservation {
    #[cfg(unix)]
    pid: u32,
    repo_root: String,
    /// Reparented to init (ppid == 1): its launching CLI has exited.
    orphaned: bool,
    health: DaemonHealth,
    /// Consecutive sweeps this pid has been CPU-pinned.
    cpu_pinned_sweeps: u32,
    /// Consecutive sweeps this pid's repo `daemon.log` has not grown — a
    /// persisted-progress stall. Gates the unreachable and CPU-pinned reap
    /// criteria so a busy-but-advancing daemon is never reaped.
    stall_sweeps: u32,
    /// How this daemon relates to the registry entry for its repo root.
    registry: RegistryRelation,
    /// The deployed binary was rebuilt after this process started — it is running
    /// stale code and is a redeploy candidate.
    stale_binary: bool,
    /// What this daemon publishes about a write transaction it has open. Read
    /// from disk rather than from `/health`, because the state this protects is
    /// exactly the state in which `/health` cannot be answered.
    transaction: crate::commit_liveness::TransactionLiveness,
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
/// - The safe reap criteria are always enabled: an orphaned daemon that ANSWERED
///   its probe with a broken response is reaped at once; an orphaned daemon that
///   is merely UNREACHABLE (probe timed out / connection failed) is reaped only
///   after it has also shown zero persisted progress across the stall window, so a
///   busy daemon that missed a probe deadline is never mistaken for a wedged one.
/// - The CPU-pinned and duplicate-twin reap criteria are policy-gated. The
///   CPU-pinned criterion additionally requires the same persisted-progress stall,
///   so a busy-but-advancing daemon is never reaped.
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
#[cfg(any(unix, test))]
fn classify_daemon(obs: &DaemonObservation, policy: &ReapPolicy) -> DaemonDecision {
    // Absolute guard (#4): a daemon serving clients or actively reconciling is
    // never a reap candidate, regardless of registration or orphan status. It can
    // still fall through to the adoption path below to restore visibility.
    let active = matches!(
        &obs.health,
        DaemonHealth::Healthy(activity) if activity.has_clients || activity.reconciling
    );

    // Absolute guard, second half: a daemon that has published a beating write
    // transaction is doing real work whether or not it can say so over HTTP.
    // The guard above reads `has_clients` off a `/health` body, so it can only
    // fire for a daemon with a runtime worker free to produce one — and a commit
    // is synchronous work on a runtime worker holding the coordination gate. The
    // one state the busy guard exists to protect was therefore the one state it
    // could not observe, which is how a 172-second commit was SIGKILLed with its
    // client still waiting. This reads the daemon's own on-disk claim instead,
    // and never adopts a stale one (see `Stale` below).
    if matches!(
        obs.transaction,
        crate::commit_liveness::TransactionLiveness::Open(_)
    ) {
        return DaemonDecision::Keep;
    }

    if !active {
        // (a) Safe criterion, always on: orphaned and the daemon ANSWERED its
        //     probe with a broken response (non-success status or unparseable
        //     body). A daemon that answers with garbage is genuinely broken, so it
        //     is reaped at once — no progress grace.
        if obs.orphaned && obs.health == DaemonHealth::Unhealthy {
            return DaemonDecision::Reap(ReapReason::OrphanedUnhealthy);
        }

        // (a') Orphaned and UNREACHABLE (probe timed out / connection failed). A
        //      busy daemon can miss a probe deadline, so an unreachable probe alone
        //      is not proof of a rogue daemon. Reap only once it has ALSO made zero
        //      persisted progress across the stall window — unreachable AND wedged.
        if obs.orphaned
            && obs.health == DaemonHealth::Unreachable
            && obs.stall_sweeps >= REAPER_STALL_SWEEPS
        {
            return DaemonDecision::Reap(ReapReason::OrphanedUnreachableStalled);
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

        // (b) Orphaned busy-spinner: healthy but idle (ensured by `!active`),
        //     CPU-pinned across enough consecutive sweeps, AND making no persisted
        //     progress across the stall window. The stall gate is what separates a
        //     rogue spinner from a daemon legitimately busy advancing its log.
        if policy.cpu_heuristic_enabled
            && obs.orphaned
            && matches!(obs.health, DaemonHealth::Healthy(_))
            && obs.cpu_pinned_sweeps >= policy.cpu_pinned_min_sweeps
            && obs.stall_sweeps >= REAPER_STALL_SWEEPS
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
        // pid -> (last observed repo daemon.log length, consecutive no-growth sweeps).
        let mut stalled_sweeps: HashMap<u32, (u64, u32)> = HashMap::new();
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
                &mut stalled_sweeps,
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
    stalled_sweeps: &mut HashMap<u32, (u64, u32)>,
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

    // Update persisted-progress streaks alongside the CPU streaks: a daemon whose
    // repo `daemon.log` has not grown since the last sweep made no persisted
    // progress this sweep. A daemon that IS growing its log is doing real work even
    // when its health probe looks idle or times out, so its streak resets to 0. The
    // first sighting of a pid only records a baseline length (no stall counted yet).
    stalled_sweeps.retain(|pid, _| live_pids.contains(pid));
    for daemon in &discovered {
        let log_len = daemon_log_len(&daemon.repo_root);
        match stalled_sweeps.get_mut(&daemon.pid) {
            Some((last_len, no_growth)) => {
                if log_len > *last_len {
                    *no_growth = 0;
                } else {
                    *no_growth = no_growth.saturating_add(1);
                }
                *last_len = log_len;
            }
            None => {
                stalled_sweeps.insert(daemon.pid, (log_len, 0));
            }
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
            stall_sweeps: stalled_sweeps
                .get(&daemon.pid)
                .map(|(_, no_growth)| *no_growth)
                .unwrap_or(0),
            registry: registry_relation,
            stale_binary,
            transaction: crate::commit_liveness::transaction_liveness(
                Path::new(&daemon.repo_root),
                daemon.pid,
            ),
        };
        match classify_daemon(&observation, &policy) {
            DaemonDecision::Reap(reason) => {
                reap_daemon(&observation, reason).await;
                pinned_sweeps.remove(&daemon.pid);
                stalled_sweeps.remove(&daemon.pid);
            }
            DaemonDecision::Redeploy(reason) => {
                redeploy_daemon(&observation, reason).await;
                pinned_sweeps.remove(&daemon.pid);
                stalled_sweeps.remove(&daemon.pid);
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
        // An adopted daemon never registered, so nothing told the supervisor
        // which managed home it runs under. Left unrecorded on purpose: a
        // home-scoped stop then skips and names it instead of assuming it is
        // the caller's.
        kin_home: String::new(),
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

/// Size in bytes of a repo daemon's persisted activity log — the reaper's
/// persisted-progress signal. A daemon doing real work grows
/// `<repo_root>/.kin/daemon.log`; a missing or unreadable log reads as 0 so a
/// daemon that has simply never written one never looks like it is "shrinking".
#[cfg(unix)]
fn daemon_log_len(repo_root: &str) -> u64 {
    let log_path = Path::new(repo_root).join(".kin").join("daemon.log");
    std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0)
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
        Err(_) => return DaemonHealth::Unreachable,
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
    // Say it in the victim's own log before signalling, because everything below
    // this line is written to the supervisor's log and the operator opens
    // `.kin/daemon.log`. Without this the daemon's log just stops: a SIGKILL
    // prints nothing, and the daemon's own SIGTERM handler is a tokio arm a
    // saturated runtime never polls, so neither signal leaves a trace there.
    let kin_root = Path::new(repo_root).join(".kin");
    let in_flight = match crate::commit_liveness::transaction_liveness(Path::new(repo_root), pid) {
        crate::commit_liveness::TransactionLiveness::Open(summary)
        | crate::commit_liveness::TransactionLiveness::Stale(summary) => Some(summary.to_string()),
        crate::commit_liveness::TransactionLiveness::None => None,
    };
    let note = kin_daemon_spawn::DaemonDeathNote {
        pid,
        killed_by: "kin-supervisor-reaper".to_string(),
        reason: format!("{action}: {reason}"),
        in_flight,
        at: chrono::Utc::now().to_rfc3339(),
    };
    kin_daemon_spawn::append_to_daemon_log(
        &kin_root,
        &format!("kin-daemon TERMINATED BY SUPERVISOR: {}", note.summary()),
    );
    kin_daemon_spawn::write_daemon_death_note(&kin_root, &note);

    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let start = Instant::now();
    let mut killed = false;
    while start.elapsed() < REAPER_SIGTERM_GRACE {
        if !is_process_alive(pid) {
            info!(
                pid,
                repo = %repo_root,
                "daemon exited gracefully after SIGTERM"
            );
            retire_endpoint_of_terminated_daemon(&kin_root, pid);
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
        killed = true;
    }
    if killed {
        // A SIGKILLed daemon retires nothing: endpoint retirement runs after the
        // shutdown select returns, which it never does. Left alone, `daemon.pid`
        // keeps naming a dead daemon as the live owner of this repo, which is
        // what `kin doctor` reported as STALE with the record still on disk. The
        // killer knows the daemon is gone, so the killer clears it.
        let settled = Instant::now();
        while settled.elapsed() < REAPER_SIGTERM_GRACE && is_process_alive(pid) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        retire_endpoint_of_terminated_daemon(&kin_root, pid);
    }
}

/// Clear the endpoint record of a daemon this supervisor just ended.
///
/// Refuses on anything short of proof: the record must still name that exact
/// pid, and that pid must be gone. A record naming a live process, a successor,
/// or nobody identifiable is left exactly where it is.
#[cfg(unix)]
fn retire_endpoint_of_terminated_daemon(kin_root: &Path, pid: u32) {
    if is_process_alive(pid) {
        return;
    }
    match crate::lifecycle::retire_endpoint_of_dead_owner(kin_root, pid) {
        true => info!(
            pid,
            kin_root = %kin_root.display(),
            "retired the endpoint record of a terminated daemon"
        ),
        false => warn!(
            pid,
            kin_root = %kin_root.display(),
            "left the endpoint record in place: it no longer names the terminated daemon"
        ),
    }
}

/// Reap a daemon: graceful SIGTERM, then SIGKILL if it survives the grace window.
/// The logged reason carries the evidence the decision rested on — the probe
/// outcome plus the CPU-pinned and persisted-progress-stall streak counts — so an
/// operator can see exactly why a daemon was judged rogue.
#[cfg(unix)]
async fn reap_daemon(observation: &DaemonObservation, reason: ReapReason) {
    let probe = match observation.health {
        DaemonHealth::Healthy(_) => "healthy",
        DaemonHealth::Unhealthy => "answered-unhealthy",
        DaemonHealth::Unreachable => "unreachable",
        DaemonHealth::Unknown => "unknown",
    };
    let mut context = format!(
        "{reason:?} (probe={probe}, cpu_pinned_sweeps={}, stall_sweeps={})",
        observation.cpu_pinned_sweeps, observation.stall_sweeps
    );
    // A daemon that opened a write transaction and then stopped beating it is
    // wedged rather than busy, and ending it may cost a caller its commit. That
    // is a decision worth taking, not one worth taking quietly: it is the only
    // reap that names an interrupted transaction, and it says so at error level
    // with the phase the daemon died in.
    if let crate::commit_liveness::TransactionLiveness::Stale(summary) = &observation.transaction {
        context = format!("{context} (abandoned transaction: {summary})");
        error!(
            pid = observation.pid,
            repo = %observation.repo_root,
            transaction = %summary,
            reason = ?reason,
            "reaping a daemon that has a write transaction open; its beat went stale, so it is \
             wedged rather than busy — the caller waiting on this transaction will lose it"
        );
    }
    graceful_terminate(
        observation.pid,
        &observation.repo_root,
        "reaping misbehaving repo daemon",
        &context,
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

    #[test]
    fn supervisor_singleton_is_process_lifetime_and_never_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_supervisor_lock(dir.path()).unwrap();

        let error = acquire_supervisor_lock(dir.path()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            dir.path().join(SUPERVISOR_SINGLETON_FILE).exists(),
            "a contended acquire must preserve the singleton pathname"
        );
        assert!(
            dir.path().join(SUPERVISOR_LIFECYCLE_FILE).exists(),
            "the lifecycle authority is never unlinked"
        );

        drop(first);
        let reacquired = acquire_supervisor_lock(dir.path()).unwrap();
        drop(reacquired);
        assert!(
            dir.path().join(SUPERVISOR_SINGLETON_FILE).exists(),
            "clean release drops the flock but never replaces its inode"
        );
    }

    #[test]
    fn supervisor_publication_and_cleanup_are_generation_conditional() {
        let dir = tempfile::tempdir().unwrap();
        let authority = acquire_supervisor_lock(dir.path()).unwrap();
        write_supervisor_endpoint_files(dir.path(), &authority, 50595).unwrap();

        // A same-process successor generation must survive cleanup formed
        // against the prior port.
        write_supervisor_endpoint_files(dir.path(), &authority, 50596).unwrap();
        remove_supervisor_endpoint_files_if_current_process(dir.path(), 50595);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(SUPERVISOR_PORT_FILE))
                .unwrap()
                .trim(),
            "50596"
        );

        remove_supervisor_endpoint_files_if_current_process(dir.path(), 50596);
        assert!(!dir.path().join(SUPERVISOR_PID_FILE).exists());
        assert!(!dir.path().join(SUPERVISOR_PORT_FILE).exists());
        assert!(dir.path().join(SUPERVISOR_SINGLETON_FILE).exists());
    }

    #[test]
    fn current_protocol_directory_sentinel_blocks_legacy_respawn_without_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let _startup_lock =
            kin_cli::daemon_client::try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let supervisor_lock = Arc::new(acquire_supervisor_lock(dir.path()).unwrap());
        let port = 50597;
        write_supervisor_endpoint_files(dir.path(), &supervisor_lock, port).unwrap();

        // Exact destructive ordering in the immutable PR-base CLI: health
        // fails, both discovery files are deleted, and only then does it try
        // create-new on supervisor.start.lock. The current protocol keeps that
        // pathname as a non-empty directory, which remove_file cannot delete
        // and create_new cannot replace. No timer or runtime task participates.
        let _ = std::fs::remove_file(dir.path().join(SUPERVISOR_PID_FILE));
        let _ = std::fs::remove_file(dir.path().join(SUPERVISOR_PORT_FILE));
        let legacy_acquired = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join("supervisor.start.lock"))
            .is_ok();
        assert!(
            !legacy_acquired,
            "the old client must not obtain spawn authority after deleting discovery"
        );
        assert!(
            dir.path().join("supervisor.start.lock").is_dir(),
            "the compatibility sentinel must remain a directory for the supervisor lifetime"
        );
    }

    fn repo_payload(instance_id: &str, port: u16) -> RepoDaemonRegistration {
        repo_payload_in_home(instance_id, port, "/homes/a/.kin")
    }

    fn repo_payload_in_home(
        instance_id: &str,
        port: u16,
        kin_home: &str,
    ) -> RepoDaemonRegistration {
        RepoDaemonRegistration {
            repo_id: "demo".to_string(),
            display_name: "demo".to_string(),
            instance_id: instance_id.to_string(),
            repo_root: "/tmp/demo".to_string(),
            pid: std::process::id(),
            port,
            endpoint: format!("http://127.0.0.1:{port}"),
            graph_entity_count: Some(12),
            kin_home: kin_home.to_string(),
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
            #[cfg(unix)]
            pid: 4242,
            repo_root: "/tmp/demo".to_string(),
            orphaned,
            health,
            cpu_pinned_sweeps: 0,
            stall_sweeps: 0,
            registry: RegistryRelation::RegisteredSelf,
            stale_binary: false,
            transaction: crate::commit_liveness::TransactionLiveness::None,
        }
    }

    /// A daemon mid-commit, as its own on-disk marker reports it.
    fn committing(beat_age_secs: u64) -> crate::commit_liveness::OpenTransactionSummary {
        crate::commit_liveness::OpenTransactionSummary {
            operation: "commit".to_string(),
            phase: "publish_workspace_admission".to_string(),
            elapsed_secs: 86,
            beat_age_secs,
        }
    }

    fn healthy(has_clients: bool, reconciling: bool) -> DaemonHealth {
        DaemonHealth::Healthy(DaemonActivity {
            has_clients,
            reconciling,
        })
    }

    /// The regression this whole marker exists for.
    ///
    /// A one-file docstring commit on a converted psf/requests store was
    /// SIGKILLed 172 seconds in, with the client still waiting on the request.
    /// Every gate the reaper checked was satisfied by a HEALTHY commit: the
    /// daemon is orphaned because `setsid` reparents every detached daemon to
    /// init, it is unreachable because the commit is synchronous work on a
    /// runtime worker so `/health` misses its 2s deadline, and it is stalled
    /// because a commit phase logs only when it finishes and one phase ran 85.8s
    /// against a 60s stall window. The `has_clients` guard that should have
    /// stopped this reads a `/health` body, which by construction does not exist
    /// for an unreachable daemon.
    ///
    /// So the decision is made against the daemon's own published claim instead,
    /// and this asserts across every reap criterion at once — including the
    /// duplicate-twin path, which carries no stall grace and fires on the very
    /// first sweep.
    #[test]
    fn reaper_never_reaps_a_daemon_that_is_beating_an_open_transaction() {
        for (health, registry) in [
            (DaemonHealth::Unreachable, RegistryRelation::RegisteredSelf),
            (DaemonHealth::Unhealthy, RegistryRelation::RegisteredSelf),
            (DaemonHealth::Unreachable, RegistryRelation::LiveTwin),
            (DaemonHealth::Unknown, RegistryRelation::LiveTwin),
        ] {
            let mut obs = observation(health.clone(), true);
            obs.registry = registry;
            obs.stall_sweeps = REAPER_STALL_SWEEPS * 10;
            obs.cpu_pinned_sweeps = 100;
            obs.stale_binary = true;
            obs.transaction =
                crate::commit_liveness::TransactionLiveness::Open(Box::new(committing(0)));
            assert_eq!(
                classify_daemon(&obs, &ReapPolicy::default()),
                DaemonDecision::Keep,
                "a daemon beating an open transaction must survive {health:?}/{registry:?}"
            );
        }
    }

    /// The marker must not become permanent immunity.
    ///
    /// A daemon that opened a transaction and then stopped beating it is wedged
    /// rather than busy: the beat runs on a dedicated OS thread precisely so
    /// runtime saturation cannot silence it, so a minute of silence is evidence
    /// about the process, not about the workload. Reaping resumes, and
    /// `reap_daemon` says at error level that it is ending a transaction.
    #[test]
    fn a_transaction_whose_beat_went_stale_stops_shielding_the_daemon() {
        let mut obs = observation(DaemonHealth::Unreachable, true);
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
        obs.transaction = crate::commit_liveness::TransactionLiveness::Stale(Box::new(committing(
            crate::commit_liveness::BEAT_STALE_AFTER.as_secs() + 30,
        )));
        assert_eq!(
            classify_daemon(&obs, &ReapPolicy::default()),
            DaemonDecision::Reap(ReapReason::OrphanedUnreachableStalled)
        );
    }

    /// A marker left by some earlier daemon shields nobody: `transaction_liveness`
    /// only reports `Open` for the pid being judged, so a leftover file cannot
    /// make a repository permanently unreapable.
    #[test]
    fn an_absent_transaction_marker_leaves_every_reap_criterion_as_it_was() {
        let mut obs = observation(DaemonHealth::Unreachable, true);
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
        assert_eq!(
            classify_daemon(&obs, &ReapPolicy::default()),
            DaemonDecision::Reap(ReapReason::OrphanedUnreachableStalled),
            "without a marker the pre-existing criteria must be untouched"
        );
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
    fn reaper_reaps_answered_unhealthy_without_waiting_for_stall() {
        // A daemon that ANSWERED with a broken response is genuinely broken, so it
        // is reaped immediately — the stall window only guards the unreachable and
        // CPU-pinned paths, not this one.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unhealthy, true);
        obs.stall_sweeps = 0;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedUnhealthy)
        );
    }

    #[test]
    fn reaper_keeps_orphaned_unreachable_without_stall() {
        // Orphaned and unreachable (probe timed out / connection failed) but still
        // making persisted progress: a busy daemon that missed a probe deadline is
        // never reaped on the probe result alone.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unreachable, true);
        obs.stall_sweeps = REAPER_STALL_SWEEPS - 1;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_orphaned_unreachable_when_stalled() {
        // Orphaned, unreachable, AND no persisted progress across the full stall
        // window: a wedged daemon, reaped.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unreachable, true);
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedUnreachableStalled)
        );
    }

    #[test]
    fn reaper_keeps_non_orphaned_unreachable_even_when_stalled() {
        // A daemon with a live parent is never reaped by the safe criteria, even
        // unreachable and stalled: its launching process still owns its lifecycle.
        let policy = ReapPolicy::default();
        let mut obs = observation(DaemonHealth::Unreachable, false);
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
    }

    #[test]
    fn reaper_reaps_orphaned_idle_cpu_spinner() {
        // CPU-pinned past threshold AND stalled (no persisted progress): a genuine
        // busy-spinner, reaped.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = REAPER_DEFAULT_CPU_PINNED_SWEEPS;
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
        assert_eq!(
            classify_daemon(&obs, &policy),
            DaemonDecision::Reap(ReapReason::OrphanedBusyNoClients)
        );
    }

    #[test]
    fn reaper_keeps_progressing_cpu_spinner() {
        // CPU-pinned past threshold but STILL advancing its log (stall_sweeps below
        // the window): busy doing real work, never reaped.
        let policy = ReapPolicy::default();
        let mut obs = observation(healthy(false, false), true);
        obs.cpu_pinned_sweeps = 99;
        obs.stall_sweeps = REAPER_STALL_SWEEPS - 1;
        assert_eq!(classify_daemon(&obs, &policy), DaemonDecision::Keep);
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
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
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
        obs.stall_sweeps = REAPER_STALL_SWEEPS;
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
    async fn supervisor_shutdown_is_bound_to_the_expected_process_incarnation() {
        let identity = kin_cli::daemon_client::current_process_identity().unwrap();
        let mut stale = serde_json::to_value(&identity).unwrap();
        stale["birth_token"] = serde_json::Value::String("reused-pid-successor".to_string());

        let (rejected_tx, rejected_rx) = tokio::sync::watch::channel(false);
        let rejected_app = router_with_auth_and_shutdown(
            Arc::new(SupervisorState::new()),
            Some("shutdown-token".to_string()),
            Some(rejected_tx),
        );
        let rejected = rejected_app
            .oneshot(
                Request::post("/shutdown")
                    .header("authorization", "Bearer shutdown-token")
                    .header("content-type", "application/json")
                    .body(Body::from(stale.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::CONFLICT);
        assert!(
            !*rejected_rx.borrow(),
            "mismatched identity requested shutdown"
        );

        let (accepted_tx, accepted_rx) = tokio::sync::watch::channel(false);
        let accepted_app = router_with_auth_and_shutdown(
            Arc::new(SupervisorState::new()),
            Some("shutdown-token".to_string()),
            Some(accepted_tx),
        );
        let accepted = accepted_app
            .oneshot(
                Request::post("/shutdown")
                    .header("authorization", "Bearer shutdown-token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&identity).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert!(
            *accepted_rx.borrow(),
            "matching identity did not request shutdown"
        );
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
        let mut bind_host = kin_core::test_env::EnvVarGuard::unset("KIN_SUPERVISOR_BIND_HOST");

        // Loopback always allowed; arbitrary hosts rejected by default.
        assert!(is_host_allowed("127.0.0.1"));
        assert!(is_host_allowed("localhost"));
        assert!(is_host_allowed("::1"));
        assert!(!is_host_allowed("attacker.com"));
        assert!(!is_host_allowed("10.0.0.5"));

        // An explicit non-loopback bind host is allowed only for that host.
        bind_host.apply("KIN_SUPERVISOR_BIND_HOST", Some("10.0.0.5"));
        assert!(is_host_allowed("10.0.0.5"));
        assert!(!is_host_allowed("attacker.com"));

        // A wildcard bind allows any host (operator opted into exposure).
        bind_host.apply("KIN_SUPERVISOR_BIND_HOST", Some("0.0.0.0"));
        assert!(is_host_allowed("attacker.com"));
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
        let mut tokens = kin_core::test_env::EnvVarGuard::unset("KIN_SUPERVISOR_AUTH_TOKEN")
            .without("KIN_SUPERVISOR_REQUIRE_TOKEN");

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
        tokens.apply("KIN_SUPERVISOR_REQUIRE_TOKEN", Some("1"));
        assert_eq!(
            resolve_serve_auth_token(&dir).as_deref(),
            Some(token.as_str())
        );

        // An explicit KIN_SUPERVISOR_AUTH_TOKEN override always wins.
        tokens.apply("KIN_SUPERVISOR_AUTH_TOKEN", Some("explicit-override"));
        assert_eq!(
            resolve_serve_auth_token(&dir).as_deref(),
            Some("explicit-override")
        );
    }

    #[test]
    fn supervisor_unreachable_reports_once_then_stays_quiet() {
        let mut reporter = RegistrationReporter::default();
        let endpoint = "http://127.0.0.1:61951";

        // Entering the condition is new information.
        let first = reporter.observe_failure(endpoint, RegistrationFailure::Unreachable);
        assert_eq!(first, RegistrationReport::Transition);
        assert_eq!(
            registration_log_level(first, RegistrationFailure::Unreachable),
            RegistrationLogLevel::Info
        );

        // Staying in it is not: no second report, at any level above debug,
        // however long an absent supervisor stays absent.
        for expected_repeats in 1..=5 {
            let repeat = reporter.observe_failure(endpoint, RegistrationFailure::Unreachable);
            assert_eq!(
                repeat,
                RegistrationReport::Unchanged {
                    repeats: expected_repeats
                }
            );
            assert_eq!(
                registration_log_level(repeat, RegistrationFailure::Unreachable),
                RegistrationLogLevel::Debug
            );
        }
    }

    #[test]
    fn supervisor_rejection_warns_once_not_on_every_attempt() {
        let mut reporter = RegistrationReporter::default();
        let endpoint = "http://127.0.0.1:61951";
        let rejected = RegistrationFailure::Rejected(401);

        // A supervisor that answers and refuses IS a defect: warn on entry.
        let first = reporter.observe_failure(endpoint, rejected);
        assert_eq!(first, RegistrationReport::Transition);
        assert_eq!(
            registration_log_level(first, rejected),
            RegistrationLogLevel::Warn
        );

        // The second identical failure must not re-log at WARN. This is the
        // whole point: a warning that repeats on a timer is indistinguishable
        // from background noise, so a real warning in the same stream is
        // invisible.
        let second = reporter.observe_failure(endpoint, rejected);
        assert_eq!(second, RegistrationReport::Unchanged { repeats: 1 });
        assert_ne!(
            registration_log_level(second, rejected),
            RegistrationLogLevel::Warn
        );
        assert_eq!(
            registration_log_level(second, rejected),
            RegistrationLogLevel::Debug
        );
    }

    #[test]
    fn supervisor_registration_state_change_is_always_reported() {
        let mut reporter = RegistrationReporter::default();
        let dead = "http://127.0.0.1:61951";
        let successor = "http://127.0.0.1:50596";

        assert_eq!(
            reporter.observe_failure(dead, RegistrationFailure::Unreachable),
            RegistrationReport::Transition
        );
        assert_eq!(
            reporter.observe_failure(dead, RegistrationFailure::Unreachable),
            RegistrationReport::Unchanged { repeats: 1 }
        );

        // A different endpoint is a different condition, even with the same
        // failure — suppression must never hide the daemon moving supervisors.
        assert_eq!(
            reporter.observe_failure(successor, RegistrationFailure::Unreachable),
            RegistrationReport::Transition
        );

        // So is a different failure at the same endpoint: unreachable becoming a
        // live refusal escalates back to WARN instead of staying suppressed.
        let refused = RegistrationFailure::Rejected(409);
        let escalated = reporter.observe_failure(successor, refused);
        assert_eq!(escalated, RegistrationReport::Transition);
        assert_eq!(
            registration_log_level(escalated, refused),
            RegistrationLogLevel::Warn
        );

        // And so is a different status from the same endpoint.
        let server_error = RegistrationFailure::Rejected(500);
        assert_eq!(
            reporter.observe_failure(successor, server_error),
            RegistrationReport::Transition
        );
    }

    #[test]
    fn supervisor_recovery_reports_hidden_volume_and_rearms() {
        let mut reporter = RegistrationReporter::default();
        let endpoint = "http://127.0.0.1:61951";

        assert!(
            reporter.observe_success().is_none(),
            "a success with no failing streak has nothing to report"
        );

        reporter.observe_failure(endpoint, RegistrationFailure::Unreachable);
        for _ in 0..4 {
            reporter.observe_failure(endpoint, RegistrationFailure::Unreachable);
        }
        assert_eq!(
            reporter.observe_success(),
            Some(4),
            "recovery must carry the volume the quiet period hid"
        );
        assert!(reporter.observe_success().is_none());

        // After a recovery the same failure is a fresh transition, not a repeat.
        assert_eq!(
            reporter.observe_failure(endpoint, RegistrationFailure::Unreachable),
            RegistrationReport::Transition
        );
    }

    #[test]
    fn supervisor_registration_backoff_grows_and_caps() {
        // The first failure escalates off the base cadence...
        assert_eq!(
            next_registration_delay(Duration::ZERO),
            DEFAULT_HEARTBEAT_INTERVAL * 2
        );
        assert_eq!(
            next_registration_delay(DEFAULT_HEARTBEAT_INTERVAL),
            DEFAULT_HEARTBEAT_INTERVAL * 2
        );

        // ...and consecutive failures keep doubling to a bounded ceiling, so a
        // daemon never gives up on a supervisor that comes back.
        let mut delay = DEFAULT_HEARTBEAT_INTERVAL;
        for _ in 0..10 {
            delay = next_registration_delay(delay);
        }
        assert_eq!(delay, MAX_REGISTRATION_BACKOFF);

        // Backoff only ever applies to failures: a healthy daemon heartbeats at
        // the base cadence, which must stay inside the supervisor's TTL.
        assert!(DEFAULT_HEARTBEAT_INTERVAL < HEARTBEAT_TTL);
    }

    #[test]
    fn supervisor_url_follows_successor_after_inherited_endpoint_dies() {
        let dir = std::env::temp_dir().join(format!("kin-supervisor-url-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let inherited = "http://127.0.0.1:61951".to_string();

        // No endpoint files recorded: the inherited KIN_SUPERVISOR_URL is all
        // there is, and a failure against it must not invent an endpoint.
        assert_eq!(
            resolve_supervisor_url(Some(inherited.clone()), &dir, None).as_deref(),
            Some(inherited.as_str())
        );
        assert_eq!(
            resolve_supervisor_url(Some(inherited.clone()), &dir, Some(inherited.as_str()))
                .as_deref(),
            Some(inherited.as_str())
        );

        // A live supervisor records its endpoint. While the inherited endpoint
        // is healthy it still wins...
        std::fs::write(
            dir.join(SUPERVISOR_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(dir.join(SUPERVISOR_PORT_FILE), "50596").unwrap();
        assert_eq!(
            resolve_supervisor_url(Some(inherited.clone()), &dir, None).as_deref(),
            Some(inherited.as_str())
        );

        // ...but once it fails, the daemon follows the live successor instead of
        // heartbeating an idled-out port for the rest of its life.
        assert_eq!(
            resolve_supervisor_url(Some(inherited.clone()), &dir, Some(inherited.as_str()))
                .as_deref(),
            Some("http://127.0.0.1:50596")
        );

        // A recorded supervisor that is no longer alive is not adopted. This
        // read-only discovery path preserves its files; conditional retirement
        // belongs to the CLI's lifecycle + singleton authority.
        #[cfg(unix)]
        {
            std::fs::write(dir.join(SUPERVISOR_PID_FILE), "999999999").unwrap();
            std::fs::write(dir.join(SUPERVISOR_PORT_FILE), "50596").unwrap();
            assert_eq!(
                resolve_supervisor_url(Some(inherited.clone()), &dir, Some(inherited.as_str()))
                    .as_deref(),
                Some(inherited.as_str())
            );
            assert!(dir.join(SUPERVISOR_PID_FILE).exists());
            assert!(dir.join(SUPERVISOR_PORT_FILE).exists());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn registry_records_the_managed_home_a_daemon_reports() {
        let state = Arc::new(SupervisorState::new());
        let payload = repo_payload_in_home("instance-a", 49152, "/scratch/home/.kin");

        let response = register_repo(router(Arc::clone(&state)), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        assert_eq!(repos.get("demo").unwrap().kin_home, "/scratch/home/.kin");
    }

    /// One machine-wide supervisor legitimately holds daemons from several
    /// managed homes. That is the whole premise of the scoping contract, so it
    /// is asserted rather than assumed.
    #[tokio::test]
    async fn one_supervisor_holds_daemons_from_two_homes() {
        let state = Arc::new(SupervisorState::new());
        let app = router(Arc::clone(&state));

        let mut a = repo_payload_in_home("instance-a", 49152, "/homes/a/.kin");
        a.repo_id = "repo-a".to_string();
        let mut b = repo_payload_in_home("instance-b", 49153, "/homes/b/.kin");
        b.repo_id = "repo-b".to_string();

        assert_eq!(
            register_repo(app.clone(), &a).await.status(),
            StatusCode::OK
        );
        assert_eq!(register_repo(app, &b).await.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        assert_eq!(repos.get("repo-a").unwrap().kin_home, "/homes/a/.kin");
        assert_eq!(repos.get("repo-b").unwrap().kin_home, "/homes/b/.kin");
    }

    /// A daemon that reports no home must stay unrecorded. The supervisor's own
    /// environment is a different process's home, and substituting it would
    /// manufacture a match that lets a scoped stop reach a foreign daemon.
    #[tokio::test]
    async fn an_unreported_home_is_never_filled_in_from_the_supervisor() {
        let state = Arc::new(SupervisorState::new());
        let payload = repo_payload_in_home("instance-a", 49152, "   ");

        let response = register_repo(router(Arc::clone(&state)), &payload).await;
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        assert!(repos.get("demo").unwrap().kin_home.is_empty());
    }

    /// A registration from a binary predating the field omits it entirely.
    #[test]
    fn a_registration_without_the_field_deserializes_as_unrecorded() {
        let json = serde_json::json!({
            "repo_id": "demo",
            "repo_root": "/tmp/demo",
            "pid": 1234,
            "port": 49152,
            "endpoint": "http://127.0.0.1:49152",
        });
        let payload: RepoDaemonRegistration = serde_json::from_value(json).unwrap();
        assert!(payload.kin_home.is_empty());
        assert!(kin_home_for_payload(&payload).is_empty());
    }

    #[tokio::test]
    async fn a_heartbeat_keeps_the_recorded_home_current() {
        let state = Arc::new(SupervisorState::new());
        let app = router(Arc::clone(&state));
        let payload = repo_payload_in_home("instance-a", 49152, "/homes/a/.kin");
        assert_eq!(
            register_repo(app.clone(), &payload).await.status(),
            StatusCode::OK
        );

        let moved = RepoDaemonRegistration {
            kin_home: "/homes/moved/.kin".to_string(),
            ..payload.clone()
        };
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::post("/daemons/demo/heartbeat")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&moved).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let repos = state.repo_daemons.read().await;
        assert_eq!(repos.get("demo").unwrap().kin_home, "/homes/moved/.kin");
    }
}
