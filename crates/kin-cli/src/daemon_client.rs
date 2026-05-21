// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP client and lifecycle helpers for the kin daemon.
//!
//! Used by CLI commands to query the daemon's live graph instead of
//! opening a snapshot directly. Also owns the repo-scoped daemon
//! auto-start logic so the CLI does not need to depend on `kin-daemon`.

use anyhow::{anyhow, bail, Context, Result};
use kin_core::KinLayout;
use serde::Deserialize;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Response from `GET /health`.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

/// A single entity entry from the daemon's entity search.
#[derive(Debug, Deserialize)]
pub struct DaemonEntityEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
}

/// Response from `GET /repos/{repo_id}/entities`.
#[derive(Debug, Deserialize)]
pub struct DaemonEntitiesResponse {
    pub repo_id: String,
    pub entities: Vec<DaemonEntityEntry>,
}

/// Response from `GET /status`.
#[derive(Debug, Deserialize)]
pub struct DaemonStatusResponse {
    pub base_change: String,
    pub entity_adds: usize,
    pub entity_mods: usize,
    pub entity_removes: usize,
    pub relation_adds: usize,
    pub relation_removes: usize,
}

/// Response from scope endpoints.
#[derive(Debug, Deserialize)]
pub struct ScopeResponse {
    pub ref_string: String,
    pub head: String,
    pub created_at_secs_ago: u64,
    pub ttl_remaining_secs: u64,
}

/// Client for the kin daemon HTTP API.
pub struct DaemonClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocateRequest {
    pub text: String,
    pub explain: bool,
    pub max_files: usize,
    pub max_files_explicit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl DaemonClient {
    pub fn from_base_url(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .context("build daemon client")?;
        Ok(Self { base_url, client })
    }

    /// Try to connect to the daemon. Returns `None` if the daemon is
    /// unreachable or unhealthy.
    pub async fn try_connect() -> Option<Self> {
        let base =
            std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

        let client = Self::from_base_url(base.clone()).ok()?.client;

        // Probe health endpoint
        let resp = client.get(format!("{}/health", base)).send().await.ok()?;

        if resp.status().is_success() {
            Some(Self {
                base_url: base,
                client,
            })
        } else {
            None
        }
    }

    /// Get the daemon's health response (includes entity count, uptime, etc.).
    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await?)
    }

    /// Get the working copy status from the daemon.
    pub async fn status(&self) -> anyhow::Result<DaemonStatusResponse> {
        let resp = self
            .client
            .get(format!("{}/status", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await?)
    }

    /// Search entities via the multi-repo API.
    ///
    /// Uses `GET /repos/{repo_id}/entities?query=<pattern>`.
    /// The `repo_id` is derived from the `.kin/` directory name.
    pub async fn search_entities(
        &self,
        repo_id: &str,
        query: Option<&str>,
    ) -> anyhow::Result<Vec<DaemonEntityEntry>> {
        let mut url = format!("{}/repos/{}/entities", self.base_url, repo_id);
        if let Some(q) = query {
            url = format!("{}?query={}", url, urlencoding::encode(q));
        }
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        let body: DaemonEntitiesResponse = resp.json().await?;
        Ok(body.entities)
    }

    /// Get the entity count from the daemon health endpoint.
    pub async fn entity_count(&self) -> anyhow::Result<usize> {
        let health = self.health().await?;
        Ok(health.graph_entity_count.unwrap_or(0))
    }

    /// Return the base URL of the connected daemon.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn locate(
        &self,
        request: &LocateRequest,
    ) -> Result<crate::commands::locate::LocateResult> {
        let resp = self
            .client
            .post(format!("{}/locate", self.base_url))
            .json(request)
            .send()
            .await
            .context("send daemon locate request")?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon locate error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await.context("parse daemon locate response")?)
    }

    pub async fn set_scope(&self, session_id: &str, ref_string: &str) -> Result<ScopeResponse> {
        let resp = self
            .client
            .post(format!("{}/session/{}/scope", self.base_url, session_id))
            .json(&serde_json::json!({ "ref_string": ref_string }))
            .send()
            .await
            .context("send set_scope request")?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await.context("parse scope response")?)
    }

    pub async fn clear_scope(&self, session_id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/session/{}/scope", self.base_url, session_id))
            .send()
            .await
            .context("send clear_scope request")?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(())
    }

    pub async fn get_scope(&self, session_id: &str) -> Result<Option<ScopeResponse>> {
        let resp = self
            .client
            .get(format!("{}/session/{}/scope", self.base_url, session_id))
            .send()
            .await
            .context("send get_scope request")?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(Some(resp.json().await.context("parse scope response")?))
    }
}

fn is_transient_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn daemon_required() -> bool {
    true
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

fn is_port_open(port: u16) -> bool {
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveDaemonEndpoint {
    pid: u32,
    port: u16,
}

fn remove_stale_daemon_files(kin_root: &Path) {
    let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
    let _ = std::fs::remove_file(kin_root.join("daemon.port"));
}

fn read_pid_file(kin_root: &Path) -> Option<u32> {
    std::fs::read_to_string(kin_root.join("daemon.pid"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn live_daemon_endpoint(kin_root: &Path) -> Option<LiveDaemonEndpoint> {
    let pid = read_pid_file(kin_root)?;
    if !is_process_alive(pid) {
        remove_stale_daemon_files(kin_root);
        return None;
    }
    let port = read_port_file(kin_root)?;
    Some(LiveDaemonEndpoint { pid, port })
}

pub fn daemon_is_up(kin_root: &Path) -> Option<u16> {
    let port = live_daemon_endpoint(kin_root)?.port;
    if is_port_open(port) {
        Some(port)
    } else {
        None
    }
}

fn find_free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

fn find_daemon_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("KIN_DAEMON_BIN") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
        if exe
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
                let target_sibling = target_dir.join("kin-daemon");
                if target_sibling.exists() {
                    return Some(target_sibling);
                }
            }
        }
    }
    which::which("kin-daemon").ok()
}

fn daemon_ready_timeout_secs() -> u64 {
    std::env::var("KIN_DAEMON_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15)
}

fn default_idle_timeout_secs() -> &'static str {
    if cfg!(test) {
        "1"
    } else {
        "60"
    }
}

fn existing_daemon_ready_timeout_secs() -> u64 {
    std::env::var("KIN_DAEMON_EXISTING_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3)
}

fn startup_lock_timeout_secs() -> u64 {
    std::env::var("KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| daemon_ready_timeout_secs().max(5))
}

fn daemon_health_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .unwrap_or_default()
}

fn daemon_log_path(kin_root: &Path) -> PathBuf {
    kin_root.join("daemon.log")
}

fn open_daemon_log(kin_root: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(daemon_log_path(kin_root))
        .with_context(|| format!("open daemon log at {}", daemon_log_path(kin_root).display()))
}

fn daemon_log_tail(kin_root: &Path) -> String {
    let path = daemon_log_path(kin_root);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return format!("daemon log unavailable at {}", path.display());
    };
    let lines: Vec<&str> = content.lines().rev().take(20).collect();
    if lines.is_empty() {
        return format!("daemon log is empty at {}", path.display());
    }
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn canonical_path_string(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn validate_health_repo(health: &HealthResponse, working_dir: &Path) -> Result<()> {
    if health.status != "ok" {
        bail!("daemon health status is {}", health.status);
    }
    if let Some(repo_root) = health.repo_root.as_deref() {
        let expected = canonical_path_string(working_dir);
        if repo_root != expected {
            bail!(
                "daemon repo mismatch: endpoint is for {}, expected {}",
                repo_root,
                expected
            );
        }
    }
    Ok(())
}

struct StartupLock {
    path: PathBuf,
    _file: File,
}

impl Drop for StartupLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn startup_lock_is_stale(path: &Path, stale_after: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .map(|elapsed| elapsed > stale_after)
        .unwrap_or(false)
}

async fn acquire_startup_lock(kin_root: &Path) -> Result<StartupLock> {
    let path = kin_root.join("daemon.start.lock");
    let timeout = Duration::from_secs(startup_lock_timeout_secs());
    let stale_after = timeout.saturating_mul(2).max(Duration::from_secs(10));
    let deadline = Instant::now() + timeout;

    loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(
                    file,
                    "pid={} acquired_at={:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                );
                return Ok(StartupLock { path, _file: file });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if startup_lock_is_stale(&path, stale_after) {
                    warn!(path = %path.display(), "removing stale daemon startup lock");
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if Instant::now() >= deadline {
                    bail!(
                        "timed out waiting for daemon startup lock at {}",
                        path.display()
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("create daemon startup lock at {}", path.display()));
            }
        }
    }
}

async fn validate_daemon_endpoint(
    kin_root: &Path,
    endpoint: LiveDaemonEndpoint,
    timeout: Duration,
) -> Result<String> {
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| anyhow!("invalid .kin layout: no parent"))?;
    let base_url = format!("http://127.0.0.1:{}", endpoint.port);
    let client = daemon_health_client();
    let deadline = Instant::now() + timeout;

    loop {
        if !is_process_alive(endpoint.pid) {
            remove_stale_daemon_files(kin_root);
            bail!("recorded daemon process {} is not alive", endpoint.pid);
        }

        let probe_error = match client.get(format!("{base_url}/readiness")).send().await {
            Ok(resp) if resp.status().is_success() => {
                let health: HealthResponse = client
                    .get(format!("{base_url}/health"))
                    .send()
                    .await
                    .context("probe daemon health")?
                    .error_for_status()
                    .context("daemon health returned an error")?
                    .json()
                    .await
                    .context("parse daemon health response")?;
                validate_health_repo(&health, working_dir)?;
                return Ok(base_url);
            }
            Ok(resp) => format!("readiness returned HTTP {}", resp.status()),
            Err(err) => err.to_string(),
        };

        if Instant::now() >= deadline {
            bail!(
                "daemon pid {} on {} failed readiness within {:.1}s: {}",
                endpoint.pid,
                base_url,
                timeout.as_secs_f64(),
                probe_error
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_daemon_ready(
    kin_root: &Path,
    child: &mut Child,
    port: u16,
    deadline: Instant,
) -> Result<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let base_url = format!("http://127.0.0.1:{port}");
    let mut last_error = String::from("daemon did not bind");

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("check daemon child status")? {
            bail!(
                "daemon exited during startup with status {status}; recent log:\n{}",
                daemon_log_tail(kin_root)
            );
        }

        if is_port_open(port) {
            match client.get(format!("{base_url}/readiness")).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let health_result: Result<HealthResponse> = async {
                        Ok(client
                            .get(format!("{base_url}/health"))
                            .send()
                            .await
                            .context("probe daemon health")?
                            .error_for_status()
                            .context("daemon health returned an error")?
                            .json()
                            .await
                            .context("parse daemon health response")?)
                    }
                    .await;
                    match health_result.and_then(|health| {
                        let working_dir = kin_root
                            .parent()
                            .ok_or_else(|| anyhow!("invalid .kin layout: no parent"))?;
                        validate_health_repo(&health, working_dir)
                    }) {
                        Ok(()) => return Ok(base_url),
                        Err(err) => last_error = err.to_string(),
                    }
                }
                Ok(resp) => {
                    last_error = format!("readiness returned HTTP {}", resp.status());
                }
                Err(err) => {
                    last_error = err.to_string();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    bail!(
        "daemon failed to become ready within {:.1}s: {}; recent log:\n{}",
        timeout.as_secs_f64(),
        last_error,
        daemon_log_tail(kin_root)
    )
}

async fn wait_for_existing_daemon(kin_root: &Path) -> Option<String> {
    let existing = live_daemon_endpoint(kin_root)?;
    match validate_daemon_endpoint(
        kin_root,
        existing,
        Duration::from_secs(existing_daemon_ready_timeout_secs()),
    )
    .await
    {
        Ok(base_url) => {
            info!(
                pid = existing.pid,
                port = existing.port,
                "connected to existing daemon"
            );
            Some(base_url)
        }
        Err(err) => {
            warn!(
                pid = existing.pid,
                port = existing.port,
                error = %err,
                "invalid daemon endpoint; clearing stale endpoint files"
            );
            remove_stale_daemon_files(kin_root);
            None
        }
    }
}

pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String> {
    if let Some(base_url) = wait_for_existing_daemon(kin_root).await {
        return Ok(base_url);
    }

    let _startup_lock = acquire_startup_lock(kin_root).await?;
    if let Some(base_url) = wait_for_existing_daemon(kin_root).await {
        return Ok(base_url);
    }

    let daemon_bin = find_daemon_binary().ok_or_else(|| anyhow!("kin-daemon binary not found"))?;
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| anyhow!("invalid .kin layout: no parent"))?;
    let port = find_free_port().unwrap_or(4219);

    info!(binary = %daemon_bin.display(), repo = %working_dir.display(), port, "starting daemon");

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args([
        "--repo",
        &working_dir.display().to_string(),
        "--port",
        &port.to_string(),
    ]);
    let log = open_daemon_log(kin_root)?;
    let stderr = log
        .try_clone()
        .context("clone daemon log handle for stderr")?;
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(stderr));
    if std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_none() {
        cmd.env("KIN_DAEMON_IDLE_TIMEOUT_SECS", default_idle_timeout_secs());
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn kin-daemon for {}", working_dir.display()))?;

    let timeout_secs = daemon_ready_timeout_secs();
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let base_url = wait_for_daemon_ready(kin_root, &mut child, port, deadline).await?;
    info!(port, "daemon is up and ready");
    Ok(base_url)
}

/// Like resolve_daemon_url, but never auto-starts a daemon.
/// Returns the daemon URL only if one is already running or explicitly configured.
pub fn resolve_daemon_url_if_running(layout: &KinLayout) -> Option<String> {
    if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        return Some(url);
    }
    daemon_is_up(layout.root()).map(|port| format!("http://127.0.0.1:{port}"))
}

pub async fn resolve_daemon_url(layout: &KinLayout) -> Result<Option<String>> {
    let no_daemon_autostart = is_transient_bool_env("KIN_NO_DAEMON");
    let explicit_daemon_url = std::env::var("KIN_DAEMON_URL").ok();
    if no_daemon_autostart {
        if let Some(url) = explicit_daemon_url {
            return Ok(Some(url));
        }
        return Ok(wait_for_existing_daemon(layout.root()).await);
    }

    match ensure_daemon_running(layout.root()).await {
        Ok(url) => Ok(Some(url)),
        Err(err) => Err(err.context("kin daemon is required")),
    }
}

/// Simple percent-encoding for query parameters.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_daemon_endpoint_returns_alive_pid_even_before_port_binds() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        std::fs::write(
            dir.path().join("daemon.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(dir.path().join("daemon.port"), port.to_string()).unwrap();

        let endpoint = live_daemon_endpoint(dir.path()).unwrap();
        assert_eq!(endpoint.pid, std::process::id());
        assert_eq!(endpoint.port, port);
        assert_eq!(daemon_is_up(dir.path()), None);
    }

    #[test]
    fn daemon_is_up_returns_listening_port() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(
            dir.path().join("daemon.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(dir.path().join("daemon.port"), port.to_string()).unwrap();

        assert_eq!(daemon_is_up(dir.path()), Some(port));
    }

    #[test]
    fn live_daemon_endpoint_cleans_stale_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "999999999").unwrap();
        std::fs::write(dir.path().join("daemon.port"), "4219").unwrap();

        assert_eq!(live_daemon_endpoint(dir.path()), None);
        assert!(!dir.path().join("daemon.pid").exists());
        assert!(!dir.path().join("daemon.port").exists());
    }

    #[test]
    fn health_validation_rejects_wrong_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let health = HealthResponse {
            status: "ok".to_string(),
            version: "test".to_string(),
            uptime_seconds: 0,
            graph_entity_count: Some(0),
            graph_loaded: false,
            reconciliation_status: "idle".to_string(),
            repo_id: Some("wrong".to_string()),
            repo_root: Some(canonical_path_string(other.path())),
            pid: Some(std::process::id()),
        };

        let error = validate_health_repo(&health, dir.path()).unwrap_err();
        assert!(error.to_string().contains("daemon repo mismatch"));
    }

    #[test]
    fn startup_lock_staleness_uses_modified_time() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("daemon.start.lock");
        std::fs::write(&lock, "pid=1").unwrap();

        assert!(startup_lock_is_stale(&lock, Duration::ZERO));
        assert!(!startup_lock_is_stale(&lock, Duration::from_secs(60)));
    }
}
