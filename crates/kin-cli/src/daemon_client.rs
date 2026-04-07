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
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tracing::info;

/// Response from `GET /health`.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
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
}

fn is_transient_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
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

fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

pub fn daemon_is_up(kin_root: &Path) -> Option<u16> {
    let pid: u32 = std::fs::read_to_string(kin_root.join("daemon.pid"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if !is_process_alive(pid) {
        let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
        let _ = std::fs::remove_file(kin_root.join("daemon.port"));
        return None;
    }
    let port = read_port_file(kin_root)?;
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
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    which::which("kin-daemon").ok()
}

pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String> {
    if let Some(port) = daemon_is_up(kin_root) {
        return Ok(format!("http://127.0.0.1:{port}"));
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
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

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

    cmd.spawn()
        .with_context(|| format!("spawn kin-daemon for {}", working_dir.display()))?;

    let timeout_secs = std::env::var("KIN_DAEMON_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let base_url = format!("http://127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

    // Phase 1: wait for TCP port to bind (fast, avoids HTTP overhead)
    while std::time::Instant::now() < deadline {
        if is_port_open(port) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Phase 2: wait for /health to return 200 (real readiness)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .unwrap_or_default();
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await {
            if resp.status().is_success() {
                info!(port, "daemon is up and healthy");
                return Ok(base_url);
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    bail!("daemon failed to become healthy within {}s", timeout_secs)
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
        return Ok(explicit_daemon_url.or_else(|| {
            daemon_is_up(layout.root()).map(|port| format!("http://127.0.0.1:{port}"))
        }));
    }

    match ensure_daemon_running(layout.root()).await {
        Ok(url) => Ok(Some(url)),
        Err(err) => {
            tracing::warn!(error = %err, "daemon auto-start failed");
            Ok(None)
        }
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
