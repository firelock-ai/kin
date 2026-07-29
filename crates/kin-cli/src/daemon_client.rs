// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP client and lifecycle helpers for the kin daemon.
//!
//! Used by CLI commands to query the daemon's live graph instead of
//! opening a snapshot directly. Also owns the repo-scoped daemon
//! auto-start logic so the CLI does not need to depend on `kin-daemon`.

use anyhow::{anyhow, bail, Context, Result};
use fs2::FileExt;
use kin_core::KinLayout;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

pub(crate) mod probe_process;

static BUILD_MISMATCH_REPORTED: AtomicBool = AtomicBool::new(false);
const DAEMON_BINARY_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Stable failure contract for callers that delegate repository-daemon
/// autostart to this crate.
///
/// The daemon crate re-exports this type. Keeping the classification at the
/// source prevents rendered error text from becoming a second, accidental
/// protocol between the two crates.
#[derive(Debug, thiserror::Error)]
pub enum AutoStartError {
    #[error("kin-daemon binary not found (not in PATH or next to kin binary)")]
    BinaryNotFound,
    #[error("daemon startup failed: {0}")]
    SpawnFailed(String),
    #[error("daemon failed to become ready before the startup deadline: {0}")]
    StartupTimeout(String),
    #[error("invalid .kin layout: {0}")]
    InvalidLayout(String),
}

impl AutoStartError {
    fn spawn(error: impl std::fmt::Display) -> Self {
        Self::SpawnFailed(error.to_string())
    }
}

fn scrub_daemon_process_authority(command: &mut Command) {
    kin_daemon_spawn::scrub_daemon_process_authority(command);
}

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
    /// Exact local workspace authority served by the daemon. Two clones share
    /// `repo_id`, so repository identity alone can never authorize routing a
    /// local command to an endpoint.
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    /// Behavior-relevant environment the daemon captured at start (see
    /// `kin_core::behavior_env`). Empty when the daemon predates this surface,
    /// which yields no divergence rather than a false one.
    #[serde(default)]
    pub behavior_env: kin_core::behavior_env::BehaviorEnv,
    #[serde(default)]
    pub build: Option<BuildResponse>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BuildResponse {
    pub sha: String,
    pub dirty: bool,
    #[serde(default)]
    pub source_known: bool,
    #[serde(default)]
    pub dependency_provenance: String,
    pub built_at: String,
}

/// Response from `GET /readiness`.
///
/// `warming` is the daemon's explicit "alive but still materializing a
/// cross-repo warm-up" signal. A client must never read a slow readiness as
/// evidence that the daemon is dead.
#[derive(Debug, Default, Deserialize)]
struct ReadinessResponse {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    warming: bool,
}

#[derive(Debug, Deserialize)]
struct SupervisorHealthResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct SupervisorRouteResponse {
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct DaemonCompatResponse {
    #[serde(default)]
    schema: String,
    graph_snapshot_version: u32,
    #[serde(default)]
    supervisor_startup_protocol: Option<u32>,
    #[serde(default)]
    supervisor_startup_capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SupervisorRegistration {
    repo_id: String,
    display_name: String,
    instance_id: String,
    repo_root: String,
    pid: u32,
    port: u16,
    endpoint: String,
    graph_entity_count: Option<usize>,
}

/// A repo worker daemon as recorded by the per-user supervisor's `/daemons`
/// registry. Mirrors the supervisor's own `RegisteredRepoDaemon` payload; shared
/// by `kin registry daemons` and `kin daemon status`/`stop` so the supervisor
/// listing plumbing lives in one place.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default)]
    pub registered_at: Option<String>,
    #[serde(default)]
    pub last_heartbeat_at: String,
}

/// Fetch the repo daemons registered with a running supervisor via `GET
/// /daemons`. The caller supplies a supervisor URL it already resolved (e.g. via
/// [`ensure_supervisor_running`] or [`supervisor_recorded_endpoint`]); this does
/// not itself start a supervisor.
pub async fn fetch_registered_daemons(supervisor_url: &str) -> Result<Vec<RegisteredRepoDaemon>> {
    let daemons = reqwest::Client::new()
        .get(format!("{}/daemons", supervisor_url.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(daemons)
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

/// Response from scope endpoints.
#[derive(Debug, Deserialize)]
pub struct ScopeResponse {
    pub ref_string: String,
    pub head: String,
    pub created_at_secs_ago: u64,
    pub ttl_remaining_secs: u64,
}

/// Client for the kin daemon HTTP API.
#[derive(Clone)]
pub struct DaemonClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocateRequest {
    pub text: String,
    /// Additional query variants for multi-query fan-out. When non-empty the
    /// daemon retrieves `text` plus each variant independently and RRF-fuses the
    /// rankings into one deduped result, with per-hit variant attribution. Empty
    /// (the default) is a single-query locate, serialized identically to before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<String>,
    pub explain: bool,
    pub max_files: usize,
    pub max_files_explicit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// When true, the daemon attaches a bounded inline source snippet to each
    /// top definition symbol of every located file (the structured/agent JSON
    /// surface). Defaults to false so existing clients and human output are
    /// unchanged.
    #[serde(default)]
    pub snippets: bool,
    /// Optional override for the snippet line budget (`KIN_LOCATE_SNIPPET_LINES`
    /// otherwise). Only meaningful when `snippets` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet_lines: Option<usize>,
    /// Opaque paging cursor (`<key>.<page>`) from a prior locate's `next_cursor`.
    /// When set and the daemon still holds the matching ranking, the next page of
    /// ENTITIES is sliced from cache with NO retrieval re-run; on a cache miss or
    /// a graph-version change the daemon transparently re-runs retrieval and
    /// returns page 0. Absent for a first/fresh query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Entities per page for the graph-native `entities` surface
    /// (`KIN_LOCATE_ENTITY_CAP` otherwise). Only affects entity paging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
}

/// Resolve the bearer token the daemon expects on non-public routes.
///
/// Matches the daemon's own `resolve_serve_auth_token` order:
/// `KIN_DAEMON_AUTH_TOKEN` env if set, else the auto-provisioned per-install
/// `.kin/daemon.token` file, else none. `pub(crate)` so any other in-crate
/// caller that builds its own client for a direct daemon request (rather
/// than going through `DaemonClient`, which attaches this automatically)
/// can still authenticate correctly.
pub(crate) fn resolve_daemon_auth_token() -> Option<String> {
    if let Some(token) = daemon_auth_token_from_env() {
        return Some(token);
    }
    let layout = std::env::current_dir()
        .ok()
        .and_then(|cwd| KinLayout::discover(&cwd))?;
    daemon_auth_token_from_layout(&layout)
}

/// Layout-explicit variant for callers that already hold the repo's layout.
///
/// The explicit environment token is endpoint configuration and retains the
/// same precedence as the daemon's own startup path. The layout token is the
/// auto-provisioned fallback.
pub(crate) fn resolve_daemon_auth_token_for_layout(layout: &KinLayout) -> Option<String> {
    daemon_auth_token_from_env().or_else(|| daemon_auth_token_from_layout(layout))
}

fn daemon_auth_token_from_env() -> Option<String> {
    let token = std::env::var("KIN_DAEMON_AUTH_TOKEN")
        .ok()?
        .trim()
        .to_string();
    (!token.is_empty()).then_some(token)
}

fn daemon_auth_token_from_layout(layout: &KinLayout) -> Option<String> {
    let token = std::fs::read_to_string(layout.root().join("daemon.token"))
        .ok()?
        .trim()
        .to_string();
    (!token.is_empty()).then_some(token)
}

fn daemon_client_headers(
    auth_token: Option<String>,
    session_id: Option<&str>,
) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(session_id) = session_id.filter(|value| !value.trim().is_empty()) {
        let header_val = reqwest::header::HeaderValue::from_str(session_id)
            .context("invalid explicit Kin session header")?;
        headers.insert("X-Kin-Session", header_val);
    }
    let build = kin_buildinfo::get();
    if let Ok(value) = reqwest::header::HeaderValue::from_str(build.sha) {
        headers.insert("X-Kin-CLI-Sha", value);
    }
    headers.insert(
        "X-Kin-CLI-Dirty",
        reqwest::header::HeaderValue::from_static(if build.dirty { "true" } else { "false" }),
    );
    if let Some(token) = auth_token {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid daemon bearer token header")?;
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    Ok(headers)
}

impl DaemonClient {
    pub fn from_base_url(base_url: impl Into<String>) -> Result<Self> {
        Self::from_base_url_with_token(base_url, resolve_daemon_auth_token())
    }

    /// Build a client for `layout`'s daemon, resolving the bearer token from
    /// that layout rather than from the process working directory.
    pub fn from_base_url_for_layout(
        base_url: impl Into<String>,
        layout: &KinLayout,
    ) -> Result<Self> {
        Self::from_base_url_with_token(base_url, resolve_daemon_auth_token_for_layout(layout))
    }

    fn from_base_url_with_token(
        base_url: impl Into<String>,
        auth_token: Option<String>,
    ) -> Result<Self> {
        let ambient_session = std::env::var("KIN_SESSION_ID")
            .ok()
            .filter(|value| !value.trim().is_empty());
        Self::from_base_url_with_explicit_authority(
            base_url,
            auth_token,
            ambient_session.as_deref(),
        )
    }

    /// Construct a client whose endpoint, bearer token, and optional session
    /// identity were already verified together. Unlike the compatibility
    /// constructors, this never reads ambient session authority.
    pub(crate) fn from_base_url_with_explicit_authority(
        base_url: impl Into<String>,
        auth_token: Option<String>,
        session_id: Option<&str>,
    ) -> Result<Self> {
        let base_url = base_url.into();
        let headers = daemon_client_headers(auth_token, session_id)?;
        let request_timeout = std::env::var("KIN_DAEMON_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&secs| secs > 0)
            .unwrap_or(300);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(request_timeout))
            .connect_timeout(Duration::from_secs(2))
            .default_headers(headers)
            .build()
            .context("build daemon client")?;
        Ok(Self { base_url, client })
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        context: &'static str,
    ) -> Result<reqwest::Response> {
        let resp = request.send().await.context(context)?;
        check_response_build_match(resp.headers())?;
        Ok(resp)
    }

    /// Try to connect to the daemon. Returns `None` if the daemon is
    /// unreachable or unhealthy.
    pub async fn try_connect() -> Option<Self> {
        let base = std::env::var("KIN_DAEMON_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;

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
            .send(
                self.client.get(format!("{}/health", self.base_url)),
                "send daemon health request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await?)
    }

    /// Compare this command's behavior-relevant environment against what the
    /// running daemon captured at start, and surface any divergence.
    ///
    /// A repo daemon is a long-lived per-user singleton: it inherited its
    /// environment from whichever command first started it, and later commands
    /// reach it over HTTP without re-exporting their own environment. So a
    /// behavior knob set on *this* command (e.g. `KIN_EMBED_HYBRID`) is silently
    /// ignored by the already-running worker. This makes that mismatch loud.
    ///
    /// Best-effort: if the daemon cannot be reached, or predates the
    /// `behavior_env` health field, this is a no-op — the command's own request
    /// still surfaces any genuine connectivity failure, so the check never
    /// double-reports one. On divergence it warns to stderr; under
    /// `KIN_STRICT_BEHAVIOR_ENV` it returns an error so scripted and proof runs
    /// fail closed instead of measuring the wrong lever.
    pub async fn warn_on_behavior_env_divergence(&self) -> Result<()> {
        let Ok(health) = self.health().await else {
            return Ok(());
        };
        let divergences = kin_core::behavior_env::compare(
            &kin_core::behavior_env::snapshot_from_process(),
            &health.behavior_env,
        );
        report_behavior_env_divergence(
            &divergences,
            is_transient_bool_env("KIN_STRICT_BEHAVIOR_ENV"),
        )
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
        let resp = self
            .send(self.client.get(&url), "send daemon entity search request")
            .await?;
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

    /// POST one caller-idempotent JSON command, retrying once with the exact
    /// same payload when transport or server acknowledgement is ambiguous.
    ///
    /// The client owns the daemon auth, build, and ambient session headers, so
    /// command modules must use this rather than constructing a raw HTTP
    /// client that silently changes request authority.
    pub(crate) async fn post_idempotent_json<Req, Resp>(
        &self,
        path: &str,
        payload: &Req,
        context: &'static str,
    ) -> Result<Resp>
    where
        Req: serde::Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let payload = serde_json::to_vec(payload)
            .with_context(|| format!("encode idempotent daemon request for {path}"))?;
        let mut last_error = None;
        for attempt in 0..2 {
            let response = match self
                .send(
                    self.client
                        .post(&url)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(payload.clone()),
                    context,
                )
                .await
            {
                Ok(response) => response,
                Err(error) if attempt == 0 => {
                    last_error = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            if response.status().is_success() {
                let body = match response.bytes().await {
                    Ok(body) => body,
                    Err(error) if attempt == 0 => {
                        last_error = Some(
                            anyhow::Error::new(error)
                                .context(format!("read daemon response body for {path}")),
                        );
                        continue;
                    }
                    Err(error) => {
                        return Err(anyhow::Error::new(error)
                            .context(format!("read daemon response body for {path}")));
                    }
                };
                match serde_json::from_slice(&body) {
                    Ok(decoded) => return Ok(decoded),
                    Err(error) if attempt == 0 => {
                        last_error = Some(
                            anyhow::Error::new(error)
                                .context(format!("decode daemon response for {path}")),
                        );
                        continue;
                    }
                    Err(error) => {
                        return Err(anyhow::Error::new(error)
                            .context(format!("decode daemon response for {path}")));
                    }
                }
            }
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if status.is_server_error() && attempt == 0 {
                last_error = Some(anyhow::anyhow!(
                    "daemon command returned HTTP {status}: {body}"
                ));
                continue;
            }
            anyhow::bail!("daemon command failed (HTTP {status}): {body}");
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("daemon command produced no response")))
    }

    pub async fn locate(
        &self,
        request: &LocateRequest,
    ) -> Result<crate::commands::locate::LocateResult> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/locate", self.base_url))
                    .json(request),
                "send daemon locate request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon locate error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon locate response")
    }

    pub async fn search(
        &self,
        request: &crate::commands::search::DaemonSearchRequest,
    ) -> Result<crate::commands::search::DaemonSearchResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/search", self.base_url))
                    .json(request),
                "send daemon search request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon search error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon search response")
    }

    pub async fn support(&self) -> Result<crate::commands::support::SupportJson> {
        let resp = self
            .send(
                self.client.get(format!("{}/support", self.base_url)),
                "send daemon support request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon support error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon support response")
    }

    pub async fn context(
        &self,
        request: &crate::commands::context::ContextRequest,
    ) -> Result<crate::commands::context::ContextResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/context", self.base_url))
                    .json(request),
                "send daemon context request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon context error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon context response")
    }

    pub async fn trace(
        &self,
        request: &crate::commands::trace::TraceRequest,
    ) -> Result<crate::commands::trace::TraceResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/trace", self.base_url))
                    .json(request),
                "send daemon trace request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon trace error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon trace response")
    }

    pub async fn impact(
        &self,
        request: &crate::commands::impact::ImpactRequest,
    ) -> Result<crate::commands::impact::ImpactResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/impact", self.base_url))
                    .json(request),
                "send daemon impact request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon impact error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon impact response")
    }

    pub async fn review(
        &self,
        request: &crate::commands::review::ReviewRequest,
    ) -> Result<crate::commands::review::ReviewResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/review", self.base_url))
                    .json(request),
                "send daemon review request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon review error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon review response")
    }

    pub async fn embed(
        &self,
        request: &crate::commands::embed::EmbedRequest,
    ) -> Result<crate::commands::embed::EmbedResponse> {
        // Embed is a long, work-proportional operation, not a fast query: a
        // bounded pass spends its whole `max_seconds` compute budget plus the
        // per-batch index persistence whose cost grows with the graph, and an
        // unbounded full-repo embed can run for many minutes on a large graph.
        // The shared 300s client default is sized for queries and silently
        // severs a legitimate embed mid-flight — the dropped connection orphans
        // the server-side pass (it keeps running, holding the embedding lock),
        // so retries stack on a wedged daemon. Size the wait to the actual work:
        // honor an explicit KIN_EMBED_HTTP_TIMEOUT_SECS override, else give a
        // bounded pass its budget plus generous persistence headroom, and an
        // unbounded embed a high ceiling. The daemon's own `max_seconds` +
        // shutdown cancellation bound the work; the client just has to wait.
        let embed_timeout = std::env::var("KIN_EMBED_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| match request.max_seconds {
                Some(seconds) if seconds > 0 => {
                    Duration::from_secs(seconds.saturating_mul(2).saturating_add(300))
                }
                _ => Duration::from_secs(3600),
            });
        let resp = self
            .send(
                self.client
                    .post(format!("{}/embed", self.base_url))
                    .timeout(embed_timeout)
                    .json(request),
                "send daemon embed request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon embed error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon embed response")
    }

    pub async fn blame(
        &self,
        request: &crate::commands::blame::BlameRequest,
    ) -> Result<crate::commands::blame::BlameResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/blame", self.base_url))
                    .json(request),
                "send daemon blame request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon blame error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon blame response")
    }

    pub async fn history(
        &self,
        request: &crate::commands::history::HistoryRequest,
    ) -> Result<crate::commands::history::HistoryResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/history", self.base_url))
                    .json(request),
                "send daemon history request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon history error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon history response")
    }

    pub async fn verify_run(
        &self,
        request: &crate::commands::verify::VerifyRunRequest,
    ) -> Result<crate::commands::verify::VerifyRunResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/verify/run", self.base_url))
                    .json(request),
                "send daemon verify run request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon verify run error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon verify run response")
    }

    pub async fn verify_command(
        &self,
        request: &crate::commands::verify::VerifyCommandRequest,
    ) -> Result<crate::commands::verify::VerifyCommandResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/verify", self.base_url))
                    .json(request),
                "send daemon verify request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon verify error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon verify response")
    }

    pub async fn reconcile(
        &self,
        request: &crate::commands::reconcile::ReconcileRequest,
    ) -> Result<crate::commands::reconcile::ReconcileSummary> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/reconcile", self.base_url))
                    .json(request),
                "send daemon reconcile request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon reconcile error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon reconcile response")
    }

    pub async fn command_status(
        &self,
        request: &crate::commands::status::CommandStatusRequest,
    ) -> Result<crate::commands::status::CommandStatusResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/status", self.base_url))
                    .json(request),
                "send daemon command status request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon command status error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon command status response")
    }

    pub async fn command_push(
        &self,
        request: &crate::commands::transfer::CommandTransferRequest,
    ) -> Result<crate::commands::transfer::CommandTransferResponse> {
        self.transfer_command("push", request).await
    }

    pub async fn command_pull(
        &self,
        request: &crate::commands::transfer::CommandTransferRequest,
    ) -> Result<crate::commands::transfer::CommandTransferResponse> {
        self.transfer_command("pull", request).await
    }

    pub async fn command_transfer_plan(
        &self,
        request: &crate::commands::transfer::CommandTransferRequest,
    ) -> Result<crate::commands::transfer::CommandTransferPlanResponse> {
        self.transfer_command("transfer-plan", request).await
    }

    /// Drive one repository-v6 transfer command in the daemon.
    ///
    /// A refusal body is surfaced verbatim. The daemon has already mapped the
    /// transfer error class onto a status code, and rewording it here would
    /// hide which replica refused and why.
    async fn transfer_command<Resp: serde::de::DeserializeOwned>(
        &self,
        leaf: &str,
        request: &crate::commands::transfer::CommandTransferRequest,
    ) -> Result<Resp> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/{leaf}", self.base_url))
                    .json(request),
                "send daemon transfer command",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("kin {leaf} refused (HTTP {status}): {body}");
        }
        resp.json()
            .await
            .context("parse daemon transfer command response")
    }

    pub async fn command_resources(
        &self,
        request: &crate::commands::resources::CommandResourcesRequest,
    ) -> Result<crate::commands::resources::CommandResourcesResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/resources", self.base_url))
                    .json(request),
                "send daemon command resources request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon command resources error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon command resources response")
    }

    pub async fn graph_command(
        &self,
        request: &crate::commands::graph::GraphCommandRequest,
    ) -> Result<crate::commands::graph::GraphCommandResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/graph", self.base_url))
                    .json(request),
                "send daemon graph command request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon graph command error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon graph command response")
    }

    pub async fn overview(
        &self,
        request: &crate::commands::overview::OverviewRequest,
    ) -> Result<crate::commands::overview::OverviewResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/overview", self.base_url))
                    .json(request),
                "send daemon overview request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon overview error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon overview response")
    }

    pub async fn dead_code(
        &self,
        request: &crate::commands::dead_code::DeadCodeRequest,
    ) -> Result<crate::commands::dead_code::DeadCodeResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/dead-code", self.base_url))
                    .json(request),
                "send daemon dead-code request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon dead-code error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon dead-code response")
    }

    pub async fn dead_code_seeded(
        &self,
        request: &crate::commands::dead_code::DeadCodeSeededRequest,
    ) -> Result<crate::commands::dead_code::DeadCodeSeededResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/dead-code-seeded", self.base_url))
                    .json(request),
                "send daemon seeded dead-code request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon seeded dead-code error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon seeded dead-code response")
    }

    pub async fn trace_data_flow(
        &self,
        request: &crate::commands::trace_data_flow::TraceDataFlowRequest,
    ) -> Result<crate::commands::trace_data_flow::TraceDataFlowResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/trace-data-flow", self.base_url))
                    .json(request),
                "send daemon trace-data-flow request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon trace-data-flow error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon trace-data-flow response")
    }

    pub async fn refs(
        &self,
        request: &crate::commands::refs::RefsRequest,
    ) -> Result<crate::commands::refs::RefsResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/refs", self.base_url))
                    .json(request),
                "send daemon refs request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon refs error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon refs response")
    }

    pub async fn bulk_refs(
        &self,
        request: &crate::commands::refs::BulkRefsRequest,
    ) -> Result<crate::commands::refs::BulkRefsResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/bulk-refs", self.base_url))
                    .json(request),
                "send daemon bulk-refs request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon bulk-refs error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon bulk-refs response")
    }

    pub async fn xref(
        &self,
        request: &crate::commands::xref::XrefRequest,
    ) -> Result<crate::commands::xref::XrefResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/xref", self.base_url))
                    .json(request),
                "send daemon xref request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon xref error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon xref response")
    }

    pub async fn diff(
        &self,
        request: &crate::commands::diff::DiffRequest,
    ) -> Result<crate::commands::diff::DiffResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/diff", self.base_url))
                    .json(request),
                "send daemon diff request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon diff error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon diff response")
    }

    pub async fn log(
        &self,
        request: &crate::commands::log::LogRequest,
    ) -> Result<crate::commands::log::LogResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/log", self.base_url))
                    .json(request),
                "send daemon log request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon log error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon log response")
    }

    pub async fn audit(
        &self,
        request: &crate::commands::audit::AuditRequest,
    ) -> Result<crate::commands::audit::AuditResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/audit", self.base_url))
                    .json(request),
                "send daemon audit request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon audit error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon audit response")
    }

    pub async fn approvals(
        &self,
        request: &crate::commands::approvals::ApprovalsRequest,
    ) -> Result<crate::commands::approvals::ApprovalsResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/approvals", self.base_url))
                    .json(request),
                "send daemon approvals request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon approvals error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon approvals response")
    }

    pub async fn security(
        &self,
        request: &crate::commands::security::SecurityRequest,
    ) -> Result<crate::commands::security::SecurityResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/security", self.base_url))
                    .json(request),
                "send daemon security request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon security error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon security response")
    }

    pub async fn branch(
        &self,
        request: &crate::commands::branch::BranchRequest,
    ) -> Result<crate::commands::branch::BranchResponse> {
        self.post_idempotent_json(
            "/commands/branch",
            request,
            "send daemon-owned repository branch request",
        )
        .await
    }

    pub async fn merge(
        &self,
        request: &crate::commands::merge::MergeRequest,
    ) -> Result<crate::commands::merge::MergeResponse> {
        self.post_idempotent_json(
            "/commands/merge",
            request,
            "send daemon-owned repository merge request",
        )
        .await
    }

    pub async fn tag(
        &self,
        request: &crate::commands::tag::TagRequest,
    ) -> Result<crate::commands::tag::TagResponse> {
        self.post_idempotent_json(
            "/commands/tag",
            request,
            "send daemon-owned repository tag request",
        )
        .await
    }

    pub async fn stash(
        &self,
        request: &crate::commands::stash::StashRequest,
    ) -> Result<crate::commands::stash::StashResponse> {
        self.post_idempotent_json(
            "/commands/stash",
            request,
            "send daemon-owned repository stash request",
        )
        .await
    }

    pub async fn rollback(
        &self,
        request: &crate::commands::rollback::RollbackRequest,
    ) -> Result<crate::commands::rollback::RollbackResponse> {
        self.post_idempotent_json(
            "/commands/rollback",
            request,
            "send daemon-owned repository rollback request",
        )
        .await
    }

    pub async fn drift(
        &self,
        request: &crate::commands::drift::DriftRequest,
    ) -> Result<crate::commands::drift::DriftResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/drift", self.base_url))
                    .json(request),
                "send daemon-owned projection drift request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon drift error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon drift response")
    }

    pub async fn checkout(
        &self,
        request: &crate::commands::checkout::CheckoutRequest,
    ) -> Result<crate::commands::checkout::CheckoutResponse> {
        self.post_idempotent_json(
            "/commands/checkout",
            request,
            "send daemon-owned exact checkout request",
        )
        .await
    }

    pub async fn rename(
        &self,
        request: &crate::commands::rename::RenameRequest,
    ) -> Result<crate::commands::rename::RenameResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/rename", self.base_url))
                    .json(request),
                "send daemon rename request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon rename error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon rename response")
    }

    pub async fn session_workspace(
        &self,
        request: &crate::commands::session_workspace::SessionWorkspaceRequest,
    ) -> Result<crate::commands::session_workspace::SessionWorkspaceResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/commands/session-workspace", self.base_url))
                    .json(request),
                "send daemon session workspace request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon session workspace error (HTTP {}): {}", status, body);
        }
        resp.json()
            .await
            .context("parse daemon session workspace response")
    }

    /// Register a capability-scoped agent session bound to a session workspace.
    ///
    /// `pid` is the launching CLI process, which outlives the child it is about
    /// to run, so the daemon's liveness check tracks a process that is really
    /// there instead of reaping the lease out from under a working agent.
    pub async fn start_session(
        &self,
        vendor: &str,
        client_name: &str,
        cwd: &std::path::Path,
        pid: u32,
        capabilities: kin_model::session::SessionCapabilities,
    ) -> Result<String> {
        let body = serde_json::json!({
            "vendor": vendor,
            "client_name": client_name,
            "transport": "cli",
            "pid": pid,
            "cwd": cwd.display().to_string(),
            "capabilities": capabilities,
        });
        let resp = self
            .send(
                self.client
                    .post(format!("{}/session", self.base_url))
                    .json(&body),
                "send daemon session registration",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon session registration error (HTTP {status}): {body}");
        }
        let value: serde_json::Value = resp
            .json()
            .await
            .context("parse daemon session registration response")?;
        value
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("daemon session registration returned no session_id"))
    }

    /// Release a session lease registered by [`Self::start_session`].
    pub async fn end_session(&self, session_id: &str) -> Result<()> {
        let resp = self
            .send(
                self.client
                    .delete(format!("{}/session/{}", self.base_url, session_id)),
                "send daemon session end",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon session end error (HTTP {status}): {body}");
        }
        Ok(())
    }

    pub async fn work(
        &self,
        request: &crate::commands::work::WorkRequest,
    ) -> Result<crate::commands::work::WorkResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/work", self.base_url))
                    .json(request),
                "send daemon work request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon work error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon work response")
    }

    pub async fn note(
        &self,
        request: &crate::commands::note::NoteRequest,
    ) -> Result<crate::commands::note::NoteResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/note", self.base_url))
                    .json(request),
                "send daemon note request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon note error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse daemon note response")
    }

    pub async fn set_scope(&self, session_id: &str, ref_string: &str) -> Result<ScopeResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/session/{}/scope", self.base_url, session_id))
                    .json(&serde_json::json!({ "ref_string": ref_string })),
                "send set_scope request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon error (HTTP {}): {}", status, body);
        }
        resp.json().await.context("parse scope response")
    }

    pub async fn clear_scope(&self, session_id: &str) -> Result<()> {
        let resp = self
            .send(
                self.client
                    .delete(format!("{}/session/{}/scope", self.base_url, session_id)),
                "send clear_scope request",
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(())
    }

    pub async fn get_scope(&self, session_id: &str) -> Result<Option<ScopeResponse>> {
        let resp = self
            .send(
                self.client
                    .get(format!("{}/session/{}/scope", self.base_url, session_id)),
                "send get_scope request",
            )
            .await?;
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

fn header_str<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn build_id(sha: &str, dirty: bool) -> Option<String> {
    let sha = sha.trim();
    if sha.is_empty() || sha == "unknown" {
        return None;
    }
    if dirty {
        Some(format!("{sha}-dirty"))
    } else {
        Some(sha.to_string())
    }
}

fn build_mismatch_message(cli: &str, daemon: &str) -> String {
    format!("Kin build mismatch: CLI {cli} / daemon {daemon} - restart the daemon to match")
}

fn parse_boolish(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
}

fn build_match_error(cli: &str, daemon: &str, strict: bool) -> Result<Option<String>> {
    if cli == daemon {
        return Ok(None);
    }
    let message = build_mismatch_message(cli, daemon);
    if strict {
        bail!("{message}");
    }
    Ok(Some(message))
}

/// Route a behavior-env divergence report to a warning or, in strict mode, an
/// error. Pure in its inputs so the warn-vs-error policy and the message are
/// unit-testable without a live daemon. Returns `Err` under strict mode when
/// there is any divergence; otherwise warns to stderr and returns `Ok`.
fn report_behavior_env_divergence(
    divergences: &[kin_core::behavior_env::Divergence],
    strict: bool,
) -> Result<()> {
    if divergences.is_empty() {
        return Ok(());
    }
    let message = behavior_env_divergence_message(divergences);
    if strict {
        bail!("{message}");
    }
    warn!("{message}");
    Ok(())
}

/// Human-facing message for a behavior-env divergence: the boundary that causes
/// it, each diverging variable with both sides' values, and the accurate remedy.
fn behavior_env_divergence_message(divergences: &[kin_core::behavior_env::Divergence]) -> String {
    let mut message = String::from(
        "behavior-relevant environment differs between this command and the running kin daemon. \
         The daemon inherited its environment when it started and does not pick up a later \
         command's overrides, so these variables take effect from the daemon, not from this \
         invocation:",
    );
    for d in divergences {
        message.push_str("\n  - ");
        message.push_str(&d.describe());
    }
    message.push_str(
        "\nremedy: restart the daemon so it re-inherits the current environment — stop it with \
         `kin daemon stop` (or `kill $(cat .kin/daemon.pid)`; it also self-stops after its \
         KIN_DAEMON_IDLE_TIMEOUT_SECS idle window) and the next kin command respawns it. \
         Set KIN_STRICT_BEHAVIOR_ENV=1 to make this a hard error.",
    );
    message
}

fn check_response_build_match(headers: &reqwest::header::HeaderMap) -> Result<()> {
    let daemon_sha = match header_str(headers, "X-Kin-Daemon-Sha") {
        Some(value) => value,
        None => return Ok(()),
    };
    let daemon_dirty = header_str(headers, "X-Kin-Daemon-Dirty")
        .map(parse_boolish)
        .unwrap_or(false);
    let Some(daemon_id) = build_id(daemon_sha, daemon_dirty) else {
        return Ok(());
    };
    let cli = kin_buildinfo::get();
    let Some(cli_id) = build_id(cli.sha, cli.dirty) else {
        return Ok(());
    };
    if let Some(message) = build_match_error(
        &cli_id,
        &daemon_id,
        is_transient_bool_env("KIN_STRICT_BUILD_MATCH"),
    )? {
        if !BUILD_MISMATCH_REPORTED.swap(true, Ordering::SeqCst) {
            warn!("{message}");
        }
    }
    Ok(())
}

pub fn daemon_required() -> bool {
    true
}

/// What the operating system can prove about a process identifier.
///
/// `Unknown` is deliberately ownership-preserving. Permission failures and
/// other indeterminate probes are not evidence that a live owner disappeared,
/// so callers may retire process-owned state only for [`ProcessLiveness::Dead`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLiveness {
    Alive,
    Dead,
    Unknown,
}

/// Stable identity of one operating-system process incarnation.
///
/// A numeric PID is only a lookup key: after exit it can name an unrelated
/// process. Startup capabilities therefore bind both the current boot and the
/// process creation instant. On supported targets, failure to obtain either
/// component is an indeterminate owner and must fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pid: u32,
    boot_id: String,
    birth_token: String,
}

impl ProcessIdentity {
    /// The PID this identity names. Only a lookup key on its own — compare
    /// whole identities to decide whether it is still the same process.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl ProcessLiveness {
    /// Compatibility view for callers that only need a conservative boolean.
    ///
    /// Unknown owners are treated as possibly alive so existing status,
    /// supervisor, session, and stop paths fail closed instead of pruning or
    /// replacing authority they could not inspect.
    pub fn may_be_alive(self) -> bool {
        !matches!(self, Self::Dead)
    }

    fn authorizes_cleanup(self) -> bool {
        matches!(self, Self::Dead)
    }
}

/// Classify whether a process with the given PID exists.
pub fn process_liveness(pid: u32) -> ProcessLiveness {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return ProcessLiveness::Dead;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return ProcessLiveness::Alive;
        }
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => ProcessLiveness::Dead,
            Some(libc::EPERM) => ProcessLiveness::Unknown,
            _ => ProcessLiveness::Unknown,
        };
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return classify_windows_process_probe(false, unsafe { GetLastError() }, false, 0);
        }
        let mut code = 0;
        let queried = unsafe { GetExitCodeProcess(process, &mut code) } != 0;
        let _ = unsafe { CloseHandle(process) };
        return classify_windows_process_probe(true, 0, queried, code);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        // Unknown targets have no reliable process primitive here. Preserve
        // ownership rather than guessing "dead" and deleting live authority.
        ProcessLiveness::Unknown
    }
}

fn stable_boot_identity() -> std::io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Linux boot_id is empty",
            ));
        }
        return Ok(format!("linux-boot-id:{boot_id}"));
    }

    #[cfg(target_os = "macos")]
    {
        let mut boot_time = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = std::mem::size_of::<libc::timeval>();
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        let status = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                &mut boot_time as *mut libc::timeval as *mut _,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if status != 0 || len != std::mem::size_of::<libc::timeval>() {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(format!(
            "macos-kern-boottime:{}:{:06}",
            boot_time.tv_sec, boot_time.tv_usec
        ));
    }

    #[cfg(windows)]
    {
        use windows_sys::core::GUID;
        use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;

        #[repr(C)]
        struct SystemBootEnvironmentInformation {
            boot_identifier: GUID,
            firmware_type: u32,
            boot_flags: u64,
        }

        let mut info = SystemBootEnvironmentInformation {
            boot_identifier: GUID::default(),
            firmware_type: 0,
            boot_flags: 0,
        };
        let mut returned = 0_u32;
        // SYSTEM_INFORMATION_CLASS 90 is
        // SystemBootEnvironmentInformation. Its BootIdentifier is generated
        // once by the kernel for this boot and does not derive from wall time.
        let status = unsafe {
            NtQuerySystemInformation(
                90,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<SystemBootEnvironmentInformation>() as u32,
                &mut returned,
            )
        };
        if status < 0 {
            return Err(std::io::Error::other(format!(
                "NtQuerySystemInformation(SystemBootEnvironmentInformation) failed with NTSTATUS \
                 0x{:08x}",
                status as u32
            )));
        }
        let guid = info.boot_identifier;
        return Ok(format!(
            "windows-boot-guid:{:08x}-{:04x}-{:04x}-{}",
            guid.data1,
            guid.data2,
            guid.data3,
            hex::encode(guid.data4)
        ));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "stable boot identity is unsupported on this platform",
        ))
    }
}

pub fn process_identity(pid: u32) -> std::io::Result<Option<ProcessIdentity>> {
    let liveness = process_liveness(pid);
    if liveness == ProcessLiveness::Dead {
        return Ok(None);
    }

    let boot_id = stable_boot_identity()?;

    #[cfg(target_os = "linux")]
    {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && process_liveness(pid) == ProcessLiveness::Dead =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        // `comm` is parenthesized and may contain spaces or `)`, so split only
        // after its final closing delimiter. The 20th field in the remaining
        // sequence is field 22 (`starttime`, in boot-relative clock ticks).
        let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("process {pid} stat has no command delimiter"),
            )
        })?;
        let start_ticks = after_comm
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("process {pid} stat has no start-time field"),
                )
            })?
            .parse::<u64>()
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("process {pid} start-time field is invalid: {error}"),
                )
            })?;
        return Ok(Some(ProcessIdentity {
            pid,
            boot_id,
            birth_token: format!("linux-start-ticks:{start_ticks}"),
        }));
    }

    #[cfg(target_os = "macos")]
    {
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return Ok(None);
        };
        let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let expected = std::mem::size_of::<libc::proc_bsdinfo>();
        let written = unsafe {
            libc::proc_pidinfo(
                raw_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut _,
                expected as i32,
            )
        };
        if written != expected as i32 {
            if process_liveness(pid) == ProcessLiveness::Dead {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("cannot read birth identity for process {pid}"),
            ));
        }
        return Ok(Some(ProcessIdentity {
            pid,
            boot_id,
            birth_token: format!(
                "macos-start-time:{}:{:06}",
                info.pbi_start_tvsec, info.pbi_start_tvusec
            ),
        }));
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            if process_liveness(pid) == ProcessLiveness::Dead {
                return Ok(None);
            }
            return Err(std::io::Error::last_os_error());
        }
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let queried =
            unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
        let _ = unsafe { CloseHandle(process) };
        if queried == 0 {
            if process_liveness(pid) == ProcessLiveness::Dead {
                return Ok(None);
            }
            return Err(std::io::Error::last_os_error());
        }
        let created_100ns = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
        return Ok(Some(ProcessIdentity {
            pid,
            boot_id,
            birth_token: format!("windows-created-100ns:{created_100ns}"),
        }));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = boot_id;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "process birth identity is unsupported on this platform",
        ))
    }
}

pub fn current_process_identity() -> std::io::Result<ProcessIdentity> {
    process_identity(std::process::id())?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "the current process disappeared while reading its birth identity",
        )
    })
}

pub fn process_identity_is_current(identity: &ProcessIdentity) -> std::io::Result<bool> {
    Ok(process_identity(identity.pid)?.as_ref() == Some(identity))
}

#[cfg(windows)]
fn classify_windows_process_probe(
    opened: bool,
    open_error: u32,
    queried: bool,
    exit_code: u32,
) -> ProcessLiveness {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, STILL_ACTIVE};

    if !opened {
        // OpenProcess documents ERROR_INVALID_PARAMETER for a PID that cannot
        // identify a process. Access denied and every other failure are
        // indeterminate: the process may be live but inaccessible.
        return if open_error == ERROR_INVALID_PARAMETER {
            ProcessLiveness::Dead
        } else {
            ProcessLiveness::Unknown
        };
    }
    if !queried {
        return ProcessLiveness::Unknown;
    }
    if exit_code == STILL_ACTIVE as u32 {
        ProcessLiveness::Alive
    } else {
        ProcessLiveness::Dead
    }
}

/// Whether a process may still be alive.
///
/// Retained as the conservative compatibility surface. Call
/// [`process_liveness`] when a destructive decision needs to distinguish
/// affirmative death from an indeterminate probe.
pub fn is_process_alive(pid: u32) -> bool {
    process_liveness(pid).may_be_alive()
}

/// Whether a TCP port on localhost is accepting connections. Distinguishes a
/// daemon that is alive and serving from one whose process exists but whose
/// port is not (yet) bound.
pub fn is_port_open(port: u16) -> bool {
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveDaemonEndpoint {
    pid: u32,
    port: u16,
}

/// Path to the current repo's worker daemon pid file.
pub fn repo_daemon_pid_path(kin_root: &Path) -> PathBuf {
    kin_root.join("daemon.pid")
}

/// Path to the current repo's worker daemon port file.
pub fn repo_daemon_port_path(kin_root: &Path) -> PathBuf {
    kin_root.join("daemon.port")
}

/// Remove a repo worker daemon's pid/port endpoint files. The daemon deletes
/// these itself on graceful shutdown; `kin daemon stop` also calls this after a
/// confirmed stop so a later `status` never reports the dead endpoint as stale.
pub fn remove_stale_daemon_files(kin_root: &Path) {
    let recorded = daemon_endpoint_snapshot(kin_root);
    match recorded.pid {
        Some(pid) if process_liveness(pid).authorizes_cleanup() => {
            let _ = retire_daemon_endpoint_if_unchanged(kin_root, recorded);
        }
        Some(pid) => {
            warn!(
                pid,
                repo = %kin_root.display(),
                "preserving daemon endpoint because its recorded owner may still be alive"
            );
        }
        None if !recorded.pid_exists => {
            let _ = retire_daemon_endpoint_if_unchanged(kin_root, recorded);
        }
        None => {
            warn!(
                repo = %kin_root.display(),
                "preserving daemon endpoint because its PID record is unparseable"
            );
        }
    }
}

/// Remove a port record only when lifecycle authority proves there is still no
/// PID owner. Used before startup and by setup hygiene; a successor publishing
/// its complete endpoint takes the same authority and therefore survives.
pub fn remove_orphaned_daemon_port(kin_root: &Path) -> bool {
    let recorded = daemon_endpoint_snapshot(kin_root);
    if recorded.pid_exists || !recorded.port_exists {
        return false;
    }
    matches!(
        retire_daemon_endpoint_if_unchanged(kin_root, recorded),
        DaemonEndpointRetirement::Retired
    )
}

fn remove_endpoint_files_with<F>(
    pid_path: &Path,
    port_path: &Path,
    mut remove_file: F,
) -> std::io::Result<()>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let paths = [pid_path, port_path];
    let mut failure_kind = None;
    let mut failures = Vec::new();

    // Attempt both removals even when the first fails. A partial retirement must
    // still fail closed, but clearing the other stale component leaves the next
    // operator attempt with less ambiguous evidence.
    for &path in &paths {
        if let Err(error) = remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                failure_kind.get_or_insert(error.kind());
                failures.push(format!("remove {}: {error}", path.display()));
            }
        }
    }

    // `NotFound` is a successful removal result only when the path is actually
    // absent. Re-check both components while the caller still holds lifecycle
    // and singleton authority so `Retired` can remain a trustworthy capability
    // to start a replacement.
    for &path in &paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                failure_kind.get_or_insert(std::io::ErrorKind::Other);
                failures.push(format!(
                    "endpoint component {} still exists after retirement",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                failure_kind.get_or_insert(error.kind());
                failures.push(format!("verify retirement of {}: {error}", path.display()));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            failure_kind.unwrap_or(std::io::ErrorKind::Other),
            failures.join("; "),
        ))
    }
}

fn remove_stale_daemon_files_uncoordinated_with<F>(
    kin_root: &Path,
    remove_file: F,
) -> std::io::Result<()>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let pid_path = repo_daemon_pid_path(kin_root);
    let port_path = repo_daemon_port_path(kin_root);
    remove_endpoint_files_with(&pid_path, &port_path, remove_file)
}

fn try_acquire_daemon_endpoint_authority(kin_root: &Path) -> std::io::Result<File> {
    let authority = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(kin_root.join("daemon.lifecycle"))?;
    authority.try_lock_exclusive()?;
    Ok(authority)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonEndpointSnapshot {
    pid: Option<u32>,
    port: Option<u16>,
    pid_exists: bool,
    port_exists: bool,
}

fn daemon_endpoint_snapshot(kin_root: &Path) -> DaemonEndpointSnapshot {
    let pid_path = repo_daemon_pid_path(kin_root);
    let port_path = repo_daemon_port_path(kin_root);
    DaemonEndpointSnapshot {
        pid: read_pid_file(kin_root),
        port: read_port_file(kin_root),
        pid_exists: pid_path.exists(),
        port_exists: port_path.exists(),
    }
}

/// Linearized outcome of a destructive endpoint-retirement attempt.
///
/// Only `Retired` authorizes a caller to start a replacement. Every other
/// variant means the record was preserved and startup must follow the current
/// generation or fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonEndpointRetirement {
    Retired,
    Changed { current: DaemonEndpointSnapshot },
    LifecycleContended,
    SingletonHeld,
    CoordinationUnavailable(String),
}

impl DaemonEndpointRetirement {
    fn preserved_reason(&self) -> String {
        match self {
            Self::Retired => "endpoint was retired".to_string(),
            Self::Changed { current } => format!(
                "endpoint changed during retirement (pid={:?}, port={:?})",
                current.pid, current.port
            ),
            Self::LifecycleContended => {
                "daemon lifecycle coordination is held by another participant".to_string()
            }
            Self::SingletonHeld => {
                "the repository daemon singleton is still held by a current or legacy owner"
                    .to_string()
            }
            Self::CoordinationUnavailable(detail) => {
                format!("daemon retirement coordination is unavailable: {detail}")
            }
        }
    }

    fn may_reflect_publication(&self) -> bool {
        matches!(
            self,
            Self::Changed { .. } | Self::LifecycleContended | Self::SingletonHeld
        )
    }
}

/// Remove endpoint files only while they still name the exact endpoint a verdict
/// was formed about.
///
/// Every judgement about a daemon is made from a `(pid, port)` read at some
/// earlier instant, and the daemon that owns this repo can change between that
/// read and the delete: the recorded owner exits, a successor takes the flock
/// and republishes its own pid and port. Deleting unconditionally then acts on a
/// true statement about the old process by destroying the new one's files —
/// re-entering the exact failure this path exists to prevent, through the
/// evidence door rather than the timeout door. The wider the probe window, the
/// likelier that is, and waiting out a warm-up makes the window long by design.
///
/// This is the client-side twin of
/// `kin_daemon::lifecycle::remove_daemon_files_if_current_process`, which solves
/// the same race from the daemon's side.
///
/// `judged_port` is `None` when the verdict was reached before a port was ever
/// published, which is the one case where the port file is legitimately absent.
///
/// Returns a typed decision. Only [`DaemonEndpointRetirement::Retired`] permits
/// a caller to start a replacement.
fn remove_daemon_files_if_unchanged(
    kin_root: &Path,
    judged_pid: u32,
    judged_port: Option<u16>,
) -> DaemonEndpointRetirement {
    let judged = DaemonEndpointSnapshot {
        pid: Some(judged_pid),
        port: judged_port,
        pid_exists: true,
        port_exists: judged_port.is_some(),
    };
    retire_daemon_endpoint_if_unchanged(kin_root, judged)
}

#[cfg(test)]
fn remove_daemon_files_if_unchanged_with_hook<F>(
    kin_root: &Path,
    judged_pid: u32,
    judged_port: Option<u16>,
    after_comparison: F,
) -> DaemonEndpointRetirement
where
    F: FnOnce(),
{
    let judged = DaemonEndpointSnapshot {
        pid: Some(judged_pid),
        port: judged_port,
        pid_exists: true,
        port_exists: judged_port.is_some(),
    };
    retire_daemon_endpoint_if_unchanged_with_hooks(kin_root, judged, after_comparison, |path| {
        std::fs::remove_file(path)
    })
}

fn retire_daemon_endpoint_if_unchanged(
    kin_root: &Path,
    judged: DaemonEndpointSnapshot,
) -> DaemonEndpointRetirement {
    retire_daemon_endpoint_if_unchanged_with_hooks(
        kin_root,
        judged,
        || {},
        |path| std::fs::remove_file(path),
    )
}

fn retire_daemon_endpoint_if_unchanged_with_hooks<F, G>(
    kin_root: &Path,
    judged: DaemonEndpointSnapshot,
    after_comparison: F,
    remove_file: G,
) -> DaemonEndpointRetirement
where
    F: FnOnce(),
    G: FnMut(&Path) -> std::io::Result<()>,
{
    // Current daemon publication and every current retirement path take this
    // same never-unlinked authority. Holding it across the final comparison
    // and both unlinks makes the judgement linearizable: a successor either
    // publishes before the comparison (and is preserved) or after retirement.
    let _authority = match try_acquire_daemon_endpoint_authority(kin_root) {
        Ok(authority) => authority,
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            warn!(
                ?judged,
                repo = %kin_root.display(),
                "preserving daemon endpoint because lifecycle authority is contended"
            );
            return DaemonEndpointRetirement::LifecycleContended;
        }
        Err(error) => {
            warn!(
                ?judged,
                repo = %kin_root.display(),
                %error,
                "preserving daemon endpoint because lifecycle authority is unavailable"
            );
            return DaemonEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    };

    // Open the never-unlinked singleton pathname before the comparison. A
    // compatible legacy publisher does not take daemon.lifecycle, but it does
    // lock this inode for its process lifetime. Trying the already-opened inode
    // after the comparison therefore closes the mixed-version
    // compare-then-unlink window without ever replacing daemon.lock.
    let singleton = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(kin_root.join("daemon.lock"))
    {
        Ok(singleton) => singleton,
        Err(error) => {
            return DaemonEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    };

    let current = daemon_endpoint_snapshot(kin_root);
    if current != judged {
        warn!(
            ?judged,
            ?current,
            "endpoint files changed while this daemon was being judged; \
             leaving the successor's endpoint intact"
        );
        return DaemonEndpointRetirement::Changed { current };
    }

    after_comparison();

    match singleton.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            warn!(
                ?judged,
                repo = %kin_root.display(),
                "preserving daemon endpoint because the daemon singleton is held"
            );
            return DaemonEndpointRetirement::SingletonHeld;
        }
        Err(error) => {
            return DaemonEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    }

    // A legacy publisher may have completed and released its singleton between
    // the first comparison and our nonblocking lock. Revalidate under both
    // authorities so even that short-lived generation is preserved.
    let current = daemon_endpoint_snapshot(kin_root);
    if current != judged {
        return DaemonEndpointRetirement::Changed { current };
    }

    match remove_stale_daemon_files_uncoordinated_with(kin_root, remove_file) {
        Ok(()) => DaemonEndpointRetirement::Retired,
        Err(error) => {
            warn!(
                ?judged,
                repo = %kin_root.display(),
                %error,
                "preserving daemon startup authority because endpoint retirement failed"
            );
            DaemonEndpointRetirement::CoordinationUnavailable(error.to_string())
        }
    }
}

fn supervisor_dir() -> PathBuf {
    kin_core::registry::registry_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".kin"))
}

const SUPERVISOR_PID_FILE: &str = "supervisor.pid";
const SUPERVISOR_PORT_FILE: &str = "supervisor.port";
const SUPERVISOR_LIFECYCLE_FILE: &str = "supervisor.lifecycle";
const SUPERVISOR_SINGLETON_FILE: &str = "supervisor.lock";
const SUPERVISOR_STARTUP_FILE: &str = "supervisor.start.lock";
const SUPERVISOR_STARTUP_AUTHORITY_FILE: &str = "authority.lock";
const SUPERVISOR_STARTUP_RECORDS_DIR: &str = "records-v2";
const SUPERVISOR_STARTUP_PROTOCOL: u32 = 2;
const SUPERVISOR_STARTUP_CAPABILITY: &str = "generation-adoption-ack-v2";
const SUPERVISOR_LEGACY_SENTINEL_CAPABILITY: &str = "legacy-directory-sentinel-v1";
const SUPERVISOR_BOUNDED_ROLLBACK_CAPABILITY: &str = "bounded-legacy-rollback-v1";
/// Internal handoff from the current CLI launcher to the supervisor child.
///
/// This is scrubbed from every daemon command and set only on a supervisor
/// spawn. It names the exact startup-lock generation the child must adopt.
pub const SUPERVISOR_STARTUP_GENERATION_ENV: &str = "KIN_SUPERVISOR_STARTUP_GENERATION";

/// Path to the per-user supervisor pid file (under the Kin registry directory).
pub fn supervisor_pid_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_PID_FILE)
}

/// Path to the per-user supervisor port file (under the Kin registry directory).
pub fn supervisor_port_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_PORT_FILE)
}

/// Remove the supervisor's pid/port endpoint files. Called after a confirmed
/// supervisor stop so a later `status` never reports the dead endpoint as stale.
pub fn remove_stale_supervisor_files() {
    let dir = supervisor_dir();
    let startup_authority = match try_acquire_supervisor_startup_lock_for_cleanup(&dir) {
        Ok(authority) => authority,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            warn!(
                dir = %dir.display(),
                "preserving supervisor endpoint because cross-version startup authority is held"
            );
            return;
        }
        Err(error) => {
            warn!(
                dir = %dir.display(),
                %error,
                "preserving supervisor endpoint because cross-version startup authority is unavailable"
            );
            return;
        }
    };
    let recorded = supervisor_endpoint_snapshot(&dir);
    match recorded.pid {
        Some(pid) if process_liveness(pid).authorizes_cleanup() => {
            let _ = retire_supervisor_endpoint_if_unchanged(&dir, recorded, &startup_authority);
        }
        Some(_) => {
            warn!(
                ?recorded,
                "preserving supervisor endpoint because its owner is live or indeterminate"
            );
        }
        None if recorded.pid_exists => {
            warn!(
                ?recorded,
                "preserving supervisor endpoint because its owner is live or indeterminate"
            );
        }
        None => {
            let _ = retire_supervisor_endpoint_if_unchanged(&dir, recorded, &startup_authority);
        }
    }
}

fn try_acquire_supervisor_startup_lock_for_cleanup(
    dir: &Path,
) -> std::io::Result<SupervisorStartupLock> {
    try_acquire_supervisor_startup_lock_in_dir(dir)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SupervisorEndpointSnapshot {
    pid: Option<u32>,
    port: Option<u16>,
    pid_exists: bool,
    port_exists: bool,
}

fn supervisor_endpoint_snapshot(dir: &Path) -> SupervisorEndpointSnapshot {
    let pid_path = dir.join(SUPERVISOR_PID_FILE);
    let port_path = dir.join(SUPERVISOR_PORT_FILE);
    SupervisorEndpointSnapshot {
        pid: std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|value| value.trim().parse().ok()),
        port: std::fs::read_to_string(&port_path)
            .ok()
            .and_then(|value| value.trim().parse().ok()),
        pid_exists: pid_path.exists(),
        port_exists: port_path.exists(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SupervisorEndpointRetirement {
    Retired,
    Changed { current: SupervisorEndpointSnapshot },
    LifecycleContended,
    SingletonHeld,
    CoordinationUnavailable(String),
}

impl SupervisorEndpointRetirement {
    fn preserved_reason(&self) -> String {
        match self {
            Self::Retired => "endpoint was retired".to_string(),
            Self::Changed { current } => format!(
                "endpoint changed during retirement (pid={:?}, port={:?})",
                current.pid, current.port
            ),
            Self::LifecycleContended => {
                "supervisor lifecycle coordination is held by another participant".to_string()
            }
            Self::SingletonHeld => {
                "the supervisor process-lifetime singleton is still held".to_string()
            }
            Self::CoordinationUnavailable(detail) => {
                format!("supervisor retirement coordination is unavailable: {detail}")
            }
        }
    }

    fn may_reflect_publication(&self) -> bool {
        matches!(
            self,
            Self::Changed { .. } | Self::LifecycleContended | Self::SingletonHeld
        )
    }
}

fn retire_supervisor_endpoint_if_unchanged(
    dir: &Path,
    judged: SupervisorEndpointSnapshot,
    startup_authority: &SupervisorStartupLock,
) -> SupervisorEndpointRetirement {
    retire_supervisor_endpoint_if_unchanged_with_hooks(
        dir,
        judged,
        startup_authority,
        || {},
        |path| std::fs::remove_file(path),
    )
}

fn retire_supervisor_endpoint_if_unchanged_with_hooks<F, G>(
    dir: &Path,
    judged: SupervisorEndpointSnapshot,
    startup_authority: &SupervisorStartupLock,
    after_final_snapshot: F,
    remove_file: G,
) -> SupervisorEndpointRetirement
where
    F: FnOnce(),
    G: FnMut(&Path) -> std::io::Result<()>,
{
    if !startup_authority.authorizes(dir) {
        return SupervisorEndpointRetirement::CoordinationUnavailable(format!(
            "startup protocol authority at {} does not authorize {}",
            startup_authority.path().display(),
            dir.display()
        ));
    }
    if let Err(error) = std::fs::create_dir_all(dir) {
        return SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string());
    }
    let lifecycle = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(SUPERVISOR_LIFECYCLE_FILE))
    {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            return SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    };
    match lifecycle.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            return SupervisorEndpointRetirement::LifecycleContended;
        }
        Err(error) => {
            return SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    }

    // Current publishers continuously hold the lifetime inode. The permanent
    // startup directory excludes immutable create-new launchers, while this
    // caller's v2 authority lock serializes the final retire-or-spawn decision.
    let singleton = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(SUPERVISOR_SINGLETON_FILE))
    {
        Ok(singleton) => singleton,
        Err(error) => {
            return SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    };
    let current = supervisor_endpoint_snapshot(dir);
    if current != judged {
        return SupervisorEndpointRetirement::Changed { current };
    }
    match singleton.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            return SupervisorEndpointRetirement::SingletonHeld;
        }
        Err(error) => {
            return SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string());
        }
    }
    let current = supervisor_endpoint_snapshot(dir);
    if current != judged {
        return SupervisorEndpointRetirement::Changed { current };
    }
    after_final_snapshot();
    let pid_path = dir.join(SUPERVISOR_PID_FILE);
    let port_path = dir.join(SUPERVISOR_PORT_FILE);
    match remove_endpoint_files_with(&pid_path, &port_path, remove_file) {
        Ok(()) => SupervisorEndpointRetirement::Retired,
        Err(error) => {
            warn!(
                ?judged,
                dir = %dir.display(),
                %error,
                "preserving supervisor startup authority because endpoint retirement failed"
            );
            SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string())
        }
    }
}

fn read_pid_file(kin_root: &Path) -> Option<u32> {
    std::fs::read_to_string(repo_daemon_pid_path(kin_root))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Read the port the daemon published for this repo.
///
/// Delegates to the shared spawn contract so the CLI and MCP paths cannot
/// disagree about what counts as a published port.
fn read_port_file(kin_root: &Path) -> Option<u16> {
    kin_daemon_spawn::read_reported_port(kin_root)
}

/// The (pid, port) recorded for the current repo's worker daemon, read from its
/// `.kin/daemon.{pid,port}` files with no liveness probe. Either component is
/// `None` when its file is absent or unparseable. Callers classify liveness
/// separately via [`is_process_alive`]/[`is_port_open`].
pub fn repo_daemon_recorded_endpoint(kin_root: &Path) -> (Option<u32>, Option<u16>) {
    (read_pid_file(kin_root), read_port_file(kin_root))
}

/// The (pid, port) recorded for the per-user supervisor, read from its
/// `supervisor.{pid,port}` files with no liveness probe. Either component is
/// `None` when its file is absent or unparseable.
pub fn supervisor_recorded_endpoint() -> (Option<u32>, Option<u16>) {
    let recorded = supervisor_endpoint_snapshot(&supervisor_dir());
    (recorded.pid, recorded.port)
}

fn live_daemon_endpoint(kin_root: &Path) -> Option<LiveDaemonEndpoint> {
    live_daemon_endpoint_with_probe(kin_root, process_liveness)
}

fn live_daemon_endpoint_with_probe(
    kin_root: &Path,
    probe: impl FnOnce(u32) -> ProcessLiveness,
) -> Option<LiveDaemonEndpoint> {
    let recorded = daemon_endpoint_snapshot(kin_root);
    let pid = recorded.pid?;
    // Capture both components before forming the liveness verdict. Reading the
    // port afterward could bind a true "dead" result about the predecessor PID
    // to a same-PID successor's newly published port, making the final
    // compare-and-retire accept the wrong endpoint generation.
    let port = recorded.port;
    if probe(pid).authorizes_cleanup() {
        // Compare-and-delete even here, where the window is only as wide as this
        // function: a successor that republished between the read and the
        // liveness check would otherwise lose its endpoint to a true statement
        // about its predecessor.
        match retire_daemon_endpoint_if_unchanged(kin_root, recorded) {
            DaemonEndpointRetirement::Retired => return None,
            DaemonEndpointRetirement::Changed { current } => {
                return Some(LiveDaemonEndpoint {
                    pid: current.pid?,
                    port: current.port?,
                });
            }
            DaemonEndpointRetirement::LifecycleContended
            | DaemonEndpointRetirement::SingletonHeld
            | DaemonEndpointRetirement::CoordinationUnavailable(_) => {}
        }
    }
    let port = port?;
    Some(LiveDaemonEndpoint { pid, port })
}

fn live_supervisor_endpoint() -> Option<LiveDaemonEndpoint> {
    let dir = supervisor_dir();
    let recorded = supervisor_endpoint_snapshot(&dir);
    let pid = recorded.pid?;
    if process_liveness(pid).authorizes_cleanup() {
        // Route lookups are observers, not startup authorities. Leave stale
        // endpoint cleanup to the path holding supervisor.start.lock so a
        // compatible older launcher cannot publish through an unlink window.
        return None;
    }
    let port = recorded.port?;
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

fn daemon_binary_supports_supervisor(path: &Path) -> bool {
    let mut command = Command::new(path);
    command.arg("--help");
    let label = format!("{} --help", path.display());
    let output =
        match probe_process::output_with_timeout(&mut command, &label, DAEMON_BINARY_PROBE_TIMEOUT)
        {
            Ok(output) => output,
            Err(error) => {
                warn!(
                    binary = %path.display(),
                    error = %error,
                    "failed to probe kin-daemon binary"
                );
                return false;
            }
        };
    let mut help = String::new();
    help.push_str(&String::from_utf8_lossy(&output.stdout));
    help.push_str(&String::from_utf8_lossy(&output.stderr));
    help.contains("--supervisor")
}

fn compact_probe_output(output: &std::process::Output) -> String {
    let mut rendered = String::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        rendered.push_str("stdout=");
        rendered.push_str(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        if !rendered.is_empty() {
            rendered.push(' ');
        }
        rendered.push_str("stderr=");
        rendered.push_str(stderr.trim());
    }
    if rendered.is_empty() {
        rendered.push_str("<empty output>");
    }
    const MAX_LEN: usize = 400;
    const TRUNCATION_SUFFIX: &str = "...";
    if rendered.len() > MAX_LEN {
        let mut content_end = MAX_LEN.saturating_sub(TRUNCATION_SUFFIX.len());
        while !rendered.is_char_boundary(content_end) {
            content_end -= 1;
        }
        rendered.truncate(content_end);
        rendered.push_str(TRUNCATION_SUFFIX);
    }
    debug_assert!(rendered.len() <= MAX_LEN);
    rendered
}

fn daemon_binary_matches_cli_graph(path: &Path) -> Result<(), String> {
    let mut command = Command::new(path);
    command.arg("--compat-json");
    let label = format!("{} --compat-json", path.display());
    let output =
        probe_process::output_with_timeout(&mut command, &label, DAEMON_BINARY_PROBE_TIMEOUT)
            .map_err(|error| format!("compat probe failed to execute: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compat probe exited with {} ({})",
            output.status,
            compact_probe_output(&output)
        ));
    }
    validate_daemon_compat_json(&output.stdout)
}

/// Validate the bounded `kin-daemon --compat-json` payload against this CLI's
/// graph and startup contracts.
///
/// Kept public so non-CLI activation surfaces (for example a macOS
/// LaunchAgent installer) can prove the exact selected daemon before making it
/// persistent.
pub fn validate_daemon_compat_json(payload: &[u8]) -> Result<(), String> {
    let compat: DaemonCompatResponse = serde_json::from_slice(payload)
        .map_err(|error| format!("compat probe returned invalid JSON: {error}"))?;
    validate_daemon_compat_response(&compat)
}

fn validate_daemon_compat_response(compat: &DaemonCompatResponse) -> Result<(), String> {
    let expected = kin_db::GraphSnapshot::CURRENT_VERSION;
    if compat.graph_snapshot_version != expected {
        return Err(format!(
            "graph snapshot version {} does not match CLI expected version {expected}",
            compat.graph_snapshot_version
        ));
    }
    if compat.schema != "kin.daemon.compat.v2"
        || compat.supervisor_startup_protocol != Some(SUPERVISOR_STARTUP_PROTOCOL)
        || !compat
            .supervisor_startup_capabilities
            .iter()
            .any(|capability| capability == SUPERVISOR_STARTUP_CAPABILITY)
        || !compat
            .supervisor_startup_capabilities
            .iter()
            .any(|capability| capability == SUPERVISOR_LEGACY_SENTINEL_CAPABILITY)
        || !compat
            .supervisor_startup_capabilities
            .iter()
            .any(|capability| capability == SUPERVISOR_BOUNDED_ROLLBACK_CAPABILITY)
    {
        return Err(format!(
            "daemon does not acknowledge supervisor startup protocol v{} ({}, {}, {})",
            SUPERVISOR_STARTUP_PROTOCOL,
            SUPERVISOR_STARTUP_CAPABILITY,
            SUPERVISOR_LEGACY_SENTINEL_CAPABILITY,
            SUPERVISOR_BOUNDED_ROLLBACK_CAPABILITY
        ));
    }
    Ok(())
}

fn validate_daemon_binary(path: &Path) -> Result<(), String> {
    if !daemon_binary_supports_supervisor(path) {
        return Err("missing --supervisor support".to_string());
    }
    daemon_binary_matches_cli_graph(path)
}

#[derive(Debug, thiserror::Error)]
enum DaemonBinaryDiscoveryError {
    #[error("kin-daemon binary not found")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
}

fn find_daemon_binary() -> std::result::Result<PathBuf, DaemonBinaryDiscoveryError> {
    if let Ok(explicit) = std::env::var("KIN_DAEMON_BIN") {
        let path = PathBuf::from(explicit);
        if !path.exists() {
            return Err(DaemonBinaryDiscoveryError::Invalid(format!(
                "explicit KIN_DAEMON_BIN does not exist: {}",
                path.display()
            )));
        }
        return match validate_daemon_binary(&path) {
            Ok(()) => Ok(path),
            Err(reason) => Err(DaemonBinaryDiscoveryError::Invalid(format!(
                "explicit KIN_DAEMON_BIN {} is incompatible with this kin CLI: {reason}",
                path.display()
            ))),
        };
    }

    let mut rejected = Vec::new();
    let mut consider = |path: PathBuf| -> Option<PathBuf> {
        if !path.exists() {
            return None;
        }
        match validate_daemon_binary(&path) {
            Ok(()) => Some(path),
            Err(reason) => {
                rejected.push((path, reason));
                None
            }
        }
    };

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if let Some(path) = consider(sibling) {
            return Ok(path);
        }
        if exe
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
                let target_sibling = target_dir.join("kin-daemon");
                if let Some(path) = consider(target_sibling) {
                    return Ok(path);
                }
            }
        }
    }
    if let Ok(path) = which::which("kin-daemon") {
        if let Some(path) = consider(path) {
            return Ok(path);
        }
    }

    if rejected.is_empty() {
        return Err(DaemonBinaryDiscoveryError::NotFound);
    }
    let checked = rejected
        .into_iter()
        .map(|(path, reason)| format!("{} ({reason})", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    Err(DaemonBinaryDiscoveryError::Invalid(format!(
        "kin-daemon binary is stale or incompatible with this kin CLI; rebuild kin-daemon. Checked: {checked}"
    )))
}

/// Readiness wait for a freshly spawned per-repo daemon. Large repositories take
/// far longer than a few seconds to load their graph into memory before `/readiness`
/// succeeds, so this cap is generous: a *dead* daemon is detected immediately by
/// `child.try_wait()` in `wait_for_daemon_ready`, leaving this to bound patience only
/// for a live daemon that is still loading. Override with KIN_DAEMON_READY_TIMEOUT_SECS.
fn daemon_ready_timeout_secs() -> u64 {
    std::env::var("KIN_DAEMON_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
}

fn default_idle_timeout_secs() -> &'static str {
    if cfg!(test) {
        "1"
    } else {
        "60"
    }
}

/// Idle timeout (seconds) for MCP-initiated daemon autostarts: 30 minutes.
///
/// Defined once in the shared spawn contract, which both this path and the MCP
/// revival path start daemons through. It used to be a literal repeated in each
/// crate with a comment asking future readers to keep them in sync.
const MCP_IDLE_TIMEOUT_SECS: &str = kin_daemon_spawn::MCP_IDLE_TIMEOUT_SECS;

/// Pure env-assembly for the daemon's idle timeout, mirroring
/// `kin_daemon::lifecycle::resolve_idle_timeout_env`.
///
/// Returns `None` when the user has already set `KIN_DAEMON_IDLE_TIMEOUT_SECS`
/// (their value propagates naturally to the child process). Returns
/// `Some(value)` when we should inject it: the caller's override if given,
/// otherwise the compiled default (60 s / 1 s in tests).
///
/// Factored out of the spawn path so the env-assembly logic is unit-testable
/// without actually starting a daemon process.
fn resolve_idle_timeout_env(
    user_env_is_set: bool,
    caller_override: Option<&'static str>,
) -> Option<&'static str> {
    if user_env_is_set {
        return None;
    }
    Some(caller_override.unwrap_or_else(default_idle_timeout_secs))
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

/// Byte length of the daemon log at the moment a new start attempt begins.
/// Anything written at or after this offset belongs to the current attempt;
/// anything before it is the stale tail of a prior run.
fn daemon_log_len(kin_root: &Path) -> u64 {
    std::fs::metadata(daemon_log_path(kin_root))
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

/// Render the daemon log output produced by the current start attempt only —
/// the bytes written at or after `since_offset` (the log length captured just
/// before the daemon was spawned). This avoids surfacing the stale tail of a
/// prior run's log as if it were the cause of this failure. When the failing
/// process wrote nothing, we say so explicitly rather than echoing old lines.
fn daemon_log_tail_since(kin_root: &Path, since_offset: u64) -> String {
    let path = daemon_log_path(kin_root);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return format!("daemon log unavailable at {}", path.display());
    };
    let fresh = content
        .get(since_offset as usize..)
        .unwrap_or(&content)
        .trim();
    if fresh.is_empty() {
        return format!(
            "no fresh daemon output captured for this start attempt at {}",
            path.display()
        );
    }
    let lines: Vec<&str> = fresh.lines().rev().take(20).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn canonical_path_string(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

/// Canonical form of a path, or `None` when it cannot be resolved.
///
/// Deliberately not [`canonical_path_string`], which falls back to the
/// unresolved path. That fallback is fine for a log line and wrong for a
/// comparison: an unresolved path compared against a correctly-resolved peer
/// differs for a reason that has nothing to do with which repo either side is
/// serving. Where the answer drives a destructive action, a failure to resolve
/// must read as "no evidence", never as "different".
fn strict_canonical_path(path: &Path) -> Option<String> {
    path.canonicalize().ok().map(|p| p.display().to_string())
}

/// Repository and workspace identity recorded in this repo's own manifest.
///
/// Startup configuration IO at an explicit boundary, not a semantic answer path:
/// it reads the local manifest to learn which exact workspace the caller is
/// standing in, so a daemon's self-reported identity can be compared against
/// something stronger than a rendered path.
struct LocalWorkspaceIdentity {
    repo_id: String,
    workspace_id: Option<String>,
}

fn local_workspace_identity(kin_root: &Path) -> Option<LocalWorkspaceIdentity> {
    kin_core::manifest::KinManifest::load(&kin_root.join("manifest.json"))
        .ok()
        .and_then(|manifest| {
            let repo_id = manifest.repo_id.trim();
            if repo_id.is_empty() {
                return None;
            }
            let workspace_id = match manifest.workspace_id.trim() {
                "" => None,
                workspace_id => Some(workspace_id.to_string()),
            };
            Some(LocalWorkspaceIdentity {
                repo_id: repo_id.to_string(),
                workspace_id,
            })
        })
}

/// What a `/health` body establishes about whether this daemon serves this repo.
#[derive(Debug, PartialEq, Eq)]
enum RepoIdentity {
    /// Proven the same repository.
    Matches,
    /// Proven a different repository, or a status that is not serving at all.
    Rejected(String),
    /// Nothing conclusive: the daemon named no identity this client can compare,
    /// or a path would not resolve on one side.
    Indeterminate(String),
}

/// Decide whether a health body identifies this repo, with no silent fallback.
///
/// Identity is compared strongest-first. A repository id establishes shared
/// repository truth, but not local authority: two clones deliberately share
/// `repo_id` and carry distinct `workspace_id` values. When both sides carry
/// workspace identity, that exact pair is conclusive. Older daemons that do not
/// report a workspace id fall back to canonical paths, and both sides must
/// resolve before a difference counts as evidence — `/tmp` against
/// `/private/tmp` on macOS, or a symlinked worktree, is an aliasing artifact and
/// not a different workspace.
fn classify_health_repo(
    health: &HealthResponse,
    kin_root: &Path,
    working_dir: &Path,
) -> RepoIdentity {
    if !health_status_is_serving(&health.status) {
        return RepoIdentity::Rejected(format!("daemon health status is {}", health.status));
    }

    let reported_repo_id = health
        .repo_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let reported_workspace_id = health
        .workspace_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let local_identity = local_workspace_identity(kin_root);

    if let (Some(reported_repo), Some(expected)) = (reported_repo_id, local_identity.as_ref()) {
        if reported_repo != expected.repo_id {
            return RepoIdentity::Rejected(format!(
                "daemon repo mismatch: endpoint serves repository {reported_repo}, expected {}",
                expected.repo_id
            ));
        }
        if let (Some(reported_workspace), Some(expected_workspace)) =
            (reported_workspace_id, expected.workspace_id.as_deref())
        {
            return if reported_workspace == expected_workspace {
                RepoIdentity::Matches
            } else {
                RepoIdentity::Rejected(format!(
                    "daemon workspace mismatch: endpoint serves workspace {reported_workspace}, \
                     expected {expected_workspace}"
                ))
            };
        }
    } else if let (Some(reported_workspace), Some(expected_workspace)) = (
        reported_workspace_id,
        local_identity
            .as_ref()
            .and_then(|identity| identity.workspace_id.as_deref()),
    ) {
        return if reported_workspace == expected_workspace {
            RepoIdentity::Matches
        } else {
            RepoIdentity::Rejected(format!(
                "daemon workspace mismatch: endpoint serves workspace {reported_workspace}, \
                 expected {expected_workspace}"
            ))
        };
    }

    let Some(reported_root) = health.repo_root.as_deref() else {
        // A daemon that names neither an id nor a root has told us nothing. It
        // is not proof of a match, which would let an unrelated daemon pass, and
        // not proof of a mismatch, which would destroy a live endpoint.
        return RepoIdentity::Indeterminate(
            "daemon reported neither a repository id nor a repo root".to_string(),
        );
    };
    let Some(expected_root) = strict_canonical_path(working_dir) else {
        return RepoIdentity::Indeterminate(format!(
            "cannot resolve {} to compare against the daemon's repo root",
            working_dir.display()
        ));
    };
    if reported_root == expected_root {
        return RepoIdentity::Matches;
    }
    match strict_canonical_path(Path::new(reported_root)) {
        Some(resolved) if resolved == expected_root => RepoIdentity::Matches,
        Some(resolved) => RepoIdentity::Rejected(format!(
            "daemon repo mismatch: endpoint is for {resolved}, expected {expected_root}"
        )),
        None => RepoIdentity::Indeterminate(format!(
            "daemon reported repo root {reported_root}, which does not resolve; \
             cannot establish whether it is this repository"
        )),
    }
}

/// Whether a daemon `/health` status string means the daemon is alive and
/// serving the graph. The daemon reports `"attention"` (not `"ok"`) when it is
/// up and serving but degraded — a withheld mass-deletion wipe or a permanently
/// stopped embedding worker (see kin-daemon `api.rs` `health`). The graph stays
/// intact and queryable in both cases, so an attention daemon is a valid
/// endpoint, not a dead one. Treating it as invalid wipes the endpoint files and
/// respawns a fresh daemon that reports the same status, producing a
/// spawn→reject→clear hang.
fn health_status_is_serving(status: &str) -> bool {
    matches!(status, "ok" | "attention")
}

/// Whether this daemon may be used for this repo, for callers that only need a
/// yes/no and treat every no the same way.
///
/// Used by the fresh-spawn path, where an inconclusive identity is still a
/// reason to keep waiting on a daemon we started ourselves and expect to
/// identify itself. Callers whose "no" branch destroys state must use
/// [`classify_health_repo`] instead and distinguish proven-different from
/// nothing-established.
pub(crate) fn validate_health_repo(health: &HealthResponse, working_dir: &Path) -> Result<()> {
    let kin_root = working_dir.join(".kin");
    match classify_health_repo(health, &kin_root, working_dir) {
        RepoIdentity::Matches => {}
        RepoIdentity::Rejected(reason) | RepoIdentity::Indeterminate(reason) => bail!(reason),
    }
    if health.status == "attention" {
        warn!(
            repo_root = health.repo_root.as_deref().unwrap_or("<unknown>"),
            "daemon is up and serving but reports health=attention (degraded); \
             continuing to use it. Run `kin status` for details."
        );
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StartupFileIdentity {
    volume: u64,
    file: u64,
}

fn startup_file_identity(file: &File) -> std::io::Result<StartupFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        return Ok(StartupFileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        });
    }
    #[cfg(windows)]
    {
        use std::mem::zeroed;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        // The std MetadataExt accessors for these fields are still unstable.
        // Query the exact open handle instead, so identity cannot drift through
        // a pathname reopen between validation and use.
        // SAFETY: zero is a valid initializer for this output structure and
        // `file` owns a live handle for the duration of the call.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(StartupFileIdentity {
            volume: information.dwVolumeSerialNumber as u64,
            file: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
        });
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "startup authority file identity is unsupported on this platform",
        ))
    }
}

fn startup_metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn open_startup_regular_file(
    path: &Path,
    create: bool,
    create_new: bool,
    write: bool,
) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(create)
        .create_new(create_new)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink()
        || startup_metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "supervisor startup protocol refuses non-regular file {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

fn open_startup_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_WRITE_ATTRIBUTES,
        };
        options
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink()
        || startup_metadata_is_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "supervisor startup protocol refuses non-directory handle {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

#[derive(Debug)]
struct SupervisorStartupNamespace {
    sentinel: PathBuf,
    records: PathBuf,
    sentinel_file: File,
    sentinel_identity: StartupFileIdentity,
}

/// Keep immutable protocol-v1 launchers on their bounded deadline path.
///
/// Those launchers treat an old `supervisor.start.lock` mtime as permission to
/// call `remove_file` and immediately retry. The permanent v2 directory cannot
/// be removed that way, so an aged ordinary mtime would turn the retry into an
/// unbounded busy loop after a binary rollback. Current launchers instead stamp
/// the outer, never-mutated sentinel far into the future. The legacy
/// `modified().elapsed()` check then returns `Err` and reaches its configured
/// deadline, while the directory continues to exclude legacy `create_new`
/// launchers structurally.
///
/// All mutable v2 records live one level below the sentinel so creating a
/// generation cannot refresh or age this compatibility stamp. Failure to set
/// and read back a future timestamp fails current startup closed.
fn preserve_bounded_legacy_rollback(
    sentinel: &Path,
    sentinel_file: &File,
) -> std::io::Result<StartupFileIdentity> {
    // One hundred leap years is inside the supported timestamp range of the
    // filesystems Kin supports and is refreshed by every current launcher.
    const FUTURE_SECS: u64 = 100 * 366 * 24 * 60 * 60;
    let future = std::time::SystemTime::now()
        .checked_add(Duration::from_secs(FUTURE_SECS))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot represent the supervisor rollback sentinel timestamp",
            )
        })?;
    let identity = startup_file_identity(sentinel_file)?;
    filetime::set_file_handle_times(
        sentinel_file,
        None,
        Some(filetime::FileTime::from_system_time(future)),
    )?;
    let readback_identity = startup_file_identity(sentinel_file)?;
    if readback_identity != identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "supervisor rollback sentinel handle identity changed at {}",
                sentinel.display()
            ),
        ));
    }
    let modified = sentinel_file.metadata()?.modified()?;
    if modified.elapsed().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "filesystem did not preserve a future supervisor rollback sentinel timestamp at {}",
                sentinel.display()
            ),
        ));
    }
    Ok(identity)
}

fn ensure_supervisor_startup_namespace(dir: &Path) -> std::io::Result<SupervisorStartupNamespace> {
    std::fs::create_dir_all(dir)?;
    let sentinel = dir.join(SUPERVISOR_STARTUP_FILE);
    loop {
        match std::fs::symlink_metadata(&sentinel) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || startup_metadata_is_reparse_point(&metadata) =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "supervisor startup protocol refuses symlink {}",
                        sentinel.display()
                    ),
                ));
            }
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "legacy supervisor launcher marker at {} is incompatible with startup \
                         protocol v{SUPERVISOR_STARTUP_PROTOCOL}; refusing before supervisor boot",
                        sentinel.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::create_dir(&sentinel) {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }

    // Create every fixed entry before stamping the outer sentinel. Per-launch
    // records are written only beneath `records`, so the outer directory mtime
    // remains a stable compatibility signal after this point.
    drop(open_startup_regular_file(
        &sentinel.join(SUPERVISOR_STARTUP_AUTHORITY_FILE),
        true,
        false,
        true,
    )?);
    let records = sentinel.join(SUPERVISOR_STARTUP_RECORDS_DIR);
    loop {
        match std::fs::symlink_metadata(&records) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || startup_metadata_is_reparse_point(&metadata)
                    || !metadata.is_dir() =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "supervisor startup protocol refuses non-directory records namespace {}",
                        records.display()
                    ),
                ));
            }
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::create_dir(&records) {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    let sentinel_file = open_startup_directory(&sentinel)?;
    let sentinel_identity = preserve_bounded_legacy_rollback(&sentinel, &sentinel_file)?;
    Ok(SupervisorStartupNamespace {
        sentinel,
        records,
        sentinel_file,
        sentinel_identity,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SupervisorLaunchRecord {
    schema: String,
    protocol: u32,
    generation: String,
    launcher: ProcessIdentity,
    authority: StartupFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SupervisorAdoptionRecord {
    schema: String,
    protocol: u32,
    generation: String,
    supervisor: ProcessIdentity,
    authority: StartupFileIdentity,
}

fn supervisor_launch_record_path(namespace: &Path, generation: &str) -> PathBuf {
    namespace.join(format!("launch-{generation}.json"))
}

fn supervisor_adoption_record_path(namespace: &Path, generation: &str) -> PathBuf {
    namespace.join(format!("adopt-{generation}.json"))
}

fn write_immutable_startup_record<T: Serialize>(path: &Path, record: &T) -> std::io::Result<()> {
    let mut file = open_startup_regular_file(path, false, true, true)?;
    serde_json::to_writer(&mut file, record).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()
}

fn read_startup_record<T: serde::de::DeserializeOwned>(path: &Path) -> std::io::Result<T> {
    let mut file = open_startup_regular_file(path, false, false, false)?;
    if file.metadata()?.len() > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("startup record is unexpectedly large: {}", path.display()),
        ));
    }
    serde_json::from_reader(&mut file).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid startup record {}: {error}", path.display()),
        )
    })
}

/// Process-bound startup serialization for protocol-v2 launchers.
///
/// `supervisor.start.lock` is now a permanent directory. Immutable old clients
/// use `remove_file`, which cannot delete it even after sleep or scheduler
/// starvation; current clients serialize on the never-unlinked
/// `authority.lock` inode inside it. Drop only releases the kernel lock, so it
/// has no pathname transition that could remove or overwrite a successor.
#[derive(Debug)]
pub struct SupervisorStartupLock {
    dir: PathBuf,
    sentinel: PathBuf,
    records: PathBuf,
    sentinel_file: File,
    sentinel_identity: StartupFileIdentity,
    file: File,
    file_identity: StartupFileIdentity,
    generation: String,
    launch: SupervisorLaunchRecord,
}

impl SupervisorStartupLock {
    fn path(&self) -> &Path {
        &self.sentinel
    }

    /// Exact generation handed from a launcher to its supervisor child.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    fn current_authority_identity(&self) -> std::io::Result<StartupFileIdentity> {
        let path = self.sentinel.join(SUPERVISOR_STARTUP_AUTHORITY_FILE);
        let file = open_startup_regular_file(&path, false, false, false)?;
        startup_file_identity(&file)
    }

    fn current_sentinel_identity(&self) -> std::io::Result<StartupFileIdentity> {
        let file = open_startup_directory(&self.sentinel)?;
        startup_file_identity(&file)
    }

    fn authorizes(&self, dir: &Path) -> bool {
        if self.dir != dir
            || self.sentinel != dir.join(SUPERVISOR_STARTUP_FILE)
            || self.records != self.sentinel.join(SUPERVISOR_STARTUP_RECORDS_DIR)
        {
            return false;
        }
        if startup_file_identity(&self.sentinel_file).ok().as_ref() != Some(&self.sentinel_identity)
            || self.current_sentinel_identity().ok().as_ref() != Some(&self.sentinel_identity)
        {
            return false;
        }
        let own_identity = startup_file_identity(&self.file);
        if own_identity.ok().as_ref() != Some(&self.file_identity) {
            return false;
        }
        if self.current_authority_identity().ok().as_ref() != Some(&self.file_identity) {
            return false;
        }
        if process_identity_is_current(&self.launch.launcher).ok() != Some(true) {
            return false;
        }
        read_startup_record::<SupervisorLaunchRecord>(&supervisor_launch_record_path(
            &self.records,
            &self.generation,
        ))
        .ok()
        .as_ref()
            == Some(&self.launch)
    }

    /// Validate authority without refreshing wall-clock metadata.
    pub fn heartbeat(&mut self) -> std::io::Result<bool> {
        Ok(self.authorizes(&self.dir))
    }

    fn verify_adoption(&self, child_pid: u32) -> std::io::Result<()> {
        if !self.authorizes(&self.dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "supervisor startup authority changed before adoption acknowledgement",
            ));
        }
        let adoption: SupervisorAdoptionRecord = read_startup_record(
            &supervisor_adoption_record_path(&self.records, &self.generation),
        )?;
        if adoption.schema != "kin.supervisor.adoption.v2"
            || adoption.protocol != SUPERVISOR_STARTUP_PROTOCOL
            || adoption.generation != self.generation
            || adoption.authority != self.file_identity
            || adoption.supervisor.pid != child_pid
            || !process_identity_is_current(&adoption.supervisor)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "supervisor adoption acknowledgement is not bound to the launched child",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SupervisorRuntimeStartup {
    records: PathBuf,
    generation: String,
    authority: StartupFileIdentity,
    supervisor: ProcessIdentity,
}

impl SupervisorRuntimeStartup {
    pub fn acknowledge(&self) -> std::io::Result<()> {
        let record = SupervisorAdoptionRecord {
            schema: "kin.supervisor.adoption.v2".to_string(),
            protocol: SUPERVISOR_STARTUP_PROTOCOL,
            generation: self.generation.clone(),
            supervisor: self.supervisor.clone(),
            authority: self.authority.clone(),
        };
        let path = supervisor_adoption_record_path(&self.records, &self.generation);
        match write_immutable_startup_record(&path, &record) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing: SupervisorAdoptionRecord = read_startup_record(&path)?;
                if existing == record {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "supervisor adoption record belongs to a different process incarnation",
                    ))
                }
            }
            Err(error) => Err(error),
        }
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

/// Acquire the current protocol's persistent startup authority without waiting.
#[doc(hidden)]
pub fn try_acquire_supervisor_startup_lock_in_dir(
    dir: &Path,
) -> std::io::Result<SupervisorStartupLock> {
    let namespace = ensure_supervisor_startup_namespace(dir)?;
    let authority_path = namespace.sentinel.join(SUPERVISOR_STARTUP_AUTHORITY_FILE);
    let file = open_startup_regular_file(&authority_path, false, false, true)?;
    let file_identity = startup_file_identity(&file)?;
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "another current launcher holds supervisor startup authority",
            ));
        }
        Err(error) => return Err(error),
    }
    let current_sentinel = open_startup_directory(&namespace.sentinel)?;
    if startup_file_identity(&current_sentinel)? != namespace.sentinel_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "supervisor startup sentinel changed before authority acquisition",
        ));
    }
    if preserve_bounded_legacy_rollback(&namespace.sentinel, &namespace.sentinel_file)?
        != namespace.sentinel_identity
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "supervisor startup sentinel changed while preserving rollback compatibility",
        ));
    }

    let generation = Uuid::new_v4().to_string();
    let launch = SupervisorLaunchRecord {
        schema: "kin.supervisor.launch.v2".to_string(),
        protocol: SUPERVISOR_STARTUP_PROTOCOL,
        generation: generation.clone(),
        launcher: current_process_identity()?,
        authority: file_identity.clone(),
    };
    write_immutable_startup_record(
        &supervisor_launch_record_path(&namespace.records, &generation),
        &launch,
    )?;
    Ok(SupervisorStartupLock {
        dir: dir.to_path_buf(),
        sentinel: namespace.sentinel,
        records: namespace.records,
        sentinel_file: namespace.sentinel_file,
        sentinel_identity: namespace.sentinel_identity,
        file,
        file_identity,
        generation,
        launch,
    })
}

#[derive(Debug)]
enum SupervisorStartupAcquisition {
    Authority(SupervisorStartupLock),
    Connected(String),
}

async fn acquire_supervisor_startup_lock() -> Result<SupervisorStartupAcquisition> {
    let dir = supervisor_dir();
    acquire_supervisor_startup_lock_in_dir_with_timeout(
        &dir,
        Duration::from_secs(startup_lock_timeout_secs()),
    )
    .await
}

async fn acquire_supervisor_startup_lock_in_dir_with_timeout(
    dir: &Path,
    timeout: Duration,
) -> Result<SupervisorStartupAcquisition> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create supervisor state directory {}", dir.display()))?;
    let path = dir.join(SUPERVISOR_STARTUP_FILE);
    let deadline = Instant::now() + timeout;

    loop {
        match try_acquire_supervisor_startup_lock_in_dir(dir) {
            Ok(authority) => return Ok(SupervisorStartupAcquisition::Authority(authority)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // A caller waiting behind a live launch must follow discovery
                // while it waits. Returning the repaired endpoint promptly is
                // the normal outcome; waiting for the launcher's lock to drop
                // would strand this command behind a healthy supervisor.
                let recorded = supervisor_endpoint_snapshot(dir);
                if let (Some(pid), Some(port)) = (recorded.pid, recorded.port) {
                    if process_liveness(pid).may_be_alive() {
                        if let Ok(base_url) =
                            validate_supervisor_endpoint(LiveDaemonEndpoint { pid, port }).await
                        {
                            return Ok(SupervisorStartupAcquisition::Connected(base_url));
                        }
                    }
                }
                if Instant::now() >= deadline {
                    bail!(
                        "timed out waiting for supervisor startup lock at {}",
                        path.display()
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("create supervisor startup lock at {}", path.display())
                });
            }
        }
    }
}

fn supervisor_startup_authority_is_held(namespace: &Path) -> std::io::Result<bool> {
    let file = open_startup_regular_file(
        &namespace.join(SUPERVISOR_STARTUP_AUTHORITY_FILE),
        false,
        false,
        true,
    )?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(false)
        }
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(true),
        Err(error) => Err(error),
    }
}

/// Validate a versioned launch capability inside the supervisor child.
///
/// The immutable PR-base launcher supplies no generation. It is rejected
/// before singleton acquisition or endpoint publication, so its unconditional
/// Drop cleanup cannot inherit a current daemon lifetime. A current launcher is
/// accepted only while its exact authority inode is locked and its
/// boot/birth-bound identity is still current. A same-process supervisor
/// re-exec may reuse an existing adoption record because `exec` preserves both
/// PID and process birth identity.
#[doc(hidden)]
pub fn validate_supervisor_runtime_startup(
    dir: &Path,
) -> std::io::Result<SupervisorRuntimeStartup> {
    let generation = std::env::var(SUPERVISOR_STARTUP_GENERATION_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            let marker = dir.join(SUPERVISOR_STARTUP_FILE);
            let detail = match std::fs::symlink_metadata(&marker) {
                Ok(metadata) if !metadata.is_dir() => {
                    "legacy launcher marker detected; this daemon requires startup protocol v2"
                }
                Ok(_) => "startup protocol v2 launch capability is missing",
                Err(_) => "startup protocol v2 launch capability is missing",
            };
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{detail}; refusing before supervisor boot"),
            )
        })?;
    let generation = generation.trim();
    Uuid::parse_str(generation).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "supervisor startup generation is not a UUID",
        )
    })?;

    let sentinel = dir.join(SUPERVISOR_STARTUP_FILE);
    let sentinel_file = open_startup_directory(&sentinel)?;
    if sentinel_file.metadata()?.modified()?.elapsed().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "supervisor startup sentinel does not preserve bounded legacy rollback",
        ));
    }
    let records = sentinel.join(SUPERVISOR_STARTUP_RECORDS_DIR);
    let _records_file = open_startup_directory(&records)?;
    let authority_file = open_startup_regular_file(
        &sentinel.join(SUPERVISOR_STARTUP_AUTHORITY_FILE),
        false,
        false,
        false,
    )?;
    let authority = startup_file_identity(&authority_file)?;
    let launch: SupervisorLaunchRecord =
        read_startup_record(&supervisor_launch_record_path(&records, generation))?;
    if launch.schema != "kin.supervisor.launch.v2"
        || launch.protocol != SUPERVISOR_STARTUP_PROTOCOL
        || launch.generation != generation
        || launch.authority != authority
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "supervisor launch capability does not match the current startup authority",
        ));
    }

    let supervisor = current_process_identity()?;
    let adoption_path = supervisor_adoption_record_path(&records, generation);
    let accepted_reexec = match read_startup_record::<SupervisorAdoptionRecord>(&adoption_path) {
        Ok(existing) => {
            existing.schema == "kin.supervisor.adoption.v2"
                && existing.protocol == SUPERVISOR_STARTUP_PROTOCOL
                && existing.generation == generation
                && existing.authority == authority
                && existing.supervisor == supervisor
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if !accepted_reexec
        && (!process_identity_is_current(&launch.launcher)?
            || !supervisor_startup_authority_is_held(&sentinel)?)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "supervisor launcher is not the live owner of the launch capability",
        ));
    }
    Ok(SupervisorRuntimeStartup {
        records,
        generation: generation.to_string(),
        authority,
        supervisor,
    })
}

/// What probing a recorded daemon endpoint established.
///
/// The distinction that matters is *why* an endpoint is unusable. A daemon that
/// simply has not answered yet is alive; a daemon whose recorded process is gone,
/// or that answered and proved the record wrong, is not. Only the latter may
/// have its endpoint files cleared: deleting a live daemon's `daemon.pid` and
/// `daemon.port` strands the repo, because the next start loses the singleton
/// flock to the daemon still holding it and the lock reclaim has lost the pid it
/// needed as evidence.
#[derive(Debug)]
enum EndpointVerdict {
    /// The daemon answered readiness and health for this repo.
    Serving(String),
    /// Positive evidence the record is wrong: the recorded process is gone, or
    /// the endpoint answered and named a different repo or a non-serving status.
    /// Safe to clear and respawn.
    Invalid(String),
    /// The recorded owner process is alive but has not reported readiness.
    /// Never clear: a busy daemon is not a dead one.
    LiveNotReady {
        pid: u32,
        port: u16,
        detail: String,
        warming: bool,
    },
}

/// Poll a recorded endpoint until it serves, proves itself invalid, or the
/// budget runs out.
///
/// Reaching the deadline is not evidence of anything except that the daemon is
/// slow, so it yields `LiveNotReady` rather than a verdict the caller could act
/// on destructively.
async fn probe_daemon_endpoint(
    kin_root: &Path,
    endpoint: LiveDaemonEndpoint,
    timeout: Duration,
) -> EndpointVerdict {
    let warming = std::sync::Arc::new(AtomicBool::new(false));
    probe_daemon_endpoint_with_warming_signal(kin_root, endpoint, timeout, warming).await
}

async fn probe_daemon_endpoint_with_warming_signal(
    kin_root: &Path,
    endpoint: LiveDaemonEndpoint,
    timeout: Duration,
    warming_signal: std::sync::Arc<AtomicBool>,
) -> EndpointVerdict {
    let Some(working_dir) = kin_root.parent() else {
        return EndpointVerdict::Invalid("invalid .kin layout: no parent".to_string());
    };
    let base_url = format!("http://127.0.0.1:{}", endpoint.port);
    let client = daemon_health_client();
    let deadline = Instant::now() + timeout;
    let mut warming = false;

    loop {
        if !is_process_alive(endpoint.pid) {
            return EndpointVerdict::Invalid(format!(
                "recorded daemon process {} is not alive",
                endpoint.pid
            ));
        }

        let probe_error = match client.get(format!("{base_url}/readiness")).send().await {
            Ok(resp) if resp.status().is_success() => {
                // Successful readiness carries the warming signal too. Parse it
                // before the health probe: a daemon can answer readiness and
                // then be too busy to complete the second request, and that is
                // exactly when retaining "warming" makes the diagnostic honest.
                if let Ok(readiness) = resp.json::<ReadinessResponse>().await {
                    warming = readiness.warming;
                    warming_signal.store(warming, Ordering::Relaxed);
                }
                match probe_health_for_repo(&client, &base_url, kin_root, working_dir).await {
                    HealthProbe::Matches => return EndpointVerdict::Serving(base_url),
                    // The daemon answered and identified itself as something
                    // else. That is real evidence the record is stale, not a
                    // slow start.
                    HealthProbe::Rejected(reason) => return EndpointVerdict::Invalid(reason),
                    // No usable answer says nothing about whether the daemon is
                    // alive, so it must not be treated as evidence against it.
                    HealthProbe::Unanswered(detail) => detail,
                }
            }
            Ok(resp) => {
                let status = resp.status();
                // A 503 body carries the daemon's own readiness detail. It
                // answered, so it is unambiguously alive; keep the last known
                // warming signal if this particular body fails to parse.
                match resp.json::<ReadinessResponse>().await {
                    Ok(readiness) => {
                        warming = readiness.warming;
                        warming_signal.store(warming, Ordering::Relaxed);
                        format!(
                            "readiness returned HTTP {status} (ready={}, warming={})",
                            readiness.ready, readiness.warming
                        )
                    }
                    Err(_) => format!("readiness returned HTTP {status}"),
                }
            }
            Err(err) => err.to_string(),
        };

        if Instant::now() >= deadline {
            return EndpointVerdict::LiveNotReady {
                pid: endpoint.pid,
                port: endpoint.port,
                detail: probe_error,
                warming,
            };
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// What a `/health` probe established about the daemon behind an endpoint.
///
/// The split that matters is answered vs unanswered. Only an answer identifies
/// the daemon, and only an identification can prove an endpoint record wrong.
/// A dropped connection or an unparseable body proves nothing, and collapsing
/// it into "invalid" would put the endpoint-clobbering bug straight back.
enum HealthProbe {
    /// The daemon answered and serves this repo.
    Matches,
    /// The daemon answered and is serving a different repo, or reported a
    /// status that is not serving at all.
    Rejected(String),
    /// No usable answer: transport error, HTTP error status, or a body that
    /// would not parse.
    Unanswered(String),
}

async fn probe_health_for_repo(
    client: &reqwest::Client,
    base_url: &str,
    kin_root: &Path,
    working_dir: &Path,
) -> HealthProbe {
    let answered = async {
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
        Ok::<HealthResponse, anyhow::Error>(health)
    }
    .await;

    match answered {
        Ok(health) => match classify_health_repo(&health, kin_root, working_dir) {
            RepoIdentity::Matches => HealthProbe::Matches,
            RepoIdentity::Rejected(reason) => HealthProbe::Rejected(reason),
            // The daemon answered but did not identify itself in terms this
            // client can compare. That is silence about identity, and silence
            // must not authorize deleting its endpoint.
            RepoIdentity::Indeterminate(detail) => HealthProbe::Unanswered(detail),
        },
        Err(error) => HealthProbe::Unanswered(error.to_string()),
    }
}

#[derive(Debug, thiserror::Error)]
enum DaemonReadinessError {
    #[error("{0:#}")]
    Failed(#[source] anyhow::Error),
    #[error("{0}")]
    Timeout(String),
}

async fn wait_for_daemon_ready(
    kin_root: &Path,
    child: &mut Child,
    deadline: Instant,
    log_offset: u64,
) -> std::result::Result<String, DaemonReadinessError> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let mut last_error = String::from("daemon did not report its port");

    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .context("check daemon child status")
            .map_err(DaemonReadinessError::Failed)?
        {
            return Err(DaemonReadinessError::Failed(anyhow!(
                "daemon exited during startup with status {status}; recent log:\n{}",
                daemon_log_tail_since(kin_root, log_offset)
            )));
        }

        // The daemon binds :0 and writes its actual bound port to the port file
        // once it is listening. Read it each poll until it appears — the port
        // file is the daemon→CLI handshake that lets the daemon own port
        // selection, eliminating the reserve-release-rebind race.
        let Some(port) = read_port_file(kin_root) else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let base_url = format!("http://127.0.0.1:{port}");

        if is_port_open(port) {
            match client.get(format!("{base_url}/readiness")).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let health_result: Result<HealthResponse> = async {
                        client
                            .get(format!("{base_url}/health"))
                            .send()
                            .await
                            .context("probe daemon health")?
                            .error_for_status()
                            .context("daemon health returned an error")?
                            .json()
                            .await
                            .context("parse daemon health response")
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

    // The deadline measures this caller's patience, not the daemon's health.
    // Killing here used to be unconditional, which meant a daemon still loading
    // a large graph was destroyed for being slow — and its replacement started
    // from cold and hit the same deadline. Endpoint probing already settled
    // this: only positive evidence of death authorizes destruction. A daemon
    // proven gone is reaped; a live one is left holding its repo, and the next
    // invocation finds it through the ordinary escalating-patience path.
    let disposition = kin_daemon_spawn::startup_disposition(child)
        .unwrap_or(kin_daemon_spawn::StartupDisposition::Indeterminate);
    let reaped = kin_daemon_spawn::terminate_if_proven_dead(child, &disposition);
    let fate = if reaped {
        "it had already exited and was reaped"
    } else {
        "it is still running and was left alone rather than killed for being slow; \
         wait for it, or stop it with `kin daemon stop`"
    };
    Err(DaemonReadinessError::Timeout(format!(
        "waited {:.1}s: {}; {}; recent log:\n{}",
        timeout.as_secs_f64(),
        last_error,
        fate,
        daemon_log_tail_since(kin_root, log_offset)
    )))
}

/// What the caller should do about the endpoint currently recorded for a repo.
#[derive(Debug)]
enum ExistingDaemon {
    /// Use this daemon.
    Connected(String),
    /// No usable record (absent, or proven wrong and now cleared). Start one.
    None,
    /// A serialized owner exists, but its endpoint publication is not complete
    /// yet. Re-snapshot until the shared startup deadline instead of treating a
    /// legitimate no-endpoint or PID-only state as terminal.
    Starting(String),
    /// A live daemon owns this repo but is not serving yet. Starting a second
    /// one would lose the singleton flock, so the caller must report this
    /// instead.
    LiveNotReady(String),
}

/// Resolve the endpoint recorded for this repo, escalating patience — never
/// destruction — when the recorded owner is alive.
///
/// The short budget is the fast path for a healthy daemon. Exhausting it while
/// the recorded process is still alive says only that the daemon is busy (a
/// large graph load, a cross-repo warm-up), so this escalates to the same long
/// budget a freshly spawned daemon gets rather than declaring it dead. Endpoint
/// files are cleared only against positive evidence.
async fn wait_for_existing_daemon(kin_root: &Path) -> ExistingDaemon {
    wait_for_existing_daemon_within(
        kin_root,
        Duration::from_secs(existing_daemon_ready_timeout_secs()),
        Duration::from_secs(daemon_ready_timeout_secs()),
    )
    .await
}

async fn wait_for_existing_daemon_within(
    kin_root: &Path,
    short: Duration,
    patience: Duration,
) -> ExistingDaemon {
    let deadline = Instant::now() + patience;
    loop {
        match inspect_existing_daemon_once(kin_root, short, deadline, patience).await {
            ExistingDaemon::Starting(_detail) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            ExistingDaemon::Starting(detail) => {
                return ExistingDaemon::LiveNotReady(format!(
                    "kin daemon startup is serialized but endpoint publication did not complete \
                     within {}s: {detail}. Kin will not start a second daemon",
                    patience.as_secs()
                ));
            }
            resolved => return resolved,
        }
    }
}

async fn inspect_existing_daemon_once(
    kin_root: &Path,
    short: Duration,
    deadline: Instant,
    patience: Duration,
) -> ExistingDaemon {
    let recorded = daemon_endpoint_snapshot(kin_root);
    let Some(pid) = recorded.pid else {
        if recorded.pid_exists {
            return ExistingDaemon::LiveNotReady(
                "the recorded daemon PID is unparseable; refusing to replace an owner whose \
                 liveness cannot be established"
                    .to_string(),
            );
        }
        if !recorded.port_exists {
            let retirement = retire_daemon_endpoint_if_unchanged(kin_root, recorded);
            return match retirement {
                DaemonEndpointRetirement::Retired => ExistingDaemon::None,
                preserved if preserved.may_reflect_publication() => {
                    ExistingDaemon::Starting(format!(
                        "the endpoint is not published yet and {}",
                        preserved.preserved_reason()
                    ))
                }
                preserved => {
                    follow_preserved_daemon_endpoint(kin_root, deadline, patience, preserved).await
                }
            };
        }
        let retirement = retire_daemon_endpoint_if_unchanged(kin_root, recorded);
        return match retirement {
            DaemonEndpointRetirement::Retired => ExistingDaemon::None,
            preserved if preserved.may_reflect_publication() => ExistingDaemon::Starting(format!(
                "the endpoint PID is not published yet and {}",
                preserved.preserved_reason()
            )),
            preserved => {
                follow_preserved_daemon_endpoint(kin_root, deadline, patience, preserved).await
            }
        };
    };

    if process_liveness(pid).authorizes_cleanup() {
        let retirement = retire_daemon_endpoint_if_unchanged(kin_root, recorded);
        return match retirement {
            DaemonEndpointRetirement::Retired => ExistingDaemon::None,
            preserved if preserved.may_reflect_publication() => ExistingDaemon::Starting(format!(
                "the recorded owner changed during startup and {}",
                preserved.preserved_reason()
            )),
            preserved => {
                follow_preserved_daemon_endpoint(kin_root, deadline, patience, preserved).await
            }
        };
    }

    let Some(port) = recorded.port else {
        return ExistingDaemon::Starting(format!(
            "kin daemon pid {pid} may still own this repo and has not published a usable port yet"
        ));
    };
    let existing = LiveDaemonEndpoint { pid, port };

    let short_deadline = (Instant::now() + short).min(deadline);
    let mut verdict = probe_daemon_endpoint_until(kin_root, existing, short_deadline, false).await;

    if let EndpointVerdict::LiveNotReady {
        pid, port, warming, ..
    } = &verdict
    {
        let last_warming = *warming;
        warn!(
            pid = *pid,
            port = *port,
            warming = *warming,
            patience_secs = patience.as_secs(),
            "daemon for this repo is alive but not ready yet; waiting rather than \
             replacing a running daemon"
        );
        verdict = probe_daemon_endpoint_until(kin_root, existing, deadline, last_warming).await;
    }

    match verdict {
        EndpointVerdict::Serving(base_url) => {
            info!(
                pid = existing.pid,
                port = existing.port,
                "connected to existing daemon"
            );
            ExistingDaemon::Connected(base_url)
        }
        EndpointVerdict::Invalid(reason) => {
            warn!(
                pid = existing.pid,
                port = existing.port,
                error = %reason,
                "daemon endpoint proved invalid; clearing stale endpoint files"
            );
            // The verdict is true about the endpoint that was probed, which may
            // no longer be the endpoint on disk — the probe deliberately runs
            // long enough for a successor to take over.
            let retirement =
                remove_daemon_files_if_unchanged(kin_root, existing.pid, Some(existing.port));
            match retirement {
                DaemonEndpointRetirement::Retired => ExistingDaemon::None,
                preserved if preserved.may_reflect_publication() => {
                    ExistingDaemon::Starting(format!(
                        "the endpoint changed while its predecessor was retired and {}",
                        preserved.preserved_reason()
                    ))
                }
                preserved => {
                    follow_preserved_daemon_endpoint(kin_root, deadline, patience, preserved).await
                }
            }
        }
        EndpointVerdict::LiveNotReady {
            pid,
            port,
            detail,
            warming,
        } => ExistingDaemon::LiveNotReady(live_daemon_not_ready_message(
            pid,
            port,
            &detail,
            warming,
            patience.as_secs(),
        )),
    }
}

async fn probe_daemon_endpoint_until(
    kin_root: &Path,
    endpoint: LiveDaemonEndpoint,
    deadline: Instant,
    last_warming: bool,
) -> EndpointVerdict {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return EndpointVerdict::LiveNotReady {
            pid: endpoint.pid,
            port: endpoint.port,
            detail: "the caller's daemon readiness deadline elapsed".to_string(),
            warming: last_warming,
        };
    }
    let warming_signal = std::sync::Arc::new(AtomicBool::new(last_warming));
    match tokio::time::timeout(
        remaining,
        probe_daemon_endpoint_with_warming_signal(
            kin_root,
            endpoint,
            remaining,
            std::sync::Arc::clone(&warming_signal),
        ),
    )
    .await
    {
        Ok(verdict) => verdict,
        Err(_) => EndpointVerdict::LiveNotReady {
            pid: endpoint.pid,
            port: endpoint.port,
            detail: "the caller's daemon readiness deadline elapsed".to_string(),
            warming: warming_signal.load(Ordering::Relaxed),
        },
    }
}

async fn follow_preserved_daemon_endpoint(
    kin_root: &Path,
    deadline: Instant,
    patience: Duration,
    retirement: DaemonEndpointRetirement,
) -> ExistingDaemon {
    debug_assert!(!matches!(retirement, DaemonEndpointRetirement::Retired));
    let reason = retirement.preserved_reason();
    let current = daemon_endpoint_snapshot(kin_root);
    let (Some(pid), Some(port)) = (current.pid, current.port) else {
        return ExistingDaemon::LiveNotReady(format!(
            "daemon endpoint retirement was refused because {reason}; the current endpoint is \
             incomplete or indeterminate, so kin will not start a replacement"
        ));
    };
    let endpoint = LiveDaemonEndpoint { pid, port };
    match probe_daemon_endpoint_until(kin_root, endpoint, deadline, false).await {
        EndpointVerdict::Serving(base_url) => ExistingDaemon::Connected(base_url),
        EndpointVerdict::LiveNotReady {
            pid,
            port,
            detail,
            warming,
        } => ExistingDaemon::LiveNotReady(format!(
            "{} Retirement was refused because {reason}.",
            live_daemon_not_ready_message(pid, port, &detail, warming, patience.as_secs(),)
        )),
        EndpointVerdict::Invalid(detail) => ExistingDaemon::LiveNotReady(format!(
            "daemon endpoint retirement was refused because {reason}; the preserved endpoint \
             (pid {pid}, port {port}) is not usable: {detail}. Kin will not start a second daemon"
        )),
    }
}

/// Message for a daemon that owns this repo, is alive, and never reported
/// readiness inside the full budget.
///
/// It names the process so an operator can act on it. The old path silently
/// deleted this daemon's endpoint files and spawned a replacement, which lost
/// the singleton flock and left the repo unusable until the first daemon
/// exited — with nothing in the output pointing at the daemon still running.
fn live_daemon_not_ready_message(
    pid: u32,
    port: u16,
    detail: &str,
    warming: bool,
    waited_secs: u64,
) -> String {
    let state = if warming {
        "is still warming its cross-repo index"
    } else {
        "has not reported readiness"
    };
    format!(
        "kin daemon (pid {pid}, port {port}) owns this repo and {state} after {waited_secs}s: \
         {detail}. It is running, so kin will not replace it. Wait for it to finish, or stop it \
         with `kin daemon stop`; raise KIN_DAEMON_READY_TIMEOUT_SECS if this repo needs longer."
    )
}

async fn validate_supervisor_endpoint(endpoint: LiveDaemonEndpoint) -> Result<String> {
    let base_url = format!("http://127.0.0.1:{}", endpoint.port);
    let client = daemon_health_client();
    let health: SupervisorHealthResponse = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .context("probe supervisor health")?
        .error_for_status()
        .context("supervisor health returned an error")?
        .json()
        .await
        .context("parse supervisor health response")?;
    // The supervisor reports "ok" while serving (it has no degraded "attention"
    // state of its own today). Route through the same serving-status predicate so
    // that if the supervisor ever surfaces an alive-but-degraded status it is not
    // mistaken for a dead endpoint and wiped/respawned — only a genuinely unknown
    // status is rejected here.
    if !health_status_is_serving(&health.status) {
        bail!("supervisor health status is {}", health.status);
    }
    Ok(base_url)
}

#[derive(Debug)]
enum ExistingSupervisor {
    Connected(String),
    NeedsStartupAuthority,
    SpawnAuthorized,
    Starting(String),
    LiveNotReady(String),
}

async fn probe_existing_supervisor() -> ExistingSupervisor {
    let dir = supervisor_dir();
    wait_for_existing_supervisor_in_dir(&dir, None).await
}

async fn wait_for_existing_supervisor_in_dir(
    dir: &Path,
    startup_authority: Option<&SupervisorStartupLock>,
) -> ExistingSupervisor {
    wait_for_existing_supervisor_in_dir_with_hook(dir, startup_authority, || {}).await
}

async fn wait_for_existing_supervisor_in_dir_with_hook<F>(
    dir: &Path,
    startup_authority: Option<&SupervisorStartupLock>,
    after_snapshot: F,
) -> ExistingSupervisor
where
    F: FnOnce(),
{
    let recorded = supervisor_endpoint_snapshot(dir);
    after_snapshot();
    let Some(pid) = recorded.pid else {
        if recorded.pid_exists {
            return ExistingSupervisor::LiveNotReady(
                "the supervisor PID record is unparseable; refusing to replace an owner whose \
                 liveness cannot be established"
                    .to_string(),
            );
        }
        let Some(startup_authority) = startup_authority else {
            return ExistingSupervisor::NeedsStartupAuthority;
        };
        if !recorded.port_exists {
            return match retire_supervisor_endpoint_if_unchanged(dir, recorded, startup_authority) {
                SupervisorEndpointRetirement::Retired => ExistingSupervisor::SpawnAuthorized,
                preserved if preserved.may_reflect_publication() => {
                    ExistingSupervisor::Starting(format!(
                        "the supervisor endpoint is not published yet and {}",
                        preserved.preserved_reason()
                    ))
                }
                preserved => ExistingSupervisor::LiveNotReady(format!(
                    "supervisor startup authority is unavailable because {}; kin will not start \
                     a replacement",
                    preserved.preserved_reason()
                )),
            };
        }
        return match retire_supervisor_endpoint_if_unchanged(dir, recorded, startup_authority) {
            SupervisorEndpointRetirement::Retired => ExistingSupervisor::SpawnAuthorized,
            preserved if preserved.may_reflect_publication() => {
                ExistingSupervisor::Starting(format!(
                    "the supervisor PID is not published yet and {}",
                    preserved.preserved_reason()
                ))
            }
            preserved => ExistingSupervisor::LiveNotReady(format!(
                "supervisor endpoint retirement was refused because {}; kin will not start a \
                 replacement",
                preserved.preserved_reason()
            )),
        };
    };

    if process_liveness(pid).authorizes_cleanup() {
        let Some(startup_authority) = startup_authority else {
            return ExistingSupervisor::NeedsStartupAuthority;
        };
        return match retire_supervisor_endpoint_if_unchanged(dir, recorded, startup_authority) {
            SupervisorEndpointRetirement::Retired => ExistingSupervisor::SpawnAuthorized,
            preserved if preserved.may_reflect_publication() => {
                ExistingSupervisor::Starting(format!(
                    "the supervisor endpoint changed during startup and {}",
                    preserved.preserved_reason()
                ))
            }
            preserved => ExistingSupervisor::LiveNotReady(format!(
                "supervisor endpoint retirement was refused because {}; kin will not start a \
                 replacement",
                preserved.preserved_reason()
            )),
        };
    }

    let Some(port) = recorded.port else {
        return ExistingSupervisor::Starting(format!(
            "kin supervisor pid {pid} may still own the per-user control plane and has not \
             published a usable port yet"
        ));
    };
    let existing = LiveDaemonEndpoint { pid, port };
    match validate_supervisor_endpoint(existing).await {
        Ok(base_url) => ExistingSupervisor::Connected(base_url),
        Err(err) => {
            warn!(
                pid = existing.pid,
                port = existing.port,
                error = %err,
                "supervisor owner is live or indeterminate but health is unavailable; \
                 preserving endpoint and refusing replacement"
            );
            ExistingSupervisor::Starting(format!(
                "kin supervisor (pid {}, port {}) may still own the per-user control plane but \
                 has not passed health yet: {err}",
                existing.pid, existing.port
            ))
        }
    }
}

async fn follow_existing_supervisor_publication(
    dir: &Path,
    startup_authority: &SupervisorStartupLock,
    timeout: Duration,
) -> ExistingSupervisor {
    let deadline = Instant::now() + timeout;
    loop {
        match wait_for_existing_supervisor_in_dir(dir, Some(startup_authority)).await {
            ExistingSupervisor::Starting(_detail) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            ExistingSupervisor::Starting(detail) => {
                return ExistingSupervisor::LiveNotReady(format!(
                    "kin supervisor startup is serialized but endpoint publication did not \
                     complete within {}s: {detail}. Kin will not start a second supervisor",
                    timeout.as_secs()
                ));
            }
            resolved => return resolved,
        }
    }
}

fn open_supervisor_log() -> Result<File> {
    let dir = supervisor_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create supervisor state directory {}", dir.display()))?;
    let log_path = dir.join("supervisor.log");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open supervisor log at {}", log_path.display()))
}

async fn wait_for_supervisor_ready(
    child: &mut Child,
    deadline: Instant,
    startup_authority: &mut SupervisorStartupLock,
) -> Result<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let mut last_error = String::from("supervisor did not report its port");
    let mut next_startup_heartbeat = Instant::now();

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("check supervisor child status")? {
            bail!("supervisor exited during startup with status {status}");
        }
        if Instant::now() >= next_startup_heartbeat {
            if !startup_authority
                .heartbeat()
                .context("refresh supervisor startup authority during readiness")?
            {
                let _ = child.kill();
                let _ = child.wait();
                bail!("supervisor startup authority changed during readiness");
            }
            next_startup_heartbeat = Instant::now() + Duration::from_secs(1);
        }

        // The supervisor binds :0 and writes its real bound port to its port
        // file once listening. Read it each poll until it appears — the port
        // file is the supervisor→CLI handshake.
        let Some(port) = std::fs::read_to_string(supervisor_port_path())
            .ok()
            .and_then(|value| value.trim().parse::<u16>().ok())
        else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let base_url = format!("http://127.0.0.1:{port}");

        if is_port_open(port) {
            match client.get(format!("{base_url}/health")).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(base_url),
                Ok(resp) => last_error = format!("health returned HTTP {}", resp.status()),
                Err(err) => last_error = err.to_string(),
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    bail!(
        "supervisor failed to become ready within {:.1}s: {}",
        timeout.as_secs_f64(),
        last_error
    )
}

pub async fn ensure_supervisor_running() -> Result<String> {
    if let Ok(url) = std::env::var("KIN_SUPERVISOR_URL") {
        let port = url
            .rsplit(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("invalid KIN_SUPERVISOR_URL: {url}"))?;
        return validate_supervisor_endpoint(LiveDaemonEndpoint {
            pid: std::process::id(),
            port,
        })
        .await
        .map(|_| url);
    }

    // The fast path is deliberately read-only. No endpoint may be retired
    // before the current CLI holds the v2 startup authority; immutable clients
    // are excluded by the permanent directory sentinel.
    match probe_existing_supervisor().await {
        ExistingSupervisor::Connected(base_url) => return Ok(base_url),
        ExistingSupervisor::LiveNotReady(message) => bail!(message),
        ExistingSupervisor::NeedsStartupAuthority | ExistingSupervisor::Starting(_) => {}
        ExistingSupervisor::SpawnAuthorized => {
            bail!("supervisor probe authorized a spawn without startup protocol authority")
        }
    }

    // Validate the binary's explicit protocol acknowledgement before taking
    // cleanup or spawn authority. In particular, an immutable base daemon is
    // rejected here and is never started under a marker it cannot adopt.
    let daemon_bin = find_daemon_binary()?;
    let mut startup_authority = match acquire_supervisor_startup_lock().await? {
        SupervisorStartupAcquisition::Connected(base_url) => return Ok(base_url),
        SupervisorStartupAcquisition::Authority(authority) => authority,
    };
    let dir = supervisor_dir();
    match follow_existing_supervisor_publication(
        &dir,
        &startup_authority,
        Duration::from_secs(daemon_ready_timeout_secs()),
    )
    .await
    {
        ExistingSupervisor::Connected(base_url) => return Ok(base_url),
        ExistingSupervisor::Starting(message) | ExistingSupervisor::LiveNotReady(message) => {
            bail!(message)
        }
        ExistingSupervisor::SpawnAuthorized => {}
        ExistingSupervisor::NeedsStartupAuthority => {
            bail!("supervisor startup authority was lost before the spawn decision")
        }
    }

    // The supervisor binds :0 and reports its real bound port via its endpoint
    // files; passing 0 (rather than a reserved port) removes the same
    // reserve-release-rebind race the repo-daemon path had. The prior
    // ExistingSupervisor::SpawnAuthorized is the only spawn authorization.
    // Stale endpoint retirement completed while holding the v2 kernel-locked
    // startup authority plus lifecycle/singleton authority, and that startup
    // authority remains held until this child has published, acknowledged the
    // exact generation, and passed health.
    info!(binary = %daemon_bin.display(), "starting supervisor (OS-assigned port)");

    let mut cmd = std::process::Command::new(&daemon_bin);
    scrub_daemon_process_authority(&mut cmd);
    cmd.args(["--supervisor", "--port", "0"]);
    cmd.env(
        SUPERVISOR_STARTUP_GENERATION_ENV,
        startup_authority.generation(),
    );
    let log = open_supervisor_log()?;
    let stderr = log
        .try_clone()
        .context("clone supervisor log handle for stderr")?;
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(stderr));
    if std::env::var_os("KIN_SUPERVISOR_IDLE_TIMEOUT_SECS").is_none() {
        cmd.env(
            "KIN_SUPERVISOR_IDLE_TIMEOUT_SECS",
            default_idle_timeout_secs(),
        );
    }

    kin_daemon_spawn::detach_from_caller(&mut cmd);

    let mut child = cmd.spawn().context("spawn kin supervisor")?;
    let deadline = Instant::now() + Duration::from_secs(daemon_ready_timeout_secs());
    let base_url = wait_for_supervisor_ready(&mut child, deadline, &mut startup_authority).await?;
    if let Err(error) = startup_authority.verify_adoption(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context(
            "supervisor became healthy without acknowledging the exact startup generation",
        );
    }
    info!(supervisor = %base_url, "supervisor is up and ready");
    Ok(base_url)
}

fn supervisor_repo_id_for_working_dir(working_dir: &Path) -> String {
    let canonical = canonical_path_string(working_dir);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("local-{}", &hex::encode(digest)[..16])
}

fn repo_display_name_for_working_dir(working_dir: &Path) -> String {
    working_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn repo_id_for_kin_root(kin_root: &Path) -> Option<String> {
    kin_root.parent().map(supervisor_repo_id_for_working_dir)
}

fn repo_display_name_for_kin_root(kin_root: &Path) -> Option<String> {
    kin_root.parent().map(repo_display_name_for_working_dir)
}

fn supervisor_instance_id(pid: u32, port: u16) -> String {
    format!("pid-{pid}-port-{port}")
}

async fn supervisor_route_for_repo(kin_root: &Path, supervisor_url: &str) -> Option<String> {
    let repo_id = repo_id_for_kin_root(kin_root)?;
    let route: SupervisorRouteResponse = daemon_health_client()
        .get(format!(
            "{}/repos/{}/route",
            supervisor_url.trim_end_matches('/'),
            urlencoding::encode(&repo_id)
        ))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;

    let port = route
        .endpoint
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())?;
    let endpoint = LiveDaemonEndpoint {
        pid: read_pid_file(kin_root).unwrap_or(std::process::id()),
        port,
    };
    // A supervisor route that does not check out just means this path cannot
    // answer; the repo-local endpoint path decides what is stale. Nothing is
    // cleared from here.
    match probe_daemon_endpoint(
        kin_root,
        endpoint,
        Duration::from_secs(existing_daemon_ready_timeout_secs()),
    )
    .await
    {
        EndpointVerdict::Serving(base_url) => Some(base_url),
        EndpointVerdict::Invalid(_) | EndpointVerdict::LiveNotReady { .. } => None,
    }
}

fn supervisor_route_for_repo_if_running(kin_root: &Path) -> Option<String> {
    let supervisor = live_supervisor_endpoint()?;
    let supervisor_url = format!("http://127.0.0.1:{}", supervisor.port);
    let repo_id = repo_id_for_kin_root(kin_root)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let route: SupervisorRouteResponse = client
        .get(format!(
            "{}/repos/{}/route",
            supervisor_url.trim_end_matches('/'),
            urlencoding::encode(&repo_id)
        ))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()?;

    let working_dir = kin_root.parent()?;
    let health: HealthResponse = client
        .get(format!("{}/health", route.endpoint.trim_end_matches('/')))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()?;
    validate_health_repo(&health, working_dir).ok()?;
    Some(route.endpoint)
}

async fn supervisor_route_for_repo_if_running_async(kin_root: &Path) -> Option<String> {
    let supervisor = live_supervisor_endpoint()?;
    let supervisor_url = format!("http://127.0.0.1:{}", supervisor.port);
    let repo_id = repo_id_for_kin_root(kin_root)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let route: SupervisorRouteResponse = client
        .get(format!(
            "{}/repos/{}/route",
            supervisor_url.trim_end_matches('/'),
            urlencoding::encode(&repo_id)
        ))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;

    let working_dir = kin_root.parent()?;
    let health: HealthResponse = client
        .get(format!("{}/health", route.endpoint.trim_end_matches('/')))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    validate_health_repo(&health, working_dir).ok()?;
    Some(route.endpoint)
}

async fn register_repo_daemon_with_supervisor(
    kin_root: &Path,
    daemon_url: &str,
    supervisor_url: &str,
) -> Result<()> {
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| anyhow!("invalid .kin layout: no parent"))?;
    let health: HealthResponse = daemon_health_client()
        .get(format!("{daemon_url}/health"))
        .send()
        .await
        .context("probe daemon health for supervisor registration")?
        .error_for_status()
        .context("daemon health returned an error for supervisor registration")?
        .json()
        .await
        .context("parse daemon health for supervisor registration")?;
    validate_health_repo(&health, working_dir)?;
    let repo_id = repo_id_for_kin_root(kin_root)
        .ok_or_else(|| anyhow!("invalid .kin layout: no parent for supervisor route id"))?;
    let display_name = repo_display_name_for_kin_root(kin_root)
        .unwrap_or_else(|| health.repo_id.clone().unwrap_or_else(|| repo_id.clone()));
    let port = daemon_url
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid daemon URL: {daemon_url}"))?;
    let pid = health.pid.unwrap_or_else(std::process::id);
    let registration = SupervisorRegistration {
        repo_id,
        display_name,
        instance_id: supervisor_instance_id(pid, port),
        repo_root: health
            .repo_root
            .unwrap_or_else(|| canonical_path_string(working_dir)),
        pid,
        port,
        endpoint: daemon_url.to_string(),
        graph_entity_count: health.graph_entity_count,
    };

    // The shared supervisor self-terminates after an idle window and deletes its
    // port file. A long, passive init (no supervisor traffic) can outlive it, so
    // by the time we register the daemon the supervisor port may be dead and the
    // POST fails with a connection error. Respawn the supervisor and retry once
    // so a slow large-repo init doesn't drop the daemon registration entirely.
    match post_supervisor_registration(supervisor_url, &registration).await {
        Ok(()) => Ok(()),
        Err(err) if is_connection_error(&err) => {
            let fresh_supervisor_url = ensure_supervisor_running()
                .await
                .context("respawn supervisor after registration connection error")?;
            post_supervisor_registration(&fresh_supervisor_url, &registration)
                .await
                .context("register repo daemon with supervisor (after respawn)")
        }
        Err(err) => Err(err).context("register repo daemon with supervisor"),
    }
}

/// POST a daemon registration to the supervisor. Returns the raw reqwest error
/// on transport failure so the caller can distinguish a dead-supervisor
/// connection error (retryable) from a rejection.
async fn post_supervisor_registration(
    supervisor_url: &str,
    registration: &SupervisorRegistration,
) -> Result<(), reqwest::Error> {
    daemon_health_client()
        .post(format!(
            "{}/daemons/register",
            supervisor_url.trim_end_matches('/')
        ))
        .json(registration)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// True when a reqwest error reflects a failure to reach the endpoint at all
/// (connection refused / transport-level), as opposed to an HTTP status error.
/// Used to retry supervisor registration after the idle supervisor has exited.
fn is_connection_error(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_request() || err.is_timeout()
}

/// Supervisor access published to whichever crate is starting a daemon.
///
/// Supervisor startup and registration live here, and `kin-mcp` cannot call
/// this crate: `kin-cli` already depends on `kin-mcp`. So the MCP revival path
/// started daemons the supervisor never learned about, leaving them out of its
/// routing table and unreachable to every other client. Installing this seam
/// gives that path the same registration this one performs.
struct CliSpawnRegistrar;

impl kin_daemon_spawn::DaemonSpawnRegistrar for CliSpawnRegistrar {
    fn supervisor_url(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>> {
        Box::pin(async { ensure_supervisor_running().await.ok() })
    }

    fn register(
        &self,
        kin_root: PathBuf,
        daemon_url: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> {
        Box::pin(async move {
            let supervisor_url = ensure_supervisor_running()
                .await
                .map_err(|error| format!("{error:#}"))?;
            register_repo_daemon_with_supervisor(&kin_root, &daemon_url, &supervisor_url)
                .await
                .map_err(|error| format!("{error:#}"))
        })
    }
}

/// Publish this crate's supervisor access to every daemon spawn in this
/// process, including spawns made from crates that cannot depend on it.
///
/// Idempotent: the first installation wins.
pub fn install_spawn_registrar() {
    kin_daemon_spawn::install_registrar(std::sync::Arc::new(CliSpawnRegistrar));
}

pub async fn ensure_daemon_running(kin_root: &Path) -> std::result::Result<String, AutoStartError> {
    ensure_daemon_running_with_idle_timeout(kin_root, None).await
}

/// Like [`ensure_daemon_running`] but lets the caller inject a specific idle
/// timeout into the spawned daemon process.
///
/// Pass `Some(MCP_IDLE_TIMEOUT_SECS)` on the MCP-initiated path (30 min) so
/// interactive agent sessions don't expire the daemon mid-session. Pass `None`
/// to use the compiled default (60 s). An explicit
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always takes precedence over both.
pub async fn ensure_daemon_running_with_idle_timeout(
    kin_root: &Path,
    idle_timeout_override: Option<&'static str>,
) -> std::result::Result<String, AutoStartError> {
    install_spawn_registrar();
    let supervisor_url = ensure_supervisor_running()
        .await
        .map_err(map_supervisor_auto_start_error)?;
    if let Some(base_url) = supervisor_route_for_repo(kin_root, &supervisor_url).await {
        return Ok(base_url);
    }

    match wait_for_existing_daemon(kin_root).await {
        ExistingDaemon::Connected(base_url) => {
            register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
                .await
                .map_err(AutoStartError::spawn)?;
            return Ok(base_url);
        }
        ExistingDaemon::Starting(message) | ExistingDaemon::LiveNotReady(message) => {
            return Err(AutoStartError::SpawnFailed(message));
        }
        ExistingDaemon::None => {}
    }

    let _startup_lock = acquire_startup_lock(kin_root)
        .await
        .map_err(AutoStartError::spawn)?;
    if let Some(base_url) = supervisor_route_for_repo(kin_root, &supervisor_url).await {
        return Ok(base_url);
    }
    match wait_for_existing_daemon(kin_root).await {
        ExistingDaemon::Connected(base_url) => {
            register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
                .await
                .map_err(AutoStartError::spawn)?;
            return Ok(base_url);
        }
        ExistingDaemon::Starting(message) | ExistingDaemon::LiveNotReady(message) => {
            return Err(AutoStartError::SpawnFailed(message));
        }
        ExistingDaemon::None => {}
    }

    let daemon_bin = find_daemon_binary().map_err(|error| match error {
        DaemonBinaryDiscoveryError::NotFound => AutoStartError::BinaryNotFound,
        DaemonBinaryDiscoveryError::Invalid(detail) => AutoStartError::SpawnFailed(detail),
    })?;
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| AutoStartError::InvalidLayout("no parent".to_string()))?;

    // The daemon owns port selection: it binds :0 and reports the real bound
    // port via the port file. Passing 0 (rather than a port we reserve here)
    // eliminates the reserve-release-rebind race where a sibling process steals
    // the port between our probe and the daemon's bind. Clear an orphaned port
    // only while lifecycle authority proves no successor PID was published.
    remove_orphaned_daemon_port(kin_root);

    info!(binary = %daemon_bin.display(), repo = %working_dir.display(), "starting daemon (OS-assigned port)");

    let user_timeout_set = std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_some();
    let plan = kin_daemon_spawn::DaemonSpawnPlan {
        daemon_bin,
        working_dir: working_dir.to_path_buf(),
        idle_timeout_secs: resolve_idle_timeout_env(user_timeout_set, idle_timeout_override),
        supervisor_url: Some(supervisor_url.clone()),
    };
    let mut cmd = plan.command();
    scrub_daemon_process_authority(&mut cmd);
    let log_offset = daemon_log_len(kin_root);
    let log = open_daemon_log(kin_root).map_err(AutoStartError::spawn)?;
    let stderr = log
        .try_clone()
        .context("clone daemon log handle for stderr")
        .map_err(AutoStartError::spawn)?;
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(stderr));

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn kin-daemon for {}", working_dir.display()))
        .map_err(AutoStartError::spawn)?;

    let timeout_secs = daemon_ready_timeout_secs();
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let base_url = wait_for_daemon_ready(kin_root, &mut child, deadline, log_offset)
        .await
        .map_err(|error| match error {
            DaemonReadinessError::Failed(error) => AutoStartError::spawn(format!("{error:#}")),
            DaemonReadinessError::Timeout(detail) => AutoStartError::StartupTimeout(detail),
        })?;
    register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
        .await
        .map_err(AutoStartError::spawn)?;
    info!(daemon = %base_url, "daemon is up and ready");
    Ok(base_url)
}

fn map_supervisor_auto_start_error(error: anyhow::Error) -> AutoStartError {
    if matches!(
        error.downcast_ref::<DaemonBinaryDiscoveryError>(),
        Some(DaemonBinaryDiscoveryError::NotFound)
    ) {
        AutoStartError::BinaryNotFound
    } else {
        AutoStartError::spawn(format!("kin supervisor is required: {error:#}"))
    }
}

/// Like resolve_daemon_url, but never auto-starts a daemon.
/// Returns the daemon URL only if one is already running or explicitly configured.
pub fn resolve_daemon_url_if_running(layout: &KinLayout) -> Option<String> {
    if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        if url.trim().is_empty() {
            return None;
        }
        return Some(url);
    }
    if let Some(url) = supervisor_route_for_repo_if_running(layout.root()) {
        return Some(url);
    }
    None
}

pub async fn resolve_daemon_url_if_running_async(layout: &KinLayout) -> Option<String> {
    if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        if url.trim().is_empty() {
            return None;
        }
        return Some(url);
    }
    supervisor_route_for_repo_if_running_async(layout.root()).await
}

pub async fn resolve_daemon_url(layout: &KinLayout) -> Result<Option<String>> {
    resolve_daemon_url_inner(layout, None).await
}

/// Like [`resolve_daemon_url`] but uses the 30-minute MCP idle timeout instead
/// of the 60-second CLI default when autostarting a daemon.
///
/// Call from `kin mcp start` so the first daemon spawned on the MCP path gets
/// the same long idle window as the auto-revival path.  An explicit
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always overrides this.
pub async fn resolve_daemon_url_for_mcp(layout: &KinLayout) -> Result<Option<String>> {
    resolve_daemon_url_inner(layout, Some(MCP_IDLE_TIMEOUT_SECS)).await
}

async fn resolve_daemon_url_inner(
    layout: &KinLayout,
    idle_timeout_override: Option<&'static str>,
) -> Result<Option<String>> {
    let no_daemon_autostart = is_transient_bool_env("KIN_NO_DAEMON");
    let explicit_daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    if let Some(url) = explicit_daemon_url {
        return Ok(Some(url));
    }
    if no_daemon_autostart {
        return Ok(supervisor_route_for_repo_if_running_async(layout.root()).await);
    }

    match ensure_daemon_running_with_idle_timeout(layout.root(), idle_timeout_override).await {
        Ok(url) => Ok(Some(url)),
        Err(err) => Err(anyhow::Error::new(err).context("kin daemon is required")),
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
    fn supervisor_autostart_mapping_preserves_typed_binary_discovery() {
        let missing =
            anyhow::Error::new(DaemonBinaryDiscoveryError::NotFound).context("start supervisor");
        assert!(matches!(
            map_supervisor_auto_start_error(missing),
            AutoStartError::BinaryNotFound
        ));

        let misleading =
            anyhow!("readiness probe detail happened to say kin-daemon binary not found");
        assert!(matches!(
            map_supervisor_auto_start_error(misleading),
            AutoStartError::SpawnFailed(detail)
                if detail.contains("readiness probe detail")
        ));
    }

    #[tokio::test]
    async fn idempotent_post_retries_exact_body_with_same_session_authority() {
        use axum::{body::Bytes, http::StatusCode, routing::post, Router};

        #[derive(Default)]
        struct ObservedRequests {
            bodies: Vec<Vec<u8>>,
            sessions: Vec<Option<String>>,
        }

        let observed = std::sync::Arc::new(std::sync::Mutex::new(ObservedRequests::default()));
        let handler_observed = observed.clone();
        let app = Router::new().route(
            "/commands/test",
            post(move |headers: axum::http::HeaderMap, body: Bytes| {
                let observed = handler_observed.clone();
                async move {
                    let mut observed = observed.lock().unwrap();
                    observed.bodies.push(body.to_vec());
                    observed.sessions.push(
                        headers
                            .get("X-Kin-Session")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string),
                    );
                    let status = if observed.bodies.len() == 1 {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::OK
                    };
                    (status, axum::Json(serde_json::json!({"accepted": true})))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = DaemonClient::from_base_url_with_explicit_authority(
            format!("http://{address}"),
            Some("checkout-token".to_string()),
            Some("session-checkout"),
        )
        .unwrap();
        let request = serde_json::json!({
            "operation_id": "stable-operation",
            "path_hex": "7372632f6c69622e7273"
        });

        let response: serde_json::Value = client
            .post_idempotent_json("/commands/test", &request, "test idempotent post")
            .await
            .unwrap();
        server.abort();

        assert_eq!(response, serde_json::json!({"accepted": true}));
        let observed = observed.lock().unwrap();
        assert_eq!(observed.bodies.len(), 2);
        assert_eq!(observed.bodies[0], observed.bodies[1]);
        assert_eq!(
            observed.sessions,
            vec![
                Some("session-checkout".to_string()),
                Some("session-checkout".to_string())
            ]
        );
    }

    #[test]
    fn explicit_client_headers_couple_token_and_requested_session_only() {
        let headers = daemon_client_headers(Some("endpoint-token".to_string()), None).unwrap();
        assert_eq!(
            headers
                .get(reqwest::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer endpoint-token"
        );
        assert!(
            headers.get("X-Kin-Session").is_none(),
            "an explicit no-session client must not manufacture ambient session authority"
        );

        let headers =
            daemon_client_headers(Some("endpoint-token".to_string()), Some("session-explicit"))
                .unwrap();
        assert_eq!(
            headers.get("X-Kin-Session").unwrap().to_str().unwrap(),
            "session-explicit"
        );
        assert!(daemon_client_headers(Some("token\ninjection".to_string()), None).is_err());
        assert!(daemon_client_headers(None, Some("session\ninjection")).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn explicit_auth_token_overrides_the_layout_token() {
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().join(".kin"));
        std::fs::create_dir_all(layout.root()).unwrap();
        std::fs::write(layout.root().join("daemon.token"), "layout-token\n").unwrap();
        let previous = std::env::var_os("KIN_DAEMON_AUTH_TOKEN");
        std::env::set_var("KIN_DAEMON_AUTH_TOKEN", "explicit-token");

        let resolved = resolve_daemon_auth_token_for_layout(&layout);

        match previous {
            Some(value) => std::env::set_var("KIN_DAEMON_AUTH_TOKEN", value),
            None => std::env::remove_var("KIN_DAEMON_AUTH_TOKEN"),
        }
        assert_eq!(resolved.as_deref(), Some("explicit-token"));
    }

    #[test]
    fn daemon_children_drop_inherited_repo_and_projection_authority() {
        // kin-daemon-spawn owns the exhaustive authority list and tests it there.
        // Keep this wrapper test focused on representative delegated scrubbing plus
        // the CLI-owned promise that explicit daemon configuration survives.
        const POISONED_AUTHORITY: &[&str] = &[
            "KIN_DAEMON_URL",
            "KIN_MCP_REPO",
            "KIN_SESSION",
            "KIN_SOURCE_ROOT",
            "KIN_SUPERVISOR_STARTUP_GENERATION",
            "DYLD_LIBRARY_PATH",
            "LD_DEBUG_OUTPUT",
        ];
        let mut command = Command::new("true");
        for key in POISONED_AUTHORITY {
            command.env(key, "poison");
        }
        command.env("KIN_VFS_DISABLE", "poison");
        command.env("KIN_DAEMON_AUTH_TOKEN", "configured-token");
        command.env("KIN_DAEMON_BIND_HOST", "0.0.0.0");
        command.env("PATH", "poison-path");

        scrub_daemon_process_authority(&mut command);

        for key in POISONED_AUTHORITY {
            let value = command
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new(key))
                .map(|(_, value)| value);
            assert_eq!(value, Some(None), "{key} was not removed");
        }
        let path = command
            .get_envs()
            .find(|(name, _)| *name == std::ffi::OsStr::new("PATH"))
            .and_then(|(_, value)| value);
        assert_ne!(path, Some(std::ffi::OsStr::new("poison-path")));
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == std::ffi::OsStr::new("KIN_VFS_DISABLE"))
                .and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("1"))
        );
        for (name, expected) in [
            ("KIN_DAEMON_AUTH_TOKEN", "configured-token"),
            ("KIN_DAEMON_BIND_HOST", "0.0.0.0"),
        ] {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == std::ffi::OsStr::new(name))
                    .and_then(|(_, value)| value),
                Some(std::ffi::OsStr::new(expected)),
                "{name} daemon configuration was not preserved"
            );
        }
    }

    #[test]
    fn daemon_log_tail_since_omits_stale_prior_run_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = daemon_log_path(dir.path());
        let stale = "ERROR 2026-06-09 embedding dimension mismatch: expected 384, got 768\n";
        std::fs::write(&path, stale).unwrap();
        let offset = daemon_log_len(dir.path());

        // No fresh output written by the failing attempt -> explicit message,
        // never the stale tail.
        let tail = daemon_log_tail_since(dir.path(), offset);
        assert!(
            tail.contains("no fresh daemon output captured"),
            "expected fresh-output notice, got: {tail}"
        );
        assert!(
            !tail.contains("384, got 768"),
            "stale prior-run line must not be surfaced: {tail}"
        );

        // Fresh output appended after the offset is the only thing surfaced.
        std::fs::write(
            &path,
            format!("{stale}ERROR 2026-06-16 incompatible graph schema version\n"),
        )
        .unwrap();
        let tail = daemon_log_tail_since(dir.path(), offset);
        assert!(
            tail.contains("incompatible graph schema version"),
            "fresh line must be surfaced: {tail}"
        );
        assert!(
            !tail.contains("384, got 768"),
            "stale prior-run line must not be surfaced even when fresh output exists: {tail}"
        );
    }

    // ── A busy daemon must never be treated as a dead one ─────────────────
    //
    // The deadlock chain started here. A daemon that did not answer readiness
    // inside a short fixed budget had its `daemon.pid` and `daemon.port`
    // deleted while it was still running and still holding the per-repo
    // singleton flock. The replacement daemon then lost that flock, and with
    // `daemon.pid` gone the lock reclaim had no owner evidence left, so every
    // later command repeated the same failure until the first daemon exited.
    // A timeout is evidence that a daemon is slow, never that it is dead.

    /// A loopback port with nothing listening: connections are refused
    /// immediately, so the probe exercises the unreachable-endpoint path
    /// without waiting on a real timeout.
    fn closed_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    fn write_endpoint_files(kin_root: &Path, pid: u32, port: u16) {
        std::fs::write(kin_root.join("daemon.pid"), pid.to_string()).unwrap();
        std::fs::write(kin_root.join("daemon.port"), port.to_string()).unwrap();
    }

    /// Model the merge-base supervisor publisher exactly: atomically replace
    /// each endpoint component without taking supervisor.lifecycle or
    /// supervisor.lock. Its parent CLI owns supervisor.start.lock.
    fn write_legacy_supervisor_endpoint_files(dir: &Path, pid: u32, port: u16) {
        let pid_tmp = dir.join(format!("{SUPERVISOR_PID_FILE}.tmp"));
        std::fs::write(&pid_tmp, pid.to_string()).unwrap();
        std::fs::rename(pid_tmp, dir.join(SUPERVISOR_PID_FILE)).unwrap();

        let port_tmp = dir.join(format!("{SUPERVISOR_PORT_FILE}.tmp"));
        std::fs::write(&port_tmp, port.to_string()).unwrap();
        std::fs::rename(port_tmp, dir.join(SUPERVISOR_PORT_FILE)).unwrap();
    }

    #[tokio::test]
    async fn unready_endpoint_with_a_live_owner_is_preserved_not_clobbered() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // The recorded owner is this test process, so it is provably alive —
        // exactly the daemon-still-loading shape.
        write_endpoint_files(root, std::process::id(), closed_loopback_port());

        let verdict = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(50),
            Duration::from_millis(150),
        )
        .await;

        assert!(
            matches!(verdict, ExistingDaemon::LiveNotReady(_)),
            "a live owner that has not answered must be reported, not replaced: {verdict:?}"
        );
        assert!(
            root.join("daemon.pid").exists(),
            "a live daemon's pid file must survive a readiness timeout"
        );
        assert!(
            root.join("daemon.port").exists(),
            "a live daemon's port file must survive a readiness timeout"
        );
    }

    #[tokio::test]
    async fn unready_endpoint_names_the_holder_and_refuses_to_replace_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let pid = std::process::id();
        write_endpoint_files(root, pid, closed_loopback_port());

        let ExistingDaemon::LiveNotReady(message) = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(50),
            Duration::from_millis(150),
        )
        .await
        else {
            panic!("a live-but-unready owner must produce a LiveNotReady verdict");
        };

        assert!(
            message.contains(&pid.to_string()),
            "the refusal must name the process that owns the repo: {message}"
        );
        assert!(
            message.contains("kin daemon stop"),
            "the refusal must tell the operator how to act: {message}"
        );
    }

    /// A daemon that answers `/readiness` but drops every `/health` connection.
    ///
    /// Stands in for a live daemon too busy to complete a second request.
    /// Returns its port and the task serving it.
    async fn daemon_answering_readiness_but_not_health(
        warming: bool,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 2048];
                let Ok(read) = socket.read(&mut buf).await else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                if request.contains("/readiness") {
                    let body = format!(r#"{{"ready":true,"warming":{warming}}}"#);
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 connection: close\r\ncontent-length: {}\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = socket.flush().await;
                }
                // Anything else (i.e. /health) gets no answer at all.
            }
        });
        (port, server)
    }

    fn serve_repo_daemon_health(
        listener: tokio::net::TcpListener,
        repo_root: &Path,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let repo_root = strict_canonical_path(repo_root).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 2048];
                let Ok(read) = socket.read(&mut buffer).await else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let body = if request.contains("/readiness") {
                    r#"{"ready":true,"warming":false}"#.to_string()
                } else if request.contains("/health") {
                    serde_json::json!({
                        "status": "ok",
                        "version": "test",
                        "uptime_seconds": 0,
                        "graph_entity_count": 0,
                        "graph_loaded": true,
                        "reconciliation_status": "idle",
                        "repo_root": repo_root,
                        "pid": std::process::id(),
                    })
                    .to_string()
                } else {
                    continue;
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     connection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        })
    }

    #[tokio::test]
    async fn a_health_probe_that_never_answers_is_not_evidence_against_the_daemon() {
        // Only an answer can identify a daemon, so only an answer can prove an
        // endpoint record wrong. A dropped health connection says nothing, and
        // treating it as proof would clobber the live daemon all over again.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (port, server) = daemon_answering_readiness_but_not_health(false).await;
        write_endpoint_files(root, std::process::id(), port);

        let verdict = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(50),
            Duration::from_millis(400),
        )
        .await;

        assert!(
            matches!(verdict, ExistingDaemon::LiveNotReady(_)),
            "an unanswered health probe must not condemn a live daemon: {verdict:?}"
        );
        assert!(
            root.join("daemon.pid").exists() && root.join("daemon.port").exists(),
            "endpoint files must survive an unanswered health probe"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_successful_readiness_body_retains_warming_when_health_drops() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (port, server) = daemon_answering_readiness_but_not_health(true).await;
        write_endpoint_files(root, std::process::id(), port);

        let ExistingDaemon::LiveNotReady(message) = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(50),
            Duration::from_millis(400),
        )
        .await
        else {
            panic!("a live warming daemon must remain LiveNotReady when health drops");
        };

        assert!(
            message.contains("warming"),
            "the successful readiness body's warming signal must survive a failed health probe: \
             {message}"
        );
        assert!(
            root.join("daemon.pid").exists() && root.join("daemon.port").exists(),
            "a warming daemon's endpoint files must be preserved"
        );
        server.abort();
    }

    // ── A verdict is about an endpoint, not about a path ──────────────────
    //
    // Every judgement is formed from a (pid, port) read at some earlier instant,
    // and the owner of the repo can change in between: the recorded daemon
    // exits, a successor takes the flock and republishes. Acting on the old
    // verdict then destroys the new daemon's files — the same failure, entered
    // through the evidence door instead of the timeout door. Waiting out a
    // warm-up makes that window long on purpose, so the delete has to re-check.

    #[cfg(unix)]
    #[tokio::test]
    async fn a_successor_endpoint_survives_a_verdict_about_its_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        // A real process, so "the recorded owner is gone" is established the way
        // production establishes it rather than mocked into place.
        let mut predecessor = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn predecessor process");
        write_endpoint_files(&root, predecessor.id(), closed_loopback_port());

        let successor_port = closed_loopback_port();
        let successor_root = root.clone();
        let handover = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            // The successor publishes its endpoint first...
            write_endpoint_files(&successor_root, std::process::id(), successor_port);
            // ...and only then does the predecessor actually go away. Reap it:
            // a zombie still answers kill(pid, 0) and would read as alive.
            let _ = predecessor.kill();
            let _ = predecessor.wait();
        });

        let verdict =
            wait_for_existing_daemon_within(&root, Duration::from_secs(2), Duration::from_secs(3))
                .await;
        handover.await.expect("handover task");

        assert!(
            matches!(verdict, ExistingDaemon::LiveNotReady(_)),
            "a changed successor must forbid replacement even when it has not served yet: \
             {verdict:?}"
        );
        assert_eq!(
            read_pid_file(&root),
            Some(std::process::id()),
            "the successor's pid file must survive a verdict about its predecessor: {verdict:?}"
        );
        assert_eq!(
            read_port_file(&root),
            Some(successor_port),
            "the successor's port file must survive a verdict about its predecessor"
        );
    }

    #[test]
    fn compare_and_delete_refuses_once_the_recorded_endpoint_moved() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Same owner, same port: the judgement still describes what is on disk.
        write_endpoint_files(root, 4242, 51000);
        assert_eq!(
            remove_daemon_files_if_unchanged(root, 4242, Some(51000)),
            DaemonEndpointRetirement::Retired
        );
        assert!(!root.join("daemon.pid").exists());

        // A different owner republished.
        write_endpoint_files(root, 4243, 51000);
        assert!(matches!(
            remove_daemon_files_if_unchanged(root, 4242, Some(51000)),
            DaemonEndpointRetirement::Changed { .. }
        ));
        assert!(root.join("daemon.pid").exists());

        // Same owner, but it rebound to a different port, so the endpoint the
        // verdict describes no longer exists either.
        write_endpoint_files(root, 4242, 51001);
        assert!(matches!(
            remove_daemon_files_if_unchanged(root, 4242, Some(51000)),
            DaemonEndpointRetirement::Changed { .. }
        ));
        assert!(root.join("daemon.port").exists());

        // A judgement formed before any port existed must not match a
        // same-PID endpoint that has since published one.
        assert!(matches!(
            remove_daemon_files_if_unchanged(root, 4242, None),
            DaemonEndpointRetirement::Changed { .. }
        ));
        assert!(root.join("daemon.port").exists());
    }

    #[tokio::test]
    async fn daemon_retirement_permission_denial_never_authorizes_replacement() {
        for denied_name in ["daemon.pid", "daemon.port"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            write_endpoint_files(root, 999_999_999, 51000);
            let judged = daemon_endpoint_snapshot(root);

            let decision = retire_daemon_endpoint_if_unchanged_with_hooks(
                root,
                judged,
                || {},
                |path| {
                    if path.file_name().and_then(|name| name.to_str()) == Some(denied_name) {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("injected denial for {denied_name}"),
                        ))
                    } else {
                        std::fs::remove_file(path)
                    }
                },
            );

            assert!(
                matches!(
                    &decision,
                    DaemonEndpointRetirement::CoordinationUnavailable(detail)
                        if detail.contains(denied_name)
                ),
                "a {denied_name} deletion error must fail closed: {decision:?}"
            );
            assert!(
                root.join(denied_name).exists(),
                "the injected failure must leave {denied_name} in place"
            );
            let removed_name = if denied_name == "daemon.pid" {
                "daemon.port"
            } else {
                "daemon.pid"
            };
            assert!(
                !root.join(removed_name).exists(),
                "retirement must attempt the second component even after a first-component error"
            );

            let verdict =
                follow_preserved_daemon_endpoint(root, Instant::now(), Duration::ZERO, decision)
                    .await;
            assert!(
                matches!(verdict, ExistingDaemon::LiveNotReady(_)),
                "a partial retirement must preserve startup authority, never authorize a \
                 replacement: {verdict:?}"
            );
        }
    }

    #[tokio::test]
    async fn supervisor_startup_authority_serializes_a_b_c_and_drop_never_unlinks() {
        let dir = tempfile::tempdir().unwrap();
        let mut launcher_a = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        assert!(
            !startup_lock_is_stale(launcher_a.path(), Duration::ZERO),
            "the permanent sentinel must keep immutable clients on their bounded deadline path"
        );

        let b_while_a =
            acquire_supervisor_startup_lock_in_dir_with_timeout(dir.path(), Duration::ZERO)
                .await
                .unwrap_err();
        assert!(
            b_while_a
                .to_string()
                .contains("timed out waiting for supervisor startup lock"),
            "B must not time-steal A while its exact kernel authority is held: {b_while_a:#}"
        );
        assert!(launcher_a.authorizes(dir.path()));
        assert!(launcher_a.heartbeat().unwrap());
        let namespace = launcher_a.path().to_path_buf();
        let generation_a = launcher_a.generation().to_string();
        drop(launcher_a);

        let launcher_b = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        assert_ne!(generation_a, launcher_b.generation());
        assert!(
            launcher_b.authorizes(dir.path()),
            "A's Drop only releases its kernel lock and cannot unlink B"
        );
        assert!(namespace.is_dir());

        let c_while_b =
            acquire_supervisor_startup_lock_in_dir_with_timeout(dir.path(), Duration::ZERO)
                .await
                .unwrap_err();
        assert!(
            c_while_b
                .to_string()
                .contains("timed out waiting for supervisor startup lock"),
            "C must not enter while B owns the authority: {c_while_b:#}"
        );
        assert!(launcher_b.authorizes(dir.path()));

        drop(launcher_b);
        let launcher_c = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        assert!(launcher_c.authorizes(dir.path()));
        drop(launcher_c);
        assert!(
            namespace.is_dir(),
            "no Drop edge removes the old-client-blocking directory sentinel"
        );
    }

    #[test]
    fn supervisor_adoption_ack_is_generation_process_and_inode_bound() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let generation = launcher.generation().to_string();
        let runtime = SupervisorRuntimeStartup {
            records: launcher.records.clone(),
            generation: generation.clone(),
            authority: launcher.file_identity.clone(),
            supervisor: current_process_identity().unwrap(),
        };
        runtime.acknowledge().unwrap();
        launcher.verify_adoption(std::process::id()).unwrap();

        let adoption_path = supervisor_adoption_record_path(&launcher.records, &generation);
        let replacement = SupervisorAdoptionRecord {
            schema: "kin.supervisor.adoption.v2".to_string(),
            protocol: SUPERVISOR_STARTUP_PROTOCOL,
            generation,
            supervisor: ProcessIdentity {
                birth_token: "reused-pid".to_string(),
                ..current_process_identity().unwrap()
            },
            authority: launcher.file_identity.clone(),
        };
        std::fs::remove_file(&adoption_path).unwrap();
        write_immutable_startup_record(&adoption_path, &replacement).unwrap();
        assert!(
            launcher.verify_adoption(std::process::id()).is_err(),
            "a replacement acknowledgement cannot inherit an earlier validation"
        );
    }

    #[test]
    #[serial_test::serial]
    fn runtime_reexec_requires_prior_adoption_and_survives_launcher_drop() {
        let prior = std::env::var_os(SUPERVISOR_STARTUP_GENERATION_ENV);

        let adopted_dir = tempfile::tempdir().unwrap();
        let adopted_launcher =
            try_acquire_supervisor_startup_lock_in_dir(adopted_dir.path()).unwrap();
        let adopted_generation = adopted_launcher.generation().to_string();
        std::env::set_var(SUPERVISOR_STARTUP_GENERATION_ENV, &adopted_generation);
        let first_runtime = validate_supervisor_runtime_startup(adopted_dir.path()).unwrap();
        first_runtime.acknowledge().unwrap();
        drop(adopted_launcher);

        let reexec_runtime = validate_supervisor_runtime_startup(adopted_dir.path()).unwrap();
        assert_eq!(reexec_runtime.generation, adopted_generation);
        assert_eq!(
            reexec_runtime.supervisor,
            current_process_identity().unwrap(),
            "an exec-preserved process incarnation may adopt its immutable acknowledgement"
        );

        let crashed_dir = tempfile::tempdir().unwrap();
        let crashed_launcher =
            try_acquire_supervisor_startup_lock_in_dir(crashed_dir.path()).unwrap();
        std::env::set_var(
            SUPERVISOR_STARTUP_GENERATION_ENV,
            crashed_launcher.generation(),
        );
        drop(crashed_launcher);
        let error = validate_supervisor_runtime_startup(crashed_dir.path()).unwrap_err();

        match prior {
            Some(value) => std::env::set_var(SUPERVISOR_STARTUP_GENERATION_ENV, value),
            None => std::env::remove_var(SUPERVISOR_STARTUP_GENERATION_ENV),
        }

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("launcher is not the live owner"),
            "a launcher crash before adoption must fail closed: {error}"
        );
    }

    #[tokio::test]
    async fn legacy_file_marker_is_rejected_and_never_reclaimed_by_pid_or_time() {
        for record in [
            format!("pid={} acquired_at=old\n", std::process::id()),
            "pid=999999999 acquired_at=old\n".to_string(),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(SUPERVISOR_STARTUP_FILE);
            std::fs::write(&path, &record).unwrap();
            assert!(startup_lock_is_stale(&path, Duration::ZERO));

            let error =
                acquire_supervisor_startup_lock_in_dir_with_timeout(dir.path(), Duration::ZERO)
                    .await
                    .unwrap_err();
            assert!(
                format!("{error:#}").contains("legacy supervisor launcher marker"),
                "unsupported legacy pairing must reject explicitly: {error:#}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record,
                "neither a dead-looking PID nor elapsed wall time authorizes unlink"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn runtime_rejects_immutable_legacy_launcher_before_singleton_or_endpoint_publish() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(SUPERVISOR_STARTUP_FILE);
        std::fs::write(
            &marker,
            format!("pid={} acquired_at=legacy\n", std::process::id()),
        )
        .unwrap();
        let prior = std::env::var_os(SUPERVISOR_STARTUP_GENERATION_ENV);
        std::env::remove_var(SUPERVISOR_STARTUP_GENERATION_ENV);
        let error = validate_supervisor_runtime_startup(dir.path()).unwrap_err();
        match prior {
            Some(value) => std::env::set_var(SUPERVISOR_STARTUP_GENERATION_ENV, value),
            None => std::env::remove_var(SUPERVISOR_STARTUP_GENERATION_ENV),
        }

        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            error.to_string().contains("legacy launcher marker"),
            "rejection must diagnose the immutable launcher pairing: {error}"
        );
        assert!(!dir.path().join(SUPERVISOR_SINGLETON_FILE).exists());
        assert!(!dir.path().join(SUPERVISOR_PID_FILE).exists());
        assert!(!dir.path().join(SUPERVISOR_PORT_FILE).exists());
        assert!(
            marker.is_file(),
            "the daemon must leave cleanup to the immutable launcher's own Drop"
        );
    }

    #[test]
    fn compat_handshake_rejects_base_daemon_without_adoption_ack() {
        let base: DaemonCompatResponse = serde_json::from_value(serde_json::json!({
            "schema": "kin.daemon.compat.v1",
            "graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,
        }))
        .unwrap();
        let error = validate_daemon_compat_response(&base).unwrap_err();
        assert!(
            error.contains("does not acknowledge supervisor startup protocol"),
            "old daemons must be rejected explicitly before spawn: {error}"
        );

        let current: DaemonCompatResponse = serde_json::from_value(serde_json::json!({
            "schema": "kin.daemon.compat.v2",
            "graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,
            "supervisor_startup_protocol": SUPERVISOR_STARTUP_PROTOCOL,
            "supervisor_startup_capabilities": [
                SUPERVISOR_STARTUP_CAPABILITY,
                SUPERVISOR_LEGACY_SENTINEL_CAPABILITY,
                SUPERVISOR_BOUNDED_ROLLBACK_CAPABILITY,
            ],
        }))
        .unwrap();
        validate_daemon_compat_response(&current).unwrap();
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn compat_probe_diagnostic_truncates_on_a_unicode_boundary() {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt as _;
            std::process::ExitStatus::from_raw(1 << 8)
        };
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt as _;
            std::process::ExitStatus::from_raw(1)
        };
        let output = std::process::Output {
            status,
            // "stdout=x" shifts the two-byte characters so the nominal
            // content cutoff lands inside one of them.
            stdout: format!("x{}", "é".repeat(300)).into_bytes(),
            stderr: Vec::new(),
        };

        let diagnostic = compact_probe_output(&output);
        assert!(diagnostic.is_char_boundary(diagnostic.len()));
        assert!(diagnostic.ends_with("..."));
        assert!(diagnostic.len() <= 400);
    }

    #[test]
    fn process_identity_rejects_pid_reuse_and_reboot_boundaries() {
        let first_boot = stable_boot_identity().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(
            stable_boot_identity().unwrap(),
            first_boot,
            "boot identity must be a kernel boot token, not wall-clock-minus-uptime"
        );

        let current = current_process_identity().unwrap();
        assert!(process_identity_is_current(&current).unwrap());

        let reused = ProcessIdentity {
            birth_token: format!("{}-reused", current.birth_token),
            ..current.clone()
        };
        assert!(!process_identity_is_current(&reused).unwrap());

        let rebooted = ProcessIdentity {
            boot_id: format!("{}-next-boot", current.boot_id),
            ..current
        };
        assert!(!process_identity_is_current(&rebooted).unwrap());
    }

    fn serve_supervisor_health(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 2048];
                let Ok(read) = socket.read(&mut buffer).await else {
                    continue;
                };
                if !String::from_utf8_lossy(&buffer[..read]).contains("/health") {
                    continue;
                }
                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     connection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        })
    }

    #[tokio::test]
    async fn supervisor_waiter_follows_staged_publication_without_stealing_authority() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.path().join(SUPERVISOR_SINGLETON_FILE))
            .unwrap();
        singleton.lock_exclusive().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let no_endpoint_fast_path = wait_for_existing_supervisor_in_dir(dir.path(), None).await;
        assert!(
            matches!(
                no_endpoint_fast_path,
                ExistingSupervisor::NeedsStartupAuthority
            ),
            "the public fast path must join startup authority before endpoint publication: \
             {no_endpoint_fast_path:?}"
        );
        let waiter_dir = dir.path().to_path_buf();
        let waiter = tokio::spawn(async move {
            acquire_supervisor_startup_lock_in_dir_with_timeout(&waiter_dir, Duration::from_secs(5))
                .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !waiter.is_finished(),
            "a waiter with no endpoint must remain behind the original startup generation"
        );

        std::fs::write(
            dir.path().join(SUPERVISOR_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let fast_path = wait_for_existing_supervisor_in_dir(dir.path(), None).await;
        assert!(
            matches!(fast_path, ExistingSupervisor::Starting(_)),
            "the public fast path must join PID-only publication: {fast_path:?}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !waiter.is_finished(),
            "PID-only publication must remain behind the original startup generation"
        );
        let port_tmp = dir.path().join(format!("{SUPERVISOR_PORT_FILE}.tmp"));
        std::fs::write(&port_tmp, port.to_string()).unwrap();
        std::fs::rename(port_tmp, dir.path().join(SUPERVISOR_PORT_FILE)).unwrap();
        let unready_fast_path = wait_for_existing_supervisor_in_dir(dir.path(), None).await;
        assert!(
            matches!(unready_fast_path, ExistingSupervisor::Starting(_)),
            "the public fast path must follow a complete endpoint until health is served: \
             {unready_fast_path:?}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !waiter.is_finished(),
            "a complete endpoint that has not served health must remain with its original owner"
        );
        let server = serve_supervisor_health(listener);
        let outcome = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .expect("waiter must follow repaired discovery promptly")
            .expect("waiter task")
            .expect("waiter result");
        assert!(
            matches!(
                outcome,
                SupervisorStartupAcquisition::Connected(ref url)
                    if url == &format!("http://127.0.0.1:{port}")
            ),
            "the waiter must connect instead of waiting for the launch lock: {outcome:?}"
        );
        assert!(
            launcher.authorizes(dir.path()),
            "following discovery must not steal startup authority"
        );
        assert!(
            dir.path().join(SUPERVISOR_SINGLETON_FILE).exists(),
            "following publication must not unlink lifetime authority"
        );
        drop(singleton);
        server.abort();
    }

    #[cfg(unix)]
    #[test]
    fn startup_namespace_and_authority_symlinks_fail_closed() {
        let state = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), state.path().join(SUPERVISOR_STARTUP_FILE))
            .unwrap();
        let namespace_error = try_acquire_supervisor_startup_lock_in_dir(state.path()).unwrap_err();
        assert_eq!(namespace_error.kind(), std::io::ErrorKind::PermissionDenied);

        let state = tempfile::tempdir().unwrap();
        let namespace = state.path().join(SUPERVISOR_STARTUP_FILE);
        std::fs::create_dir(&namespace).unwrap();
        let target_file = state.path().join("target.lock");
        std::fs::write(&target_file, "").unwrap();
        std::os::unix::fs::symlink(
            &target_file,
            namespace.join(SUPERVISOR_STARTUP_AUTHORITY_FILE),
        )
        .unwrap();
        assert!(
            try_acquire_supervisor_startup_lock_in_dir(state.path()).is_err(),
            "authority symlinks must never become lock authority"
        );
    }

    #[test]
    fn legacy_supervisor_publisher_is_excluded_after_final_retirement_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let startup_authority = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        write_legacy_supervisor_endpoint_files(dir.path(), 999_999_999, 51000);
        let judged = supervisor_endpoint_snapshot(dir.path());
        let mut legacy_publication_was_excluded = false;

        let decision = retire_supervisor_endpoint_if_unchanged_with_hooks(
            dir.path(),
            judged,
            &startup_authority,
            || match try_acquire_supervisor_startup_lock_in_dir(dir.path()) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    legacy_publication_was_excluded = true;
                }
                Err(error) => panic!("legacy startup authority probe failed: {error}"),
                Ok(_legacy_authority) => {
                    write_legacy_supervisor_endpoint_files(dir.path(), std::process::id(), 51001);
                    panic!("a legacy launcher acquired startup authority during retirement");
                }
            },
            |path| std::fs::remove_file(path),
        );

        assert!(legacy_publication_was_excluded);
        assert_eq!(decision, SupervisorEndpointRetirement::Retired);
        assert!(!dir.path().join(SUPERVISOR_PID_FILE).exists());
        assert!(!dir.path().join(SUPERVISOR_PORT_FILE).exists());
        assert!(
            dir.path().join(SUPERVISOR_STARTUP_FILE).exists(),
            "startup authority must remain held after retirement for the caller's spawn decision"
        );
    }

    #[tokio::test]
    async fn legacy_supervisor_publication_during_probe_is_followed_and_forbids_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_startup_authority =
            try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let legacy_port = closed_loopback_port();

        let initial = wait_for_existing_supervisor_in_dir_with_hook(dir.path(), None, || {
            // The merge-base supervisor itself writes without either new lock.
            // Its merge-base parent CLI still owns supervisor.start.lock.
            write_legacy_supervisor_endpoint_files(dir.path(), std::process::id(), legacy_port);
        })
        .await;

        assert!(
            matches!(initial, ExistingSupervisor::NeedsStartupAuthority),
            "a read-only pre-lock probe must defer stale retirement: {initial:?}"
        );
        assert_eq!(
            supervisor_endpoint_snapshot(dir.path()),
            SupervisorEndpointSnapshot {
                pid: Some(std::process::id()),
                port: Some(legacy_port),
                pid_exists: true,
                port_exists: true,
            },
            "the post-snapshot legacy publication must survive the read-only probe"
        );

        drop(legacy_startup_authority);
        let current_startup_authority =
            try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let final_decision =
            wait_for_existing_supervisor_in_dir(dir.path(), Some(&current_startup_authority)).await;

        assert!(
            matches!(final_decision, ExistingSupervisor::Starting(_)),
            "the final serialized check must follow/preserve the live legacy owner and forbid a \
             second spawn: {final_decision:?}"
        );
        assert_eq!(
            supervisor_endpoint_snapshot(dir.path()).pid,
            Some(std::process::id())
        );
        assert_eq!(
            supervisor_endpoint_snapshot(dir.path()).port,
            Some(legacy_port)
        );
    }

    #[test]
    fn supervisor_retirement_permission_denial_never_authorizes_replacement() {
        for denied_name in [SUPERVISOR_PID_FILE, SUPERVISOR_PORT_FILE] {
            let dir = tempfile::tempdir().unwrap();
            let startup_authority = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
            std::fs::write(dir.path().join(SUPERVISOR_PID_FILE), "999999999").unwrap();
            std::fs::write(dir.path().join(SUPERVISOR_PORT_FILE), "51000").unwrap();
            let judged = supervisor_endpoint_snapshot(dir.path());

            let decision = retire_supervisor_endpoint_if_unchanged_with_hooks(
                dir.path(),
                judged,
                &startup_authority,
                || {},
                |path| {
                    if path.file_name().and_then(|name| name.to_str()) == Some(denied_name) {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("injected denial for {denied_name}"),
                        ))
                    } else {
                        std::fs::remove_file(path)
                    }
                },
            );

            assert!(
                matches!(
                    &decision,
                    SupervisorEndpointRetirement::CoordinationUnavailable(detail)
                        if detail.contains(denied_name)
                ),
                "a {denied_name} deletion error must fail closed, not authorize a supervisor \
                 replacement: {decision:?}"
            );
            assert!(
                dir.path().join(denied_name).exists(),
                "the injected failure must leave {denied_name} in place"
            );
            let removed_name = if denied_name == SUPERVISOR_PID_FILE {
                SUPERVISOR_PORT_FILE
            } else {
                SUPERVISOR_PID_FILE
            };
            assert!(
                !dir.path().join(removed_name).exists(),
                "retirement must attempt the second component even after a first-component error"
            );
        }
    }

    #[test]
    fn retirement_treats_not_found_as_success_only_when_components_are_absent() {
        let daemon_dir = tempfile::tempdir().unwrap();
        let daemon_judged = daemon_endpoint_snapshot(daemon_dir.path());
        assert_eq!(
            retire_daemon_endpoint_if_unchanged_with_hooks(
                daemon_dir.path(),
                daemon_judged,
                || {},
                |_| Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            ),
            DaemonEndpointRetirement::Retired
        );

        let supervisor_dir = tempfile::tempdir().unwrap();
        let supervisor_startup_authority =
            try_acquire_supervisor_startup_lock_in_dir(supervisor_dir.path()).unwrap();
        let supervisor_judged = supervisor_endpoint_snapshot(supervisor_dir.path());
        assert_eq!(
            retire_supervisor_endpoint_if_unchanged_with_hooks(
                supervisor_dir.path(),
                supervisor_judged,
                &supervisor_startup_authority,
                || {},
                |_| Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            ),
            SupervisorEndpointRetirement::Retired
        );

        let remaining_dir = tempfile::tempdir().unwrap();
        write_endpoint_files(remaining_dir.path(), 999_999_999, 51000);
        let remaining_judged = daemon_endpoint_snapshot(remaining_dir.path());
        let decision = retire_daemon_endpoint_if_unchanged_with_hooks(
            remaining_dir.path(),
            remaining_judged,
            || {},
            |_| Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        );
        assert!(
            matches!(
                decision,
                DaemonEndpointRetirement::CoordinationUnavailable(_)
            ),
            "`NotFound` cannot authorize replacement when post-removal verification still sees \
             endpoint components"
        );
        assert!(remaining_dir.path().join("daemon.pid").exists());
        assert!(remaining_dir.path().join("daemon.port").exists());
    }

    #[test]
    fn generic_stale_cleanup_preserves_a_live_successor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, std::process::id(), 51000);

        remove_stale_daemon_files(root);

        assert_eq!(read_pid_file(root), Some(std::process::id()));
        assert_eq!(read_port_file(root), Some(51000));
    }

    #[test]
    fn orphan_port_cleanup_requires_an_absent_pid_record() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.pid"), "indeterminate").unwrap();
        std::fs::write(root.join("daemon.port"), "51000").unwrap();

        assert!(!remove_orphaned_daemon_port(root));
        assert!(root.join("daemon.pid").exists());
        assert!(root.join("daemon.port").exists());

        std::fs::remove_file(root.join("daemon.pid")).unwrap();
        assert!(remove_orphaned_daemon_port(root));
        assert!(!root.join("daemon.port").exists());
    }

    #[test]
    fn successor_publication_after_final_comparison_is_serialized() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        write_endpoint_files(&root, 4242, 51000);

        let (comparison_tx, comparison_rx) = mpsc::channel();
        let (publication_started_tx, publication_started_rx) = mpsc::channel();
        let successor_root = root.clone();
        let successor = std::thread::spawn(move || {
            comparison_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("retirement must reach the final comparison");
            publication_started_tx.send(()).unwrap();
            let authority = loop {
                match try_acquire_daemon_endpoint_authority(&successor_root) {
                    Ok(authority) => break authority,
                    Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("successor publication authority: {error}"),
                }
            };
            write_endpoint_files(&successor_root, 4243, 51001);
            drop(authority);
        });

        assert_eq!(
            remove_daemon_files_if_unchanged_with_hook(&root, 4242, Some(51000), || {
                comparison_tx.send(()).unwrap();
                publication_started_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("successor must attempt publication after comparison");
            }),
            DaemonEndpointRetirement::Retired
        );
        successor.join().expect("successor publisher");

        assert_eq!(read_pid_file(&root), Some(4243));
        assert_eq!(read_port_file(&root), Some(51001));
    }

    #[test]
    fn legacy_singleton_publisher_after_comparison_is_preserved() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        write_endpoint_files(&root, 4242, 51000);

        let (comparison_tx, comparison_rx) = mpsc::channel();
        let (published_tx, published_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let legacy_root = root.clone();
        let legacy = std::thread::spawn(move || {
            comparison_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("retirement must reach its endpoint comparison");
            let singleton = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(legacy_root.join("daemon.lock"))
                .unwrap();
            singleton.lock_exclusive().unwrap();
            // Model a compatible old publisher: it owns daemon.lock and writes
            // endpoint files without participating in daemon.lifecycle.
            write_endpoint_files(&legacy_root, 4243, 51001);
            published_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("test must retain the legacy lifetime lock");
        });

        let decision = remove_daemon_files_if_unchanged_with_hook(&root, 4242, Some(51000), || {
            comparison_tx.send(()).unwrap();
            published_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("legacy publisher must acquire and publish");
        });

        assert_eq!(decision, DaemonEndpointRetirement::SingletonHeld);
        assert_eq!(read_pid_file(&root), Some(4243));
        assert_eq!(read_port_file(&root), Some(51001));
        assert!(
            root.join("daemon.lock").exists(),
            "endpoint retirement must never unlink the singleton pathname"
        );

        release_tx.send(()).unwrap();
        legacy.join().expect("legacy publisher");
    }

    #[tokio::test]
    async fn contended_retirement_never_becomes_start_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 999_999_999, closed_loopback_port());
        let lifecycle = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("daemon.lifecycle"))
            .unwrap();
        lifecycle.lock_exclusive().unwrap();

        let verdict = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(20),
            Duration::from_millis(50),
        )
        .await;

        assert!(
            matches!(verdict, ExistingDaemon::LiveNotReady(_)),
            "coordination contention must fail closed rather than authorize a spawn: {verdict:?}"
        );
        assert!(root.join("daemon.pid").exists());
        assert!(root.join("daemon.port").exists());
    }

    #[tokio::test]
    async fn unpublished_daemon_singleton_owner_forbids_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.path().join("daemon.lock"))
            .unwrap();
        singleton.lock_exclusive().unwrap();

        let verdict = wait_for_existing_daemon_within(
            dir.path(),
            Duration::from_millis(20),
            Duration::from_millis(50),
        )
        .await;

        assert!(
            matches!(verdict, ExistingDaemon::LiveNotReady(_)),
            "a process-lifetime singleton owner must forbid a loser spawn even before endpoint \
             publication: {verdict:?}"
        );
        assert!(dir.path().join("daemon.lock").exists());
    }

    #[tokio::test]
    async fn daemon_waiter_follows_no_endpoint_pid_only_and_unready_publication() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().join(".kin");
        std::fs::create_dir(&root).unwrap();
        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("daemon.lock"))
            .unwrap();
        singleton.lock_exclusive().unwrap();

        // Bind the final port without serving it yet. This gives the waiter a
        // deterministic complete-but-not-yet-serving publication slice after
        // the preceding no-endpoint and PID-only slices.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiter_root = root.clone();
        let waiter = tokio::spawn(async move {
            wait_for_existing_daemon_within(
                &waiter_root,
                Duration::from_millis(20),
                Duration::from_secs(3),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "a held singleton with no endpoint must be followed, not rejected"
        );
        std::fs::write(root.join("daemon.pid"), std::process::id().to_string()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "PID-only publication must be followed, not rejected"
        );
        std::fs::write(root.join("daemon.port"), port.to_string()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiter.is_finished(),
            "a complete endpoint that has not served yet must remain owned"
        );

        let server = serve_repo_daemon_health(listener, repo.path());
        let outcome = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must follow endpoint publication")
            .expect("waiter task");
        assert!(
            matches!(
                outcome,
                ExistingDaemon::Connected(ref url)
                    if url == &format!("http://127.0.0.1:{port}")
            ),
            "the waiter must connect to the original serialized owner: {outcome:?}"
        );
        assert_eq!(read_pid_file(&root), Some(std::process::id()));
        assert_eq!(read_port_file(&root), Some(port));
        assert!(
            root.join("daemon.lock").exists(),
            "following publication must not unlink lifetime authority"
        );
        drop(singleton);
        server.abort();
    }

    #[tokio::test]
    async fn live_supervisor_health_failure_preserves_lifetime_owner_and_forbids_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let startup_authority = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.path().join(SUPERVISOR_SINGLETON_FILE))
            .unwrap();
        singleton.lock_exclusive().unwrap();
        let port = closed_loopback_port();
        std::fs::write(
            dir.path().join(SUPERVISOR_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(dir.path().join(SUPERVISOR_PORT_FILE), port.to_string()).unwrap();

        let verdict = wait_for_existing_supervisor_in_dir(dir.path(), None).await;
        assert!(
            matches!(verdict, ExistingSupervisor::Starting(_)),
            "a health hiccup from a live owner must forbid spawning: {verdict:?}"
        );
        assert!(dir.path().join(SUPERVISOR_PID_FILE).exists());
        assert!(dir.path().join(SUPERVISOR_PORT_FILE).exists());
        assert_eq!(
            retire_supervisor_endpoint_if_unchanged(
                dir.path(),
                supervisor_endpoint_snapshot(dir.path()),
                &startup_authority,
            ),
            SupervisorEndpointRetirement::SingletonHeld,
            "the process-lifetime singleton must independently prevent retirement"
        );
        assert!(
            dir.path().join(SUPERVISOR_SINGLETON_FILE).exists(),
            "the supervisor singleton pathname is never unlinked"
        );

        std::fs::remove_file(dir.path().join(SUPERVISOR_PID_FILE)).unwrap();
        std::fs::remove_file(dir.path().join(SUPERVISOR_PORT_FILE)).unwrap();
        let unpublished_owner =
            wait_for_existing_supervisor_in_dir(dir.path(), Some(&startup_authority)).await;
        assert!(
            matches!(unpublished_owner, ExistingSupervisor::Starting(_)),
            "a supervisor holding its lifetime singleton before publication must still forbid a \
             second spawn: {unpublished_owner:?}"
        );
    }

    #[tokio::test]
    async fn dead_owner_endpoint_is_cleared_so_a_replacement_can_start() {
        // The other side of the rule: a recorded owner that is provably gone is
        // positive evidence, so the record is cleared and a start proceeds.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 999_999_999, closed_loopback_port());

        let verdict = wait_for_existing_daemon_within(
            root,
            Duration::from_millis(50),
            Duration::from_millis(150),
        )
        .await;

        assert!(
            matches!(verdict, ExistingDaemon::None),
            "a dead owner must not block a fresh start: {verdict:?}"
        );
        assert!(!root.join("daemon.pid").exists());
        assert!(!root.join("daemon.port").exists());
    }

    // ── Only a proven different repo is grounds for destruction ───────────
    //
    // "The daemon answered and named a different repo" is one of exactly two
    // affirmative grounds for deleting a live daemon's endpoint. A rendered-path
    // comparison is not that: two spellings of one directory are an aliasing
    // artifact, and a path that will not resolve is no information at all.

    fn health_naming(
        repo_id: Option<&str>,
        workspace_id: Option<&str>,
        repo_root: Option<String>,
    ) -> HealthResponse {
        HealthResponse {
            status: "ok".to_string(),
            version: "test".to_string(),
            uptime_seconds: 0,
            graph_entity_count: Some(0),
            graph_loaded: false,
            reconciliation_status: "idle".to_string(),
            repo_id: repo_id.map(str::to_string),
            workspace_id: workspace_id.map(str::to_string),
            repo_root,
            pid: Some(std::process::id()),
            behavior_env: Default::default(),
            build: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_aliased_path_to_the_same_directory_is_not_a_different_repo() {
        // macOS reports /tmp as /private/tmp and this fleet runs lane worktrees
        // behind symlinks, so the daemon's resolved root and the client's
        // unresolved one routinely disagree as strings while naming one
        // directory. Reading that as a different repository deletes the live
        // daemon serving it.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("repo");
        std::fs::create_dir_all(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        // The daemon reports the resolved path; the client holds the alias.
        let health = health_naming(None, None, Some(strict_canonical_path(&real).unwrap()));
        assert_eq!(
            classify_health_repo(&health, &alias.join(".kin"), &alias),
            RepoIdentity::Matches,
            "two spellings of one directory must not read as two repositories"
        );
    }

    #[test]
    fn a_daemon_that_names_no_identity_is_indeterminate_not_a_match() {
        // Fail-open was the old behavior: an absent repo_root skipped the check
        // entirely and any daemon passed identity validation.
        let dir = tempfile::tempdir().unwrap();
        let health = health_naming(None, None, None);
        assert!(
            matches!(
                classify_health_repo(&health, &dir.path().join(".kin"), dir.path()),
                RepoIdentity::Indeterminate(_)
            ),
            "silence about identity is not proof of identity"
        );
    }

    #[test]
    fn an_unresolvable_repo_root_is_indeterminate_not_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let health = health_naming(None, None, Some("/nonexistent/kin/repo/path".to_string()));
        assert!(
            matches!(
                classify_health_repo(&health, &dir.path().join(".kin"), dir.path()),
                RepoIdentity::Indeterminate(_)
            ),
            "a path that will not resolve proves nothing about which repo is served"
        );
    }

    #[test]
    fn a_resolvable_different_directory_is_a_real_mismatch() {
        // The rule must still fire where it should: both sides resolve, and they
        // genuinely name different directories.
        let mine = tempfile::tempdir().unwrap();
        let theirs = tempfile::tempdir().unwrap();
        let health = health_naming(
            None,
            None,
            Some(strict_canonical_path(theirs.path()).unwrap()),
        );
        assert!(
            matches!(
                classify_health_repo(&health, &mine.path().join(".kin"), mine.path()),
                RepoIdentity::Rejected(_)
            ),
            "a daemon serving a different directory is real evidence"
        );
    }

    #[test]
    fn workspace_identity_decides_local_authority_within_a_repository() {
        // Repository identity proves shared history, not local endpoint
        // authority. Two clones carry the same repo id and different workspace
        // ids, so only the pair can decide before paths.
        let dir = tempfile::tempdir().unwrap();
        let kin_root = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_root).unwrap();
        std::fs::write(
            kin_root.join("manifest.json"),
            serde_json::json!({
                "kin_version": "test",
                "repo_id": "11111111-1111-4111-8111-111111111111",
                "workspace_id": "22222222-2222-4222-8222-222222222222",
                "created_at": "2026-01-01T00:00:00Z",
            })
            .to_string(),
        )
        .unwrap();

        // Same repo and workspace, even though repo_root would fail a path
        // comparison.
        let same = health_naming(
            Some("11111111-1111-4111-8111-111111111111"),
            Some("22222222-2222-4222-8222-222222222222"),
            Some("/some/other/spelling".to_string()),
        );
        assert_eq!(
            classify_health_repo(&same, &kin_root, dir.path()),
            RepoIdentity::Matches
        );

        // Same repository but a different workspace must be rejected even
        // when the path would otherwise pass.
        let other_workspace = health_naming(
            Some("11111111-1111-4111-8111-111111111111"),
            Some("33333333-3333-4333-8333-333333333333"),
            Some(strict_canonical_path(dir.path()).unwrap()),
        );
        assert!(matches!(
            classify_health_repo(&other_workspace, &kin_root, dir.path()),
            RepoIdentity::Rejected(ref reason) if reason.contains("workspace mismatch")
        ));

        // Different repository remains conclusive even if workspace and path
        // are made to look local.
        let other_repo = health_naming(
            Some("33333333-3333-4333-8333-333333333333"),
            Some("22222222-2222-4222-8222-222222222222"),
            Some(strict_canonical_path(dir.path()).unwrap()),
        );
        assert!(matches!(
            classify_health_repo(&other_repo, &kin_root, dir.path()),
            RepoIdentity::Rejected(ref reason) if reason.contains("repo mismatch")
        ));

        // An old daemon with no workspace id gets only the legacy path
        // fallback. Matching repo ids do not bypass a proven path mismatch.
        let other_dir = tempfile::tempdir().unwrap();
        let old_daemon = health_naming(
            Some("11111111-1111-4111-8111-111111111111"),
            None,
            Some(strict_canonical_path(other_dir.path()).unwrap()),
        );
        assert!(matches!(
            classify_health_repo(&old_daemon, &kin_root, dir.path()),
            RepoIdentity::Rejected(ref reason) if reason.contains("repo mismatch")
        ));
    }

    #[test]
    fn a_non_serving_status_is_still_a_real_answer() {
        let dir = tempfile::tempdir().unwrap();
        let mut health =
            health_naming(None, None, Some(strict_canonical_path(dir.path()).unwrap()));
        health.status = "starting".to_string();
        assert!(matches!(
            classify_health_repo(&health, &dir.path().join(".kin"), dir.path()),
            RepoIdentity::Rejected(_)
        ));
    }

    #[test]
    fn not_ready_message_distinguishes_warming_from_silent() {
        let warming = live_daemon_not_ready_message(4242, 51000, "HTTP 503", true, 300);
        assert!(
            warming.contains("warming"),
            "a daemon that reported warming must be described as warming: {warming}"
        );
        let silent = live_daemon_not_ready_message(4242, 51000, "connection refused", false, 300);
        assert!(
            silent.contains("has not reported readiness"),
            "a silent daemon must not be described as warming: {silent}"
        );
        for message in [&warming, &silent] {
            assert!(message.contains("4242"), "must name the pid: {message}");
            assert!(message.contains("51000"), "must name the port: {message}");
            assert!(
                message.contains("will not replace it"),
                "must state that kin refuses to replace a running daemon: {message}"
            );
        }
    }

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
    fn process_liveness_recognizes_the_current_process() {
        assert!(
            is_process_alive(std::process::id()),
            "the current process must be observable as alive"
        );
        assert_eq!(process_liveness(std::process::id()), ProcessLiveness::Alive);
    }

    #[test]
    fn indeterminate_liveness_never_retires_an_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let endpoint = live_daemon_endpoint_with_probe(root, |_| ProcessLiveness::Unknown)
            .expect("unknown liveness must preserve possible ownership");

        assert_eq!(endpoint.pid, 4242);
        assert_eq!(endpoint.port, 51000);
        assert!(root.join("daemon.pid").exists());
        assert!(root.join("daemon.port").exists());
    }

    #[test]
    fn dead_verdict_cannot_bind_to_a_same_pid_successor_port() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let endpoint = live_daemon_endpoint_with_probe(root, |_| {
            // Model PID reuse: the predecessor was judged by its original
            // (pid, port), then a successor with the same numeric PID published
            // a new endpoint generation before conditional retirement.
            write_endpoint_files(root, 4242, 51001);
            ProcessLiveness::Dead
        });

        assert_eq!(
            endpoint,
            Some(LiveDaemonEndpoint {
                pid: 4242,
                port: 51001,
            }),
            "a changed generation must be returned for follow-up, never collapsed into absence"
        );
        assert_eq!(read_pid_file(root), Some(4242));
        assert_eq!(read_port_file(root), Some(51001));
    }

    #[cfg(windows)]
    #[test]
    fn windows_startup_file_identity_uses_the_exact_open_handle() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first.lock");
        let second_path = dir.path().join("second.lock");
        std::fs::write(&first_path, "").unwrap();
        std::fs::write(&second_path, "").unwrap();
        let first = open_startup_regular_file(&first_path, false, false, false).unwrap();
        let first_reopened = open_startup_regular_file(&first_path, false, false, false).unwrap();
        let second = open_startup_regular_file(&second_path, false, false, false).unwrap();

        assert_eq!(
            startup_file_identity(&first).unwrap(),
            startup_file_identity(&first_reopened).unwrap(),
            "two handles to the same startup authority must report one identity"
        );
        assert_ne!(
            startup_file_identity(&first).unwrap(),
            startup_file_identity(&second).unwrap(),
            "distinct startup authority files must not alias"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_handle_can_preserve_bounded_rollback_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let namespace = ensure_supervisor_startup_namespace(dir.path()).unwrap();
        assert_eq!(
            startup_file_identity(&namespace.sentinel_file).unwrap(),
            namespace.sentinel_identity
        );
        assert!(
            namespace
                .sentinel_file
                .metadata()
                .unwrap()
                .modified()
                .unwrap()
                .elapsed()
                .is_err(),
            "the exact Windows directory handle must retain a future mtime"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_process_liveness_rejects_a_missing_process() {
        assert!(
            !is_process_alive(u32::MAX),
            "an unopenable Windows process id must not wedge daemon ownership forever"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_access_denied_and_query_failure_are_indeterminate() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, STILL_ACTIVE,
        };

        assert_eq!(
            classify_windows_process_probe(false, ERROR_INVALID_PARAMETER, false, 0),
            ProcessLiveness::Dead
        );
        assert_eq!(
            classify_windows_process_probe(false, ERROR_ACCESS_DENIED, false, 0),
            ProcessLiveness::Unknown
        );
        assert_eq!(
            classify_windows_process_probe(true, 0, false, 0),
            ProcessLiveness::Unknown
        );
        assert_eq!(
            classify_windows_process_probe(true, 0, true, STILL_ACTIVE as u32),
            ProcessLiveness::Alive
        );
        assert_eq!(
            classify_windows_process_probe(true, 0, true, 0),
            ProcessLiveness::Dead
        );
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
            workspace_id: None,
            repo_root: Some(canonical_path_string(other.path())),
            pid: Some(std::process::id()),
            behavior_env: Default::default(),
            build: None,
        };

        let error = validate_health_repo(&health, dir.path()).unwrap_err();
        assert!(error.to_string().contains("daemon repo mismatch"));
    }

    fn health_for(status: &str, repo_root: &Path) -> HealthResponse {
        HealthResponse {
            status: status.to_string(),
            version: "test".to_string(),
            uptime_seconds: 0,
            graph_entity_count: Some(0),
            graph_loaded: false,
            reconciliation_status: "idle".to_string(),
            repo_id: Some("repo".to_string()),
            workspace_id: None,
            repo_root: Some(canonical_path_string(repo_root)),
            pid: Some(std::process::id()),
            behavior_env: Default::default(),
            build: None,
        }
    }

    #[test]
    fn serving_status_predicate_accepts_ok_and_attention_only() {
        assert!(health_status_is_serving("ok"));
        assert!(health_status_is_serving("attention"));
        assert!(!health_status_is_serving("starting"));
        assert!(!health_status_is_serving("error"));
        assert!(!health_status_is_serving(""));
    }

    #[test]
    fn health_validation_accepts_attention_for_matching_repo() {
        // A degraded-but-serving daemon (embed_worker_failed / mass_deletion_blocked
        // -> status "attention") is a valid endpoint, not a dead one. Accepting it
        // is what breaks the spawn->reject->clear hang: the caller keeps the daemon
        // instead of wiping its endpoint files and respawning.
        let dir = tempfile::tempdir().unwrap();
        let health = health_for("attention", dir.path());
        validate_health_repo(&health, dir.path())
            .expect("attention daemon for the right repo must validate as serving");
    }

    #[test]
    fn health_validation_rejects_attention_for_wrong_repo() {
        // Attention means alive+serving, but a repo mismatch is still invalid — an
        // attention status must not bypass the repo-root guard.
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let health = health_for("attention", other.path());
        let error = validate_health_repo(&health, dir.path()).unwrap_err();
        assert!(error.to_string().contains("daemon repo mismatch"));
    }

    #[test]
    fn health_validation_rejects_unknown_status() {
        // Any status that is neither "ok" nor "attention" is treated as a genuinely
        // invalid endpoint and rejected (so truly broken daemons are still cleared).
        let dir = tempfile::tempdir().unwrap();
        let health = health_for("error", dir.path());
        let error = validate_health_repo(&health, dir.path()).unwrap_err();
        assert!(error.to_string().contains("daemon health status is error"));
    }

    #[test]
    fn build_mismatch_warns_without_strict_mode() {
        let warning = build_match_error("bd7cd12", "a09f882", false)
            .unwrap()
            .expect("mismatch should warn");

        assert_eq!(
            warning,
            "Kin build mismatch: CLI bd7cd12 / daemon a09f882 - restart the daemon to match"
        );
    }

    #[test]
    fn build_mismatch_errors_in_strict_mode() {
        let err = build_match_error("bd7cd12", "a09f882", true).unwrap_err();

        assert!(err.to_string().contains("restart the daemon to match"));
    }

    fn one_divergence() -> Vec<kin_core::behavior_env::Divergence> {
        vec![kin_core::behavior_env::Divergence {
            var: "KIN_EMBED_HYBRID".to_string(),
            cli: Some("balanced".to_string()),
            daemon: None,
        }]
    }

    #[test]
    fn behavior_env_no_divergence_is_ok_in_either_mode() {
        assert!(report_behavior_env_divergence(&[], false).is_ok());
        assert!(report_behavior_env_divergence(&[], true).is_ok());
    }

    #[test]
    fn behavior_env_divergence_warns_without_strict_mode() {
        // Non-strict: surfaced as a warning; the command is allowed to continue.
        assert!(report_behavior_env_divergence(&one_divergence(), false).is_ok());
    }

    #[test]
    fn behavior_env_divergence_errors_in_strict_mode() {
        let err = report_behavior_env_divergence(&one_divergence(), true).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("KIN_EMBED_HYBRID"));
        assert!(text.contains("restart the daemon"));
    }

    #[test]
    fn behavior_env_message_names_each_var_and_remedy() {
        let divergences = vec![
            kin_core::behavior_env::Divergence {
                var: "KIN_EMBED_HYBRID".to_string(),
                cli: Some("balanced".to_string()),
                daemon: None,
            },
            kin_core::behavior_env::Divergence {
                var: "KIN_RESOURCE_PROFILE".to_string(),
                cli: None,
                daemon: Some("throughput".to_string()),
            },
        ];
        let message = behavior_env_divergence_message(&divergences);
        // Each diverging var names both sides' values...
        assert!(message.contains("KIN_EMBED_HYBRID: cli=\"balanced\" daemon=(unset)"));
        assert!(message.contains("KIN_RESOURCE_PROFILE: cli=(unset) daemon=\"throughput\""));
        // ...and the message states the accurate remedy and the strict escalation.
        // The remedy now names the supported `kin daemon stop` command and keeps
        // the raw kill as a fallback.
        assert!(message.contains("kin daemon stop"));
        assert!(message.contains(".kin/daemon.pid"));
        assert!(message.contains("KIN_STRICT_BEHAVIOR_ENV=1"));
    }

    #[test]
    fn health_without_behavior_env_defaults_empty() {
        // A daemon that predates the behavior_env field must still deserialize,
        // with an empty surface, so an old daemon yields no divergence warnings.
        let json = r#"{
            "status":"ok","version":"0.0.0","uptime_seconds":1,
            "graph_entity_count":10,"graph_loaded":true,
            "reconciliation_status":"idle"
        }"#;
        let health: HealthResponse = serde_json::from_str(json).unwrap();
        assert!(health.behavior_env.is_empty());
    }

    #[test]
    fn health_with_behavior_env_deserializes_surface() {
        let json = r#"{
            "status":"ok","version":"0.0.0","uptime_seconds":1,
            "graph_entity_count":10,"graph_loaded":true,
            "reconciliation_status":"idle",
            "behavior_env":{"KIN_EMBED_HYBRID":"balanced","KIN_RESOURCE_PROFILE":null}
        }"#;
        let health: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            health.behavior_env.get("KIN_EMBED_HYBRID"),
            Some(&Some("balanced".to_string()))
        );
        assert_eq!(health.behavior_env.get("KIN_RESOURCE_PROFILE"), Some(&None));
    }

    #[test]
    fn build_id_preserves_dirty_suffix() {
        assert_eq!(build_id("bd7cd12", true).as_deref(), Some("bd7cd12-dirty"));
        assert_eq!(build_id("unknown", true), None);
    }

    #[test]
    fn startup_lock_staleness_uses_modified_time() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("daemon.start.lock");
        std::fs::write(&lock, "pid=1").unwrap();

        assert!(startup_lock_is_stale(&lock, Duration::ZERO));
        assert!(!startup_lock_is_stale(&lock, Duration::from_secs(60)));
    }

    // ── startup deadline is patience, not a death sentence ─────────────────
    //
    // The ready-wait used to SIGKILL its child the moment the deadline passed,
    // with no check that anything was wrong with it. A daemon loading a large
    // graph was killed for being slow, and its replacement started cold and hit
    // the same deadline.

    // Both drive a real child process and need the POSIX stand-in binaries.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_still_running_at_the_deadline_is_not_killed() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a long-lived stand-in for a slow daemon");

        let disposition = kin_daemon_spawn::startup_disposition(&mut child)
            .expect("a child we spawned is observable");
        assert_eq!(disposition, kin_daemon_spawn::StartupDisposition::Alive);
        assert!(
            !kin_daemon_spawn::terminate_if_proven_dead(&mut child, &disposition),
            "a live daemon must survive its caller's deadline"
        );
        assert!(
            child.try_wait().expect("still observable").is_none(),
            "the child must still be running after the deadline elapsed"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_already_exited_is_reaped() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a child that exits immediately");
        // Let it actually exit before classifying.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let disposition = kin_daemon_spawn::startup_disposition(&mut child)
            .expect("a child we spawned is observable");
        assert!(
            matches!(disposition, kin_daemon_spawn::StartupDisposition::Exited(_)),
            "an exited child is positive evidence: {disposition:?}"
        );
        assert!(
            kin_daemon_spawn::terminate_if_proven_dead(&mut child, &disposition),
            "a dead child is reaped rather than left as a zombie"
        );
    }

    // ── idle-timeout env-assembly ──────────────────────────────────────────

    #[test]
    fn resolve_idle_timeout_uses_default_when_nothing_set() {
        // No user env, no caller override → compiled default.
        // In test builds default_idle_timeout_secs() returns "1"; we key on
        // whatever that function returns so the assertion survives cfg changes.
        assert_eq!(
            resolve_idle_timeout_env(false, None),
            Some(default_idle_timeout_secs())
        );
    }

    #[test]
    fn resolve_idle_timeout_mcp_override_propagates() {
        // MCP-path caller passes Some(MCP_IDLE_TIMEOUT_SECS) → "1800" reaches daemon.
        assert_eq!(
            resolve_idle_timeout_env(false, Some(MCP_IDLE_TIMEOUT_SECS)),
            Some("1800")
        );
    }

    #[test]
    fn resolve_idle_timeout_user_env_always_wins() {
        // When user has set KIN_DAEMON_IDLE_TIMEOUT_SECS we must not inject anything,
        // regardless of the caller override.
        assert_eq!(resolve_idle_timeout_env(true, None), None);
        assert_eq!(
            resolve_idle_timeout_env(true, Some(MCP_IDLE_TIMEOUT_SECS)),
            None
        );
    }

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        // Regression guard: the MCP path must inject 1800s (30 min), not the
        // 60-second CLI default.
        assert_eq!(MCP_IDLE_TIMEOUT_SECS, "1800");
    }
}
