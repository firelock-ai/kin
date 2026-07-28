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
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};

static BUILD_MISMATCH_REPORTED: AtomicBool = AtomicBool::new(false);

/// Repository/session authority inherited by the CLI must not leak into a
/// daemon process. Daemons receive their repository explicitly through
/// `--repo`; retaining any of these variables can bind the worker to a prior
/// projection or repository identity before argument processing. Daemon
/// configuration such as bind host and bearer token is intentionally retained.
const DAEMON_AMBIENT_AUTHORITY_ENV: &[&str] = &[
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
    "KIN_VFS_WORKSPACE",
    "KIN_VFS_WORKSPACE_ALIASES",
    "KIN_VFS_SOCK",
    "KIN_VFS_PIPE",
    "KIN_VFS_CANARY",
    "KIN_VFS_INTERPOSE_ACTIVE",
    "KIN_VFS_LAST_DIR",
    "_KIN_VFS_LAST_DIR",
    "KIN_NO_VFS",
    "KIN_SESSION",
    "KIN_SESSION_ID",
    "KIN_SESSION_DIR",
    "KIN_DAEMON_URL",
    "KIN_DAEMON_WATCH_PID",
    "KIN_REPO_ID",
    "KIN_REPO_IDS",
    "KIN_PRIMARY_REPO_ID",
    "KIN_MCP_REPO",
    "KIN_SOURCE_ROOT",
    "KIN_ORIGINAL_PATH",
    "KIN_DISCOVERY_MODE",
    "KIN_CONTENT_MODE",
    "KIN_VFS_DISABLE",
];

fn scrub_daemon_process_authority(command: &mut Command) {
    let host_path = kin_core::shims::unshimmed_path();
    for key in DAEMON_AMBIENT_AUTHORITY_ENV {
        command.env_remove(key);
    }
    command.env("PATH", host_path).env("KIN_VFS_DISABLE", "1");
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
    graph_snapshot_version: u32,
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

/// Whether a process with the given pid currently exists (signal 0 probe on
/// unix). Used by the daemon lifecycle and by `kin daemon status`/`stop` to
/// classify a recorded pid as live or stale.
pub fn is_process_alive(pid: u32) -> bool {
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
    let _ = std::fs::remove_file(repo_daemon_pid_path(kin_root));
    let _ = std::fs::remove_file(repo_daemon_port_path(kin_root));
}

fn supervisor_dir() -> PathBuf {
    kin_core::registry::registry_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".kin"))
}

/// Path to the per-user supervisor pid file (under the Kin registry directory).
pub fn supervisor_pid_path() -> PathBuf {
    supervisor_dir().join("supervisor.pid")
}

/// Path to the per-user supervisor port file (under the Kin registry directory).
pub fn supervisor_port_path() -> PathBuf {
    supervisor_dir().join("supervisor.port")
}

/// Remove the supervisor's pid/port endpoint files. Called after a confirmed
/// supervisor stop so a later `status` never reports the dead endpoint as stale.
pub fn remove_stale_supervisor_files() {
    let _ = std::fs::remove_file(supervisor_pid_path());
    let _ = std::fs::remove_file(supervisor_port_path());
}

fn read_pid_file(kin_root: &Path) -> Option<u32> {
    std::fs::read_to_string(repo_daemon_pid_path(kin_root))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(repo_daemon_port_path(kin_root))
        .ok()
        .and_then(|s| s.trim().parse().ok())
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
    let pid = std::fs::read_to_string(supervisor_pid_path())
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let port = std::fs::read_to_string(supervisor_port_path())
        .ok()
        .and_then(|s| s.trim().parse().ok());
    (pid, port)
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

fn live_supervisor_endpoint() -> Option<LiveDaemonEndpoint> {
    let pid = std::fs::read_to_string(supervisor_pid_path())
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if !is_process_alive(pid) {
        remove_stale_supervisor_files();
        return None;
    }
    let port = std::fs::read_to_string(supervisor_port_path())
        .ok()?
        .trim()
        .parse()
        .ok()?;
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
    scrub_daemon_process_authority(&mut command);
    let output = match command.arg("--help").output() {
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
    if rendered.len() > MAX_LEN {
        rendered.truncate(MAX_LEN);
        rendered.push_str("...");
    }
    rendered
}

fn daemon_binary_matches_cli_graph(path: &Path) -> Result<(), String> {
    let mut command = Command::new(path);
    scrub_daemon_process_authority(&mut command);
    let output = command
        .arg("--compat-json")
        .output()
        .map_err(|error| format!("compat probe failed to execute: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compat probe exited with {} ({})",
            output.status,
            compact_probe_output(&output)
        ));
    }
    let compat: DaemonCompatResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("compat probe returned invalid JSON: {error}"))?;
    let expected = kin_db::GraphSnapshot::CURRENT_VERSION;
    if compat.graph_snapshot_version != expected {
        return Err(format!(
            "graph snapshot version {} does not match CLI expected version {expected}",
            compat.graph_snapshot_version
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

fn find_daemon_binary() -> Result<PathBuf> {
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

    if let Ok(explicit) = std::env::var("KIN_DAEMON_BIN") {
        let path = PathBuf::from(explicit);
        if let Some(path) = consider(path) {
            return Ok(path);
        }
    }
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
        bail!("kin-daemon binary not found");
    }
    let checked = rejected
        .into_iter()
        .map(|(path, reason)| format!("{} ({reason})", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "kin-daemon binary is stale or incompatible with this kin CLI; rebuild kin-daemon. Checked: {checked}"
    )
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
/// Mirrors `kin_daemon::lifecycle::MCP_IDLE_TIMEOUT_SECS`; keep both in sync
/// at "1800". kin-cli does not take a direct dep on kin-daemon, so the value
/// is repeated here with an explicit cross-reference as the guard.
const MCP_IDLE_TIMEOUT_SECS: &str = "1800";

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

pub(crate) fn validate_health_repo(health: &HealthResponse, working_dir: &Path) -> Result<()> {
    if !health_status_is_serving(&health.status) {
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

async fn acquire_supervisor_startup_lock() -> Result<StartupLock> {
    let dir = supervisor_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create supervisor state directory {}", dir.display()))?;
    let path = dir.join("supervisor.start.lock");
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
                    warn!(path = %path.display(), "removing stale supervisor startup lock");
                    let _ = std::fs::remove_file(&path);
                    continue;
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
    deadline: Instant,
    log_offset: u64,
) -> Result<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let mut last_error = String::from("daemon did not report its port");

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("check daemon child status")? {
            bail!(
                "daemon exited during startup with status {status}; recent log:\n{}",
                daemon_log_tail_since(kin_root, log_offset)
            );
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

    let _ = child.kill();
    let _ = child.wait();
    bail!(
        "daemon failed to become ready within {:.1}s: {}; recent log:\n{}",
        timeout.as_secs_f64(),
        last_error,
        daemon_log_tail_since(kin_root, log_offset)
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

async fn wait_for_existing_supervisor() -> Option<String> {
    let existing = live_supervisor_endpoint()?;
    match validate_supervisor_endpoint(existing).await {
        Ok(base_url) => Some(base_url),
        Err(err) => {
            warn!(
                pid = existing.pid,
                port = existing.port,
                error = %err,
                "invalid supervisor endpoint; clearing stale endpoint files"
            );
            remove_stale_supervisor_files();
            None
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

async fn wait_for_supervisor_ready(child: &mut Child, deadline: Instant) -> Result<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let mut last_error = String::from("supervisor did not report its port");

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("check supervisor child status")? {
            bail!("supervisor exited during startup with status {status}");
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

    if let Some(base_url) = wait_for_existing_supervisor().await {
        return Ok(base_url);
    }

    let _startup_lock = acquire_supervisor_startup_lock().await?;
    if let Some(base_url) = wait_for_existing_supervisor().await {
        return Ok(base_url);
    }

    let daemon_bin = find_daemon_binary()?;
    // The supervisor binds :0 and reports its real bound port via its endpoint
    // files; passing 0 (rather than a reserved port) removes the same
    // reserve-release-rebind race the repo-daemon path had. Clear stale endpoint
    // files so wait_for_supervisor_ready reads only this spawn's port.
    remove_stale_supervisor_files();
    info!(binary = %daemon_bin.display(), "starting supervisor (OS-assigned port)");

    let mut cmd = std::process::Command::new(&daemon_bin);
    scrub_daemon_process_authority(&mut cmd);
    cmd.args(["--supervisor", "--port", "0"]);
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

    let mut child = cmd.spawn().context("spawn kin supervisor")?;
    let deadline = Instant::now() + Duration::from_secs(daemon_ready_timeout_secs());
    let base_url = wait_for_supervisor_ready(&mut child, deadline).await?;
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
    validate_daemon_endpoint(
        kin_root,
        endpoint,
        Duration::from_secs(existing_daemon_ready_timeout_secs()),
    )
    .await
    .ok()
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

pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String> {
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
) -> Result<String> {
    let supervisor_url = ensure_supervisor_running()
        .await
        .context("kin supervisor is required")?;
    if let Some(base_url) = supervisor_route_for_repo(kin_root, &supervisor_url).await {
        return Ok(base_url);
    }

    if let Some(base_url) = wait_for_existing_daemon(kin_root).await {
        register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url).await?;
        return Ok(base_url);
    }

    let _startup_lock = acquire_startup_lock(kin_root).await?;
    if let Some(base_url) = supervisor_route_for_repo(kin_root, &supervisor_url).await {
        return Ok(base_url);
    }
    if let Some(base_url) = wait_for_existing_daemon(kin_root).await {
        register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url).await?;
        return Ok(base_url);
    }

    let daemon_bin = find_daemon_binary()?;
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| anyhow!("invalid .kin layout: no parent"))?;

    // The daemon owns port selection: it binds :0 and reports the real bound
    // port via the port file. Passing 0 (rather than a port we reserve here)
    // eliminates the reserve-release-rebind race where a sibling process steals
    // the port between our probe and the daemon's bind. Clear any stale port
    // file first so wait_for_daemon_ready only reads the port this spawn writes.
    let _ = std::fs::remove_file(kin_root.join("daemon.port"));

    info!(binary = %daemon_bin.display(), repo = %working_dir.display(), "starting daemon (OS-assigned port)");

    let mut cmd = std::process::Command::new(&daemon_bin);
    scrub_daemon_process_authority(&mut cmd);
    cmd.args(["--repo", &working_dir.display().to_string(), "--port", "0"]);
    let log_offset = daemon_log_len(kin_root);
    let log = open_daemon_log(kin_root)?;
    let stderr = log
        .try_clone()
        .context("clone daemon log handle for stderr")?;
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(stderr));
    let user_timeout_set = std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_some();
    if let Some(timeout) = resolve_idle_timeout_env(user_timeout_set, idle_timeout_override) {
        cmd.env("KIN_DAEMON_IDLE_TIMEOUT_SECS", timeout);
    }
    cmd.env("KIN_SUPERVISOR_URL", &supervisor_url);

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
    let base_url = wait_for_daemon_ready(kin_root, &mut child, deadline, log_offset).await?;
    register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url).await?;
    info!(daemon = %base_url, "daemon is up and ready");
    Ok(base_url)
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
        let mut command = Command::new("true");
        for key in DAEMON_AMBIENT_AUTHORITY_ENV {
            command.env(key, "poison");
        }
        command.env("KIN_DAEMON_AUTH_TOKEN", "configured-token");
        command.env("KIN_DAEMON_BIND_HOST", "0.0.0.0");
        command.env("PATH", "poison-path");

        scrub_daemon_process_authority(&mut command);

        for key in DAEMON_AMBIENT_AUTHORITY_ENV {
            if *key == "KIN_VFS_DISABLE" {
                continue;
            }
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
