// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP client and lifecycle helpers for the kin daemon.
//!
//! Used by CLI commands to query the daemon's live graph instead of
//! opening a snapshot directly. Also owns the repo-scoped daemon
//! auto-start logic so the CLI does not need to depend on `kin-daemon`.
//!
//! This module is the process and install boundary for the CLI, so locating
//! installed kin binaries and probing them is boundary IO that belongs here:
//! it resolves what to execute and executes it, and never answers a question
//! about repository content. Diagnostic surfaces consume the verdict rather
//! than reaching for the filesystem to compute one.

use anyhow::{anyhow, bail, Context, Result};
use fs2::FileExt;
use kin_core::KinLayout;
use kin_model::OperationId;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub(crate) mod probe_process;

static BUILD_MISMATCH_REPORTED: AtomicBool = AtomicBool::new(false);
static BEHAVIOR_ENV_DIVERGENCE_REPORTED: AtomicBool = AtomicBool::new(false);
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
    /// The `.kin/` store predates the layout this build serves.
    ///
    /// Its own text is the whole answer, so callers render it as the headline
    /// rather than as a cause under a missing daemon. No daemon can start
    /// against such a store, and saying the daemon is required first states a
    /// consequence and buries the reason.
    #[error("{0}")]
    IncompatibleStore(String),
    /// This command carries behavior levers the daemon it attached to fixed at
    /// its own start, and `KIN_STRICT_BEHAVIOR_ENV` asked for that to be fatal.
    ///
    /// Its own text is the whole answer, as with an incompatible store: nothing
    /// about starting a daemon failed, so framing it as a startup failure would
    /// name the wrong thing.
    #[error("{0}")]
    BehaviorEnvIgnored(String),
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
    /// The managed Kin home the daemon reported at registration, empty when it
    /// is not recorded (an older daemon, or one the supervisor adopted rather
    /// than received a registration from).
    ///
    /// The supervisor is machine-wide while `KIN_HOME` bounds store and install
    /// state, so a single registry legitimately lists daemons from several
    /// homes. This is what the census labels and what a home-scoped
    /// `kin daemon stop --all` partitions on.
    #[serde(default)]
    pub kin_home: String,
    #[serde(default)]
    pub registered_at: Option<String>,
    #[serde(default)]
    pub last_heartbeat_at: String,
}

/// How a registered daemon's home relates to the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonHomeScope {
    /// The daemon recorded the same managed home the caller resolves.
    Own,
    /// The daemon recorded a different managed home.
    Foreign,
    /// No home was recorded, so the relationship cannot be established.
    ///
    /// Deliberately distinct from [`DaemonHomeScope::Foreign`]: both are
    /// excluded from a home-scoped sweep, but only one of them can be reported
    /// with a home to name.
    Unrecorded,
}

impl RegisteredRepoDaemon {
    /// Classify this daemon against a caller's resolved managed home.
    ///
    /// An unrecorded home is never treated as a match. Failing to stop a daemon
    /// is visible and recoverable; stopping a neighbour's is neither.
    pub fn home_scope(&self, caller_home_id: &str) -> DaemonHomeScope {
        let recorded = self.kin_home.trim();
        if recorded.is_empty() {
            DaemonHomeScope::Unrecorded
        } else if recorded == caller_home_id {
            DaemonHomeScope::Own
        } else {
            DaemonHomeScope::Foreign
        }
    }

    /// The recorded home to show an operator, or a stated absence.
    pub fn home_label(&self) -> &str {
        let recorded = self.kin_home.trim();
        if recorded.is_empty() {
            "unrecorded"
        } else {
            recorded
        }
    }
}

/// The managed Kin home this process resolves, in the string form recorded by
/// registering daemons.
pub fn caller_home_id() -> String {
    kin_core::registry::managed_kin_home_id(&kin_core::registry::managed_kin_home())
}

/// Fetch the repo daemons registered with a running supervisor via `GET
/// /daemons`. The caller supplies a supervisor URL it already resolved (e.g. via
/// [`ensure_supervisor_running`] or [`supervisor_recorded_endpoint`]); this does
/// not itself start a supervisor.
/// Bound on the supervisor topology fetch.
///
/// `kin daemon stop --all` awaits this before it stops anything, so an
/// unbounded fetch is an unbounded stop: a supervisor that accepts the
/// connection and never answers holds the whole command open with no identity
/// yet signalled and no verdict to print. The supervisor only reads its own
/// in-memory registry, so a healthy one answers immediately and this ceiling is
/// never approached.
const SUPERVISOR_TOPOLOGY_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn fetch_registered_daemons(supervisor_url: &str) -> Result<Vec<RegisteredRepoDaemon>> {
    let client = reqwest::Client::builder()
        .timeout(SUPERVISOR_TOPOLOGY_TIMEOUT)
        .build()?;
    let mut request = client.get(format!("{}/daemons", supervisor_url.trim_end_matches('/')));
    if let Some(token) = supervisor_auth_token() {
        request = request.bearer_auth(token);
    }
    let daemons = request.send().await?.error_for_status()?.json().await?;
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
    /// Carries the same endpoint authority as `client`, but never follows an
    /// HTTP redirect that could redispatch a non-idempotent mutation.
    one_dispatch_client: reqwest::Client,
    /// The store this client's daemon serves, when one was resolvable.
    ///
    /// Held so that a request which goes unanswered can ask the store what
    /// happened to its daemon instead of asserting the ordinary cause. A
    /// transport error describes a socket; the killer leaves its evidence in
    /// the repository, and without a root there is nowhere to read it.
    /// `None` behaves exactly as this client behaved before it had this field.
    kin_root: Option<PathBuf>,
}

/// A mutating daemon command was dispatched, but its committed outcome could
/// not be established from the acknowledgement.
///
/// The operation identity remains available to future command-level recovery,
/// but this transport layer deliberately does not claim that a durable receipt
/// exists or retry a request whose first dispatch may already have committed.
#[derive(Debug)]
pub(crate) struct IndeterminateDaemonCommandError {
    pub(crate) operation_id: OperationId,
    path: String,
    detail: String,
}

impl IndeterminateDaemonCommandError {
    fn new(operation_id: OperationId, path: &str, detail: impl Into<String>) -> Self {
        Self {
            operation_id,
            path: path.to_string(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for IndeterminateDaemonCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "daemon command outcome is indeterminate for operation {} at {}: {}; \
             the daemon may already have committed it, so do not retry automatically \
             without reconciling repository state",
            self.operation_id, self.path, self.detail
        )
    }
}

impl std::error::Error for IndeterminateDaemonCommandError {}

/// Proof carried by a successful acknowledgement of a non-idempotent command.
///
/// Requiring this trait at the one-dispatch transport boundary makes it
/// impossible for a new mutation response to treat merely-decodable JSON as
/// authority. The request identity must be echoed exactly, and the response
/// must carry the report that describes the committed outcome.
trait NonIdempotentAcknowledgement {
    fn acknowledged_operation_id(&self) -> Option<OperationId>;
    fn has_authoritative_report(&self) -> bool;
}

impl NonIdempotentAcknowledgement for crate::commands::merge::MergeResponse {
    fn acknowledged_operation_id(&self) -> Option<OperationId> {
        self.operation_id
    }

    fn has_authoritative_report(&self) -> bool {
        self.report.is_some()
    }
}

impl NonIdempotentAcknowledgement for crate::commands::resolve::ResolveResponse {
    fn acknowledged_operation_id(&self) -> Option<OperationId> {
        self.operation_id
    }

    fn has_authoritative_report(&self) -> bool {
        self.report.is_some()
    }
}

#[cfg(test)]
impl NonIdempotentAcknowledgement for serde_json::Value {
    fn acknowledged_operation_id(&self) -> Option<OperationId> {
        self.get("operation_id")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
    }

    fn has_authoritative_report(&self) -> bool {
        self.get("report").is_some_and(|report| !report.is_null())
    }
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
    /// When true, project the graph-native `entities[]` ranking even though
    /// `snippets` is false.
    ///
    /// `snippets` cannot express this on its own: it means "carry source
    /// bodies", and the daemon used it to gate the entity projection as well, so
    /// an agent asking for the structured surface WITHOUT bodies
    /// (`kin locate --json --no-snippets`) received an empty `entities[]`. Its
    /// results were removed in answer to a request to spend fewer tokens, which
    /// is the same defect `include_snippet: false` had on `semantic_locate`.
    /// Defaults to false so the human CLI path and any older client stay
    /// coordinates-only.
    #[serde(default)]
    pub entity_surface: bool,
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
    /// Rank test-role entities alongside source for this query.
    ///
    /// Defaults to false, which is the ranking every caller has today: test-role
    /// entities are demoted, and at several stages excluded, unless the query
    /// text itself reads as being about tests. That heuristic is the only thing
    /// that lifted the demotion, and a caller who knows exactly what it is
    /// asking for had no way to say so.
    #[serde(default)]
    pub include_tests: bool,
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

/// What one admission dispatch established.
///
/// The daemon runs a complete exact-tree admission in a task of its own, so a
/// request that goes unanswered says nothing about the pass: it is still
/// running, and a later request joins it rather than starting a second one.
/// Collapsing that into an ordinary transport error would let a caller read "no
/// answer" as "nothing happened", which is the one reading that is never true
/// here.
pub enum AdmitDispatch {
    /// The daemon answered with a report. Terminal, whatever the report says:
    /// a refused admission is an answer and carries its cause.
    Answered(crate::commands::admit::AdmitResponse),
    /// The daemon refused the request itself, so no pass was started by it.
    Refused(anyhow::Error),
    /// Nothing usable came back. The pass may be running, and its outcome is
    /// not established either way.
    Unanswered(anyhow::Error),
}

impl DaemonClient {
    pub fn from_base_url(base_url: impl Into<String>) -> Result<Self> {
        Self::from_base_url_with_token(base_url, resolve_daemon_auth_token())
    }

    /// Build a client for `layout`'s daemon, resolving the bearer token from
    /// that layout rather than from the process working directory.
    ///
    /// The store root comes from the layout for the same reason the token
    /// does. `kin init` takes the repository as an argument, so on a runner
    /// whose working directory is not that repository, discovery from the
    /// process working directory finds the wrong store or none, and the
    /// evidence about a daemon that died is in the one the layout names.
    pub fn from_base_url_for_layout(
        base_url: impl Into<String>,
        layout: &KinLayout,
    ) -> Result<Self> {
        let mut client =
            Self::from_base_url_with_token(base_url, resolve_daemon_auth_token_for_layout(layout))?;
        client.kin_root = Some(layout.root().to_path_buf());
        Ok(client)
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
            .default_headers(headers.clone())
            .build()
            .context("build daemon client")?;
        let one_dispatch_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(request_timeout))
            .connect_timeout(Duration::from_secs(2))
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .build()
            .context("build one-dispatch daemon client")?;
        Ok(Self {
            base_url,
            client,
            one_dispatch_client,
            // Discovery from the working directory is the fallback every
            // constructor but the layout one gets. A caller standing outside a
            // repository resolves nothing, which is the same reading as a store
            // that never lost a daemon and leaves every message unchanged.
            kin_root: crate::daemon_death::kin_root_from_cwd(),
        })
    }

    /// The store whose records explain a daemon of this endpoint that died.
    fn kin_root(&self) -> Option<&Path> {
        self.kin_root.as_deref()
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        leaf: &str,
    ) -> Result<reqwest::Response> {
        let resp = request
            .send()
            .await
            .with_context(|| daemon_send_failure_message(&self.base_url, leaf, self.kin_root()))?;
        check_response_build_match(resp.headers())?;
        Ok(resp)
    }

    /// Turn a non-success daemon response into the error the user reads.
    async fn http_refusal(&self, leaf: &str, response: reqwest::Response) -> anyhow::Error {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        daemon_http_error(&self.base_url, leaf, status, &body)
    }

    /// Try to connect to the daemon. Returns `None` if the daemon is
    /// unreachable or unhealthy.
    pub async fn try_connect() -> Option<Self> {
        let base = std::env::var("KIN_DAEMON_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;

        let client = Self::from_base_url(base.clone()).ok()?;

        // Probe health endpoint
        let resp = client
            .client
            .get(format!("{}/health", base))
            .send()
            .await
            .ok()?;

        if resp.status().is_success() {
            Some(client)
        } else {
            None
        }
    }

    /// Get the daemon's health response (includes entity count, uptime, etc.).
    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        let resp = self
            .send(
                self.client.get(format!("{}/health", self.base_url)),
                "health",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("health", resp).await);
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
    /// The `repo_id` is the identity the daemon advertises on `GET /health`,
    /// which is the only key space the repo-scoped routes resolve. Deriving it
    /// from a directory name instead addresses a repository the daemon does
    /// not serve.
    pub async fn search_entities(
        &self,
        repo_id: &str,
        query: Option<&str>,
    ) -> anyhow::Result<Vec<DaemonEntityEntry>> {
        let mut url = format!("{}/repos/{}/entities", self.base_url, repo_id);
        if let Some(q) = query {
            url = format!("{}?query={}", url, urlencoding::encode(q));
        }
        let resp = self.send(self.client.get(&url), "entity search").await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("entity search", resp).await);
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
        leaf: &str,
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
                    leaf,
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
                last_error = Some(daemon_http_error(
                    &self.base_url,
                    leaf,
                    status.as_u16(),
                    &body,
                ));
                continue;
            }
            return Err(daemon_http_error(
                &self.base_url,
                leaf,
                status.as_u16(),
                &body,
            ));
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("daemon command produced no response")))
    }

    /// POST one non-idempotent JSON command exactly once.
    ///
    /// Once dispatch begins, no response class alone proves whether the daemon
    /// committed the operation. Merge and resolve can durably publish authority
    /// before daemon-side finalization reports a 4xx or 5xx error, so every
    /// non-success response, transport failure, response-body failure, and
    /// successful-but-undecodable or uncorroborated response returns a typed
    /// indeterminate error carrying the caller-stable operation identity. A
    /// future protocol may recover precise rejection semantics through
    /// explicit pre-commit proof.
    async fn post_non_idempotent_json<Req, Resp>(
        &self,
        path: &str,
        payload: &Req,
        operation_id: OperationId,
        leaf: &str,
    ) -> Result<Resp>
    where
        Req: serde::Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned + NonIdempotentAcknowledgement,
    {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let payload = serde_json::to_vec(payload)
            .with_context(|| format!("encode non-idempotent daemon request for {path}"))?;
        let response = self
            .send(
                self.one_dispatch_client
                    .post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(payload),
                leaf,
            )
            .await
            .map_err(|error| {
                anyhow::Error::new(IndeterminateDaemonCommandError::new(
                    operation_id,
                    path,
                    format!("request dispatch or acknowledgement failed: {error:#}"),
                ))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|error| format!("<response body unavailable: {error}>"));
            return Err(anyhow::Error::new(IndeterminateDaemonCommandError::new(
                operation_id,
                path,
                format!("daemon returned HTTP {status}: {body}"),
            )));
        }

        let body = response.bytes().await.map_err(|error| {
            anyhow::Error::new(IndeterminateDaemonCommandError::new(
                operation_id,
                path,
                format!("read daemon response body failed: {error}"),
            ))
        })?;
        let acknowledgement: Resp = serde_json::from_slice(&body).map_err(|error| {
            anyhow::Error::new(IndeterminateDaemonCommandError::new(
                operation_id,
                path,
                format!("decode daemon response failed: {error}"),
            ))
        })?;
        match acknowledgement.acknowledged_operation_id() {
            Some(acknowledged) if acknowledged == operation_id => {}
            Some(acknowledged) => {
                return Err(anyhow::Error::new(IndeterminateDaemonCommandError::new(
                    operation_id,
                    path,
                    format!(
                        "daemon success acknowledgement named operation {acknowledged}, \
                         expected {operation_id}"
                    ),
                )));
            }
            None => {
                return Err(anyhow::Error::new(IndeterminateDaemonCommandError::new(
                    operation_id,
                    path,
                    "daemon success acknowledgement omitted operation_id",
                )));
            }
        }
        if !acknowledgement.has_authoritative_report() {
            return Err(anyhow::Error::new(IndeterminateDaemonCommandError::new(
                operation_id,
                path,
                "daemon success acknowledgement omitted its authoritative report",
            )));
        }
        Ok(acknowledgement)
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
                "locate",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("locate", resp).await);
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
                "search",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("search", resp).await);
        }
        resp.json().await.context("parse daemon search response")
    }

    pub async fn support(&self) -> Result<crate::commands::support::SupportJson> {
        let resp = self
            .send(
                self.client.get(format!("{}/support", self.base_url)),
                "support",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("support", resp).await);
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
                "context",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("context", resp).await);
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
                "trace",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("trace", resp).await);
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
                "impact",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("impact", resp).await);
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
                "review",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("review", resp).await);
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
                "embed",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("embed", resp).await);
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
                "blame",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("blame", resp).await);
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
                "history",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("history", resp).await);
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
                "verify run",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("verify run", resp).await);
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
                "verify",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("verify", resp).await);
        }
        resp.json().await.context("parse daemon verify response")
    }

    /// Queue a cold language-server sweep and report the count a waiter must
    /// exceed. See `POST /lsp/sweep`.
    pub async fn queue_lsp_sweep(&self) -> Result<serde_json::Value> {
        let resp = self
            .send(
                self.client.post(format!("{}/lsp/sweep", self.base_url)),
                "lsp sweep",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("lsp sweep", resp).await);
        }
        Ok(resp.json().await.context("read lsp sweep response")?)
    }

    /// How far the cold sweep has got. See `GET /lsp/sweep/status`.
    pub async fn lsp_sweep_status(&self) -> Result<serde_json::Value> {
        let resp = self
            .send(
                self.client
                    .get(format!("{}/lsp/sweep/status", self.base_url)),
                "lsp sweep status",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("lsp sweep status", resp).await);
        }
        Ok(resp.json().await.context("read lsp sweep status")?)
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
                "reconcile",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("reconcile", resp).await);
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
                "command status",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("command status", resp).await);
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
                leaf,
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal(leaf, resp).await);
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
                "resources",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("resources", resp).await);
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
                "graph",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("graph", resp).await);
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
                "overview",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("overview", resp).await);
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
                "dead-code",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("dead-code", resp).await);
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
                "seeded dead-code",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("seeded dead-code", resp).await);
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
                "trace-data-flow",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("trace-data-flow", resp).await);
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
                "refs",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("refs", resp).await);
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
                "bulk refs",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("bulk refs", resp).await);
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
                "xref",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("xref", resp).await);
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
                "diff",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("diff", resp).await);
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
                "log",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("log", resp).await);
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
                "audit",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("audit", resp).await);
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
                "approvals",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("approvals", resp).await);
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
                "security",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("security", resp).await);
        }
        resp.json().await.context("parse daemon security response")
    }

    pub async fn branch(
        &self,
        request: &crate::commands::branch::BranchRequest,
    ) -> Result<crate::commands::branch::BranchResponse> {
        self.post_idempotent_json("/commands/branch", request, "branch")
            .await
    }

    pub async fn merge(
        &self,
        request: &crate::commands::merge::MergeRequest,
    ) -> Result<crate::commands::merge::MergeResponse> {
        self.post_non_idempotent_json("/commands/merge", request, request.operation_id, "merge")
            .await
    }

    pub async fn conflicts(
        &self,
        request: &crate::commands::conflicts::ConflictsRequest,
    ) -> Result<crate::commands::conflicts::ConflictsResponse> {
        self.post_idempotent_json("/commands/conflicts", request, "conflicts")
            .await
    }

    pub async fn resolve(
        &self,
        request: &crate::commands::resolve::ResolveRequest,
    ) -> Result<crate::commands::resolve::ResolveResponse> {
        self.post_non_idempotent_json(
            "/commands/resolve",
            request,
            request.operation_id,
            "resolve",
        )
        .await
    }

    pub async fn tag(
        &self,
        request: &crate::commands::tag::TagRequest,
    ) -> Result<crate::commands::tag::TagResponse> {
        self.post_idempotent_json("/commands/tag", request, "tag")
            .await
    }

    pub async fn stash(
        &self,
        request: &crate::commands::stash::StashRequest,
    ) -> Result<crate::commands::stash::StashResponse> {
        self.post_idempotent_json("/commands/stash", request, "stash")
            .await
    }

    pub async fn purge_ignored(
        &self,
        request: &crate::commands::purge_ignored::PurgeIgnoredRequest,
    ) -> Result<crate::commands::purge_ignored::PurgeIgnoredResponse> {
        self.post_idempotent_json("/commands/purge-ignored", request, "purge-ignored")
            .await
    }

    /// Request one complete exact-tree admission.
    ///
    /// Deliberately not on the shared retrying poster. That poster retries a
    /// transport failure with the same payload, and here the first attempt may
    /// have left a pass running that already published the tree: the retry then
    /// observes a tree with nothing to do, and the fast empty-delta answer it
    /// gets back reports a complete admission for a pass whose enrichment never
    /// ran. One dispatch keeps the two facts apart, and the caller waits by
    /// asking again on purpose rather than by being retried silently.
    pub async fn admit(&self, request: &crate::commands::admit::AdmitRequest) -> AdmitDispatch {
        let url = format!("{}/commands/admit", self.base_url.trim_end_matches('/'));
        let payload = match serde_json::to_vec(request) {
            Ok(payload) => payload,
            Err(error) => {
                return AdmitDispatch::Refused(
                    anyhow::Error::new(error).context("encode the admission request"),
                )
            }
        };
        let response = match self
            .one_dispatch_client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return AdmitDispatch::Unanswered(anyhow::Error::new(error).context(
                    daemon_send_failure_message(&self.base_url, "admit", self.kin_root()),
                ))
            }
        };
        if let Err(error) = check_response_build_match(response.headers()) {
            return AdmitDispatch::Refused(error);
        }
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return AdmitDispatch::Refused(daemon_http_error(
                &self.base_url,
                "admit",
                status.as_u16(),
                &body,
            ));
        }
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => {
                return AdmitDispatch::Unanswered(
                    anyhow::Error::new(error).context("read the admission response body"),
                )
            }
        };
        match serde_json::from_slice(&body) {
            Ok(decoded) => AdmitDispatch::Answered(decoded),
            Err(error) => AdmitDispatch::Unanswered(
                anyhow::Error::new(error).context("decode the admission response"),
            ),
        }
    }

    /// Whether the daemon is answering at all, on a budget short enough to be
    /// asked while another request is outstanding.
    ///
    /// A command waiting on work the daemon is doing has to tell "still
    /// running" from "gone", and the request it is waiting on cannot answer
    /// that: both look like nothing coming back. Deliberately a bool, because
    /// the only thing it establishes is reachability, and a daemon that is
    /// reachable has said nothing about the work.
    pub async fn is_reachable(&self) -> bool {
        self.one_dispatch_client
            .get(format!("{}/health", self.base_url.trim_end_matches('/')))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }

    pub async fn rollback(
        &self,
        request: &crate::commands::rollback::RollbackRequest,
    ) -> Result<crate::commands::rollback::RollbackResponse> {
        self.post_idempotent_json("/commands/rollback", request, "rollback")
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
                "drift",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("drift", resp).await);
        }
        resp.json().await.context("parse daemon drift response")
    }

    pub async fn checkout(
        &self,
        request: &crate::commands::checkout::CheckoutRequest,
    ) -> Result<crate::commands::checkout::CheckoutResponse> {
        self.post_idempotent_json("/commands/checkout", request, "checkout")
            .await
    }

    pub async fn rename(
        &self,
        request: &crate::commands::rename::RenameRequest,
    ) -> Result<crate::commands::rename::RenameResponse> {
        self.post_idempotent_json("/commands/rename", request, "rename")
            .await
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
                "session workspace",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("session workspace", resp).await);
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
                "session start",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("session start", resp).await);
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
                "session end",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("session end", resp).await);
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
                "work",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("work", resp).await);
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
                "note",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("note", resp).await);
        }
        resp.json().await.context("parse daemon note response")
    }

    pub async fn set_scope(&self, session_id: &str, ref_string: &str) -> Result<ScopeResponse> {
        let resp = self
            .send(
                self.client
                    .post(format!("{}/session/{}/scope", self.base_url, session_id))
                    .json(&serde_json::json!({ "ref_string": ref_string })),
                "scope update",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("scope update", resp).await);
        }
        resp.json().await.context("parse scope response")
    }

    pub async fn clear_scope(&self, session_id: &str) -> Result<()> {
        let resp = self
            .send(
                self.client
                    .delete(format!("{}/session/{}/scope", self.base_url, session_id)),
                "scope clear",
            )
            .await?;
        if !resp.status().is_success() {
            return Err(self.http_refusal("scope clear", resp).await);
        }
        Ok(())
    }

    pub async fn get_scope(&self, session_id: &str) -> Result<Option<ScopeResponse>> {
        let resp = self
            .send(
                self.client
                    .get(format!("{}/session/{}/scope", self.base_url, session_id)),
                "scope read",
            )
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(self.http_refusal("scope read", resp).await);
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
    // One process holds one environment and talks to one daemon, so a second
    // telling repeats the first exactly. The suppression covers the warning
    // only: strict mode above refuses every time, because a refusal that fires
    // once and then passes is not a refusal.
    if BEHAVIOR_ENV_DIVERGENCE_REPORTED.swap(true, Ordering::Relaxed) {
        return Ok(());
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

/// The headline a dropped daemon request leads with.
///
/// The worker exits after its idle window, so the ordinary cause of a request
/// that never lands is a daemon that retired between URL resolution and this
/// dispatch. Naming the endpoint and the command keeps the plumbing verb out of
/// the headline.
///
/// The idle window is the ordinary cause and not the only one, and this used to
/// assert it unconditionally, from the endpoint and the request name alone,
/// having asked nothing about whether the daemon was alive. On the measured
/// FIR-2650 run it named an idle window for a daemon the kernel had OOM-killed
/// fourteen seconds earlier, and told the reader to re-run. That advice cannot
/// terminate: an OOM at that repository size recurs on every attempt.
///
/// So the store is asked first. It answers only when it can prove a death, and
/// on every host that has never lost a daemon it answers nothing and this
/// message stays byte for byte what it was.
fn daemon_send_failure_message(base_url: &str, leaf: &str, kin_root: Option<&Path>) -> String {
    if let Some(state) = kin_root.and_then(crate::daemon_death::daemon_not_answering) {
        return crate::daemon_death::dropped_request_sentence(base_url, leaf, &state);
    }
    format!(
        "the kin daemon at {base_url} stopped answering while the {leaf} request was in flight; \
         it exits after its idle window, so re-run the command and kin will start a fresh one"
    )
}

/// The error a non-success daemon response becomes.
///
/// An empty body is its own outcome rather than a refusal with nothing to say,
/// so that branch names the log to read instead of rendering a status code and
/// a colon with nothing after it.
fn daemon_http_error(base_url: &str, leaf: &str, status: u16, body: &str) -> anyhow::Error {
    if body.trim().is_empty() {
        anyhow::anyhow!(
            "the kin daemon at {base_url} answered HTTP {status} with an empty body for {leaf}; \
             read .kin/daemon.log, then stop it with `kin daemon stop` and re-run"
        )
    } else {
        anyhow::anyhow!("kin {leaf} refused (HTTP {status}): {body}")
    }
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

/// Whether a Linux `/proc/<pid>/stat` line describes a zombie.
///
/// Split out from the probe below, and compiled under `test` on every platform,
/// so this is not code that only ever builds on one target. Reading the wrong
/// field is the failure mode that matters: it would answer "not a corpse"
/// forever, which is exactly the bug being fixed, and it would do so silently.
#[cfg(any(target_os = "linux", test))]
fn linux_stat_line_is_zombie(stat: &str) -> bool {
    // Field 3 is the state character. `comm` (field 2) is parenthesized and may
    // itself contain spaces and `)`, and it is the only field that can, so the
    // state is the first whitespace-separated field after `comm`'s FINAL
    // closing delimiter.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z")
}

/// Has this PID already terminated, with only an unreaped process-table entry
/// left behind?
///
/// `kill(pid, 0)` succeeds against a zombie, so a liveness probe built on the
/// signal check alone reports a daemon that has already exited as still
/// running — for as long as whichever process started it stays alive without
/// waiting on it. That is the ordinary shape of an agent session: the MCP
/// server starts a repo daemon, keeps running, and never reaps it, so `kin
/// daemon stop` could watch the corpse for any length of time and never see it
/// go away.
///
/// Reporting a zombie dead is affirmative rather than a guess, and it is
/// strictly safer than the alternative: the process has terminated, it cannot
/// execute, it holds no port, and its PID cannot be reused until it is reaped,
/// so no successor can inherit a decision made here.
///
/// Callers must have established same-credential access first (this is only
/// reached after `kill(pid, 0)` succeeded). Anything short of affirmative
/// evidence of a corpse answers `false` and leaves the caller's conservative
/// path intact.
#[cfg(unix)]
fn process_is_unreaped_corpse(pid: libc::pid_t) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        linux_stat_line_is_zombie(&stat)
    }
    #[cfg(target_os = "macos")]
    {
        let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let expected = std::mem::size_of::<libc::proc_bsdinfo>();
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut _,
                expected as i32,
            )
        };
        // `proc_pidinfo` reports failure as a zero return with `errno` set, so
        // only zero is a result whose `errno` is this call's. A short non-zero
        // return is undocumented and would leave `errno` holding whatever an
        // earlier, unrelated call left there — and reading a stale `ESRCH` out
        // of it would declare a LIVE daemon stopped, which is the one direction
        // this must never fail in.
        if written != 0 {
            return false;
        }
        // Permission to inspect is already established by the caller's
        // successful `kill(pid, 0)`, so `ESRCH` here is the kernel reporting
        // that the process is gone rather than that this caller may not look.
        // `EPERM` and every other failure stay indeterminate.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // No affirmative corpse probe on this platform. Never guess: an
        // unrecognised Unix keeps the conservative "signalable means alive"
        // answer it had before.
        let _ = pid;
        false
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
            // Signalable is not the same as running: an exited child whose
            // parent has not waited on it still answers `kill(pid, 0)`.
            return if process_is_unreaped_corpse(pid) {
                ProcessLiveness::Dead
            } else {
                ProcessLiveness::Alive
            };
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

/// Prefix of the macOS boot identity this build no longer mints, but must still
/// be able to read.
///
/// `kern.boottime` is not a boot token. macOS derives it as (now - uptime) and
/// re-derives it whenever the clock moves, so an NTP correction shifts it while
/// the machine stays up. Measured on one host: the same boot reported
/// `sec=1785713468 usec=118135` and, ninety minutes later with no reboot,
/// `usec=168489`. An identity carrying that microsecond therefore stops
/// matching itself, and every path gated on process identity - stop, autostart
/// singleton detection, stale-endpoint cleanup, eject - concludes the process it
/// is looking at is a different incarnation. The reported symptom is `kin daemon
/// stop` answering "nothing to stop" while the daemon it cannot see burns a
/// core.
///
/// The boot second is far more stable than the microsecond but is not immune
/// either: a slew that accumulates past one second moves it too. That is
/// tolerable only because this format is now read-only. Identities recorded from
/// here on carry `kern.bootsessionuuid`, which the kernel generates once per boot
/// and never derives from a clock, so any daemon that restarts leaves the legacy
/// format behind for good.
#[cfg(any(target_os = "macos", test))]
const MACOS_LEGACY_BOOTTIME_PREFIX: &str = "macos-kern-boottime:";

/// The kernel's per-boot UUID, or `None` when it cannot be read.
///
/// `None` is a fallback signal rather than an error: the caller degrades to the
/// boot second, which is still a usable identity, instead of failing closed and
/// making every identity-gated path indeterminate on a host whose kernel does
/// not publish this key.
#[cfg(target_os = "macos")]
fn macos_boot_session_uuid() -> Option<String> {
    const NAME: &[u8] = b"kern.bootsessionuuid\0";

    let mut len: usize = 0;
    let sized = unsafe {
        libc::sysctlbyname(
            NAME.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let read = unsafe {
        libc::sysctlbyname(
            NAME.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    buf.truncate(len);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    let uuid = String::from_utf8(buf).ok()?;
    let uuid = uuid.trim();
    if uuid.is_empty() {
        None
    } else {
        Some(uuid.to_string())
    }
}

/// The boot second from `kern.boottime`, deliberately without its microsecond.
#[cfg(target_os = "macos")]
fn macos_kern_boottime_seconds() -> std::io::Result<i64> {
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
    Ok(boot_time.tv_sec as i64)
}

/// Whether a legacy `macos-kern-boottime:` identity names the boot whose second
/// is `live_seconds`.
///
/// Compares the second and discards the microsecond, which is the whole point:
/// the microsecond is the field the clock moves. The second is compared exactly
/// rather than with tolerance, because a window wide enough to absorb a large
/// slew is also wide enough to accept a different boot, and a guard that accepts
/// every boot protects nothing.
///
/// Pure and target-independent so the slew case is testable on every platform
/// rather than only on the one where it happens.
#[cfg(any(target_os = "macos", test))]
fn macos_legacy_boottime_matches(recorded: &str, live_seconds: i64) -> bool {
    recorded
        .strip_prefix(MACOS_LEGACY_BOOTTIME_PREFIX)
        .and_then(|rest| rest.split(':').next())
        .and_then(|seconds| seconds.parse::<i64>().ok())
        .is_some_and(|seconds| seconds == live_seconds)
}

/// Whether `recorded` names the boot this process is running under.
///
/// Reads the recorded identity's own scheme rather than assuming it was minted
/// by this build. A daemon started before the boot-session-UUID change recorded
/// the legacy format and is still running, so an upgraded binary that compared
/// only against the format it now mints would declare every one of those daemons
/// a stranger - reproducing the bug it was meant to fix, once, for every process
/// already on the machine.
fn boot_identity_matches(recorded: &str) -> std::io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        if recorded.starts_with(MACOS_LEGACY_BOOTTIME_PREFIX) {
            return Ok(macos_legacy_boottime_matches(
                recorded,
                macos_kern_boottime_seconds()?,
            ));
        }
    }
    Ok(recorded == stable_boot_identity()?)
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
        if let Some(uuid) = macos_boot_session_uuid() {
            return Ok(format!("macos-boot-session:{uuid}"));
        }
        // Fall back to the boot second, never the microsecond. See
        // `MACOS_LEGACY_BOOTTIME_PREFIX` for why the microsecond cannot be part
        // of an identity.
        return Ok(format!(
            "{MACOS_LEGACY_BOOTTIME_PREFIX}{}",
            macos_kern_boottime_seconds()?
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

/// Whether `identity` still names the process incarnation running at its PID.
///
/// The PID and the birth token are compared exactly: they are what separate a
/// process from an unrelated successor that inherited its number. The boot
/// component goes through [`boot_identity_matches`] instead of struct equality,
/// because on macOS the recorded boot string can be a wall-clock derivation that
/// moves under the recorder's feet. Whole-struct equality is what turned that
/// movement into "this is a different process", so the single comparison that
/// every identity-gated path funnels through is the right and only place to fix
/// it.
pub fn process_identity_is_current(identity: &ProcessIdentity) -> std::io::Result<bool> {
    let Some(live) = process_identity(identity.pid)? else {
        return Ok(false);
    };
    if live.pid != identity.pid || live.birth_token != identity.birth_token {
        return Ok(false);
    }
    boot_identity_matches(&identity.boot_id)
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

/// Path to the sidecar attributing a published endpoint to one process
/// incarnation. Written by the daemon alongside the endpoint it describes.
pub fn repo_daemon_owner_path(kin_root: &Path) -> PathBuf {
    kin_root.join("daemon.owner")
}

/// Schema tag carried by the endpoint owner sidecar.
pub const ENDPOINT_OWNER_SCHEMA: &str = "kin.daemon.endpoint-owner.v1";

/// Who published the endpoint currently on disk.
///
/// `daemon.pid` holds a bare PID because every version of every Kin surface
/// reads it that way, and a PID alone cannot survive reuse: after the recorded
/// daemon exits, that number starts naming whatever the kernel handed it to
/// next, and a reader comparing PIDs either preserves a dead endpoint forever
/// or deletes a live one. This sidecar records the same process incarnation the
/// singleton lock stamps, so ownership can be *proved* rather than inferred
/// from a number.
///
/// The record carries identity and nothing else. A port field was tempting and
/// is deliberately absent: `daemon.port` is the port, nothing would read a
/// second copy, and two records of the same fact can only ever disagree.
///
/// The definition lives here rather than beside the daemon that writes it for
/// the same reason. The daemon publishes the record and the CLI start path
/// reads it to decide whether an endpoint may be replaced; a second declaration
/// of one schema is a second thing to keep in step, and the schema tag exists
/// precisely so a reader can refuse a record it does not understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointOwnerRecord {
    schema: String,
    identity: ProcessIdentity,
}

impl EndpointOwnerRecord {
    /// A record attributing an endpoint to this process incarnation, or `None`
    /// on a target that cannot describe one.
    pub fn current() -> Option<Self> {
        Some(Self {
            schema: ENDPOINT_OWNER_SCHEMA.to_string(),
            identity: current_process_identity().ok()?,
        })
    }

    /// The incarnation this record names.
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Attribute an endpoint to an incarnation other than this process, so a
    /// test can build the state a predecessor or a successor would leave behind
    /// without running a second daemon.
    ///
    /// Hidden rather than `#[cfg(test)]`: the daemon crate's tests need it too,
    /// and a `cfg(test)` item is invisible across a crate boundary.
    #[doc(hidden)]
    pub fn for_identity(identity: ProcessIdentity) -> Self {
        Self {
            schema: ENDPOINT_OWNER_SCHEMA.to_string(),
            identity,
        }
    }
}

/// Read the endpoint owner sidecar, if one exists and this build understands it.
pub fn read_endpoint_owner_record(kin_root: &Path) -> Option<EndpointOwnerRecord> {
    let raw = std::fs::read_to_string(repo_daemon_owner_path(kin_root)).ok()?;
    let record: EndpointOwnerRecord = serde_json::from_str(&raw).ok()?;
    (record.schema == ENDPOINT_OWNER_SCHEMA).then_some(record)
}

/// What could be established about the owner of a published endpoint, and
/// whether the answer came from a verified incarnation or only from a PID.
///
/// The two travel together because the honest diagnostic differs: a bare PID
/// that stopped responding says only that a number is gone, while a verified
/// identity mismatch says the daemon that published this endpoint is gone and
/// its PID now names something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointOwnerLiveness {
    liveness: ProcessLiveness,
    identity_verified: bool,
}

impl EndpointOwnerLiveness {
    /// Whether the endpoint may be retired: only affirmative death qualifies.
    pub fn authorizes_cleanup(self) -> bool {
        self.liveness.authorizes_cleanup()
    }

    /// Whether the verdict was decided against a recorded incarnation rather
    /// than a bare PID.
    pub fn identity_verified(self) -> bool {
        self.identity_verified
    }

    fn from_identity(liveness: ProcessLiveness) -> Self {
        Self {
            liveness,
            identity_verified: true,
        }
    }

    fn from_pid(liveness: ProcessLiveness) -> Self {
        Self {
            liveness,
            identity_verified: false,
        }
    }
}

/// Judge the owner of this repo's published endpoint, preferring the recorded
/// incarnation over the bare PID.
///
/// This is the client-side twin of `kin_daemon::lifecycle::endpoint_ownership`
/// and answers the same question in the same direction: it governs whether an
/// endpoint may be *deleted*, so an indeterminate probe is ownership-preserving.
/// Refusing to retire what cannot be inspected costs a stale file; retiring a
/// live daemon's endpoint strands the repo.
///
/// Deciding from the bare PID is what wedged autostart. A SIGKILLed daemon
/// leaves its endpoint behind, the kernel hands that PID to an unrelated
/// process, `kill(pid, 0)` reports it alive, and the start path concludes
/// forever that a live daemon it cannot reach owns the repo: never `Invalid`,
/// never retired, never respawned.
pub fn endpoint_owner_liveness(kin_root: &Path, recorded_pid: u32) -> EndpointOwnerLiveness {
    endpoint_owner_liveness_with_probes(
        kin_root,
        recorded_pid,
        process_identity_is_current,
        process_liveness,
    )
}

/// Both probes are injectable for the same reason the daemon's are: the
/// indeterminate arm and the legacy arm are decisions, and a decision that
/// cannot be exercised in a test is one a later change can silently invert.
fn endpoint_owner_liveness_with_probes(
    kin_root: &Path,
    recorded_pid: u32,
    identity_probe: impl FnOnce(&ProcessIdentity) -> std::io::Result<bool>,
    pid_probe: impl FnOnce(u32) -> ProcessLiveness,
) -> EndpointOwnerLiveness {
    let Some(record) = read_endpoint_owner_record(kin_root) else {
        // A legacy endpoint published before attribution existed, or by a
        // compatible older daemon. A bare PID is all there is to go on.
        return EndpointOwnerLiveness::from_pid(pid_probe(recorded_pid));
    };
    if record.identity.pid != recorded_pid {
        // Attribution and endpoint disagree, so the record does not describe
        // the endpoint being judged. Publication installs the record before the
        // PID file it attributes, so this is a torn write or a mixed-version
        // writer rather than a generation this reader can reason about. Judge
        // the PID the endpoint actually names, which can only ever be more
        // conservative than acting on a statement about a different process.
        return EndpointOwnerLiveness::from_pid(pid_probe(recorded_pid));
    }
    if record.identity.pid == std::process::id() {
        // Answer the "is it mine" case from this process's own identity rather
        // than from a probe of its PID: routing the self case through a
        // fallible probe would let a transient error report this process as
        // gone.
        return EndpointOwnerLiveness::from_identity(match current_process_identity() {
            Ok(current) if current == record.identity => ProcessLiveness::Alive,
            // Our PID, a different incarnation: the publisher exited and the
            // kernel handed us its number.
            Ok(_) => ProcessLiveness::Dead,
            Err(_) => ProcessLiveness::Unknown,
        });
    }
    EndpointOwnerLiveness::from_identity(match identity_probe(&record.identity) {
        Ok(true) => ProcessLiveness::Alive,
        // The PID resolves to a different incarnation than the one that
        // published this endpoint, so the publisher is gone.
        Ok(false) => ProcessLiveness::Dead,
        // An identity that cannot be read at all (another user's process) is
        // indeterminate, and an uninspectable owner is not a dead one.
        Err(_) => ProcessLiveness::Unknown,
    })
}

/// An endpoint that survived a retirement attempt, and why.
///
/// `daemon.pid` is what publishes an endpoint, so a record left behind is a
/// standing claim on the repo that outlives the daemon it names. Carrying the
/// path and the reason together is what lets a caller report the survivor
/// instead of only knowing that something went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedDaemonEndpoint {
    pid_path: PathBuf,
    reason: String,
}

impl PreservedDaemonEndpoint {
    /// The pid file still publishing the endpoint.
    pub fn pid_path(&self) -> &Path {
        &self.pid_path
    }

    /// Why retirement did not happen.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Build a preserved-endpoint value so the CLI's stop-report tests can exercise
/// the exit-code decision without standing up a daemon.
///
/// Hidden rather than `#[cfg(test)]`: the report lives in another module, and a
/// `cfg(test)` item is invisible to it.
#[doc(hidden)]
pub fn preserved_daemon_endpoint_for_test(
    pid_path: &Path,
    reason: &str,
) -> PreservedDaemonEndpoint {
    PreservedDaemonEndpoint {
        pid_path: pid_path.to_path_buf(),
        reason: reason.to_string(),
    }
}

impl fmt::Display for PreservedDaemonEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} survives ({})", self.pid_path.display(), self.reason)
    }
}

/// What a retirement attempt left on disk.
///
/// `#[must_use]` on purpose. Discarding this verdict is the defect this type
/// exists to close: retirement is conditional on a liveness probe, the skip is
/// silent, and a caller that ignores the answer reports a clean stop while the
/// stopped daemon's endpoint stays published.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum DaemonEndpointCleanup {
    /// Nothing publishes the judged endpoint any more: it was retired here or
    /// was already gone.
    Retired,
    /// The record on disk names a different daemon than the one judged, so it
    /// belongs to a successor and preserving it is the correct outcome.
    Superseded,
    /// The judged endpoint is still published.
    Preserved(PreservedDaemonEndpoint),
}

impl DaemonEndpointCleanup {
    /// The surviving endpoint, when the judged one was preserved.
    pub fn preserved(&self) -> Option<&PreservedDaemonEndpoint> {
        match self {
            Self::Preserved(preserved) => Some(preserved),
            Self::Retired | Self::Superseded => None,
        }
    }
}

/// How long a caller that has just confirmed a stop waits for the operating
/// system to finish tearing the process down before judging its endpoint.
///
/// A stop returns as soon as the daemon's incarnation stops answering; process
/// teardown completes afterwards, and until it does a liveness probe can answer
/// `Alive` or an indeterminate `Unknown`. Both refuse cleanup, and the refusal
/// is permanent because nothing retries it, so one probe taken inside that
/// window preserves a dead daemon's endpoint for good.
const ENDPOINT_TEARDOWN_BUDGET: Duration = Duration::from_secs(5);

const ENDPOINT_TEARDOWN_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Remove a repo worker daemon's pid/port endpoint files. The daemon deletes
/// these itself on graceful shutdown; hygiene paths call this to clear a record
/// left behind by a daemon that is already gone.
///
/// Probes liveness once, so a caller that has *just* stopped the daemon should
/// call [`retire_stopped_daemon_endpoint`] instead: this probe would run inside
/// the teardown window it needs to wait out.
pub fn remove_stale_daemon_files(kin_root: &Path) -> DaemonEndpointCleanup {
    retire_daemon_endpoint(kin_root, Duration::ZERO)
}

/// Retire the endpoint of a worker daemon whose stop was just confirmed.
///
/// Waits boundedly for the recorded owner to become affirmatively dead before
/// deciding, and reports what happened. Both halves matter: without the wait the
/// decision is a coin flip against process teardown, and without the report a
/// lost coin flip is invisible to the operator and to every later reader of the
/// endpoint.
pub fn retire_stopped_daemon_endpoint(kin_root: &Path) -> DaemonEndpointCleanup {
    retire_daemon_endpoint(kin_root, ENDPOINT_TEARDOWN_BUDGET)
}

fn retire_daemon_endpoint(kin_root: &Path, teardown_budget: Duration) -> DaemonEndpointCleanup {
    retire_daemon_endpoint_with_probe(kin_root, teardown_budget, |root, pid| {
        // Judged against the recorded incarnation, not the bare PID. After the
        // publisher exits, its number starts naming whatever the kernel handed
        // it next, and a bare probe then reports a live stranger as the endpoint
        // owner forever. Waiting a bounded window and then FAILING the stop over
        // that would turn a recycled PID into a loud, permanent, wrong error on
        // a command operators run constantly.
        endpoint_owner_liveness(root, pid).authorizes_cleanup()
    })
}

/// Wait, boundedly, for an endpoint's recorded owner to be affirmatively gone.
///
/// A zero budget probes exactly once, which is what the hygiene paths did before
/// any of this waited.
fn wait_until_retirable(
    kin_root: &Path,
    pid: u32,
    budget: Duration,
    retirable: &mut impl FnMut(&Path, u32) -> bool,
) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if retirable(kin_root, pid) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(
            ENDPOINT_TEARDOWN_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
        );
    }
}

/// Attempt retirement, retrying while the only thing standing in the way is a
/// lock a dead daemon has not finished releasing.
///
/// Waiting for the process to be affirmatively dead is NOT enough, and assuming
/// it was is what left this half of the defect in place. Process death and
/// handle release are two events: on Windows the exited daemon's `daemon.lock`
/// handle outlives the moment `GetExitCodeProcess` reports it gone, so the
/// non-blocking `try_lock_exclusive` still reports contention and retirement is
/// refused for good. Observed in CI as a stop that correctly waited, correctly
/// judged the owner dead, and then preserved the endpoint anyway with
/// "the repository daemon singleton is still held by a current or legacy owner".
///
/// Only the two LOCK outcomes retry. `Changed` must not: a successor published
/// its own endpoint, retrying would race a live daemon's record, and preserving
/// it is the correct answer rather than a delay. `CoordinationUnavailable` must
/// not either, since it reports a real IO failure rather than contention.
///
/// Returns `None` when the endpoint is gone, or the reason it survived.
fn retire_within_budget(kin_root: &Path, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    loop {
        // Re-snapshot each attempt. The comparison inside retirement is against
        // the endpoint as it is NOW, and a record that changed between attempts
        // must be judged as the successor it is rather than against a stale read.
        let judged = daemon_endpoint_snapshot(kin_root);
        let outcome = retire_daemon_endpoint_if_unchanged(kin_root, judged);
        let retryable = matches!(
            outcome,
            DaemonEndpointRetirement::LifecycleContended | DaemonEndpointRetirement::SingletonHeld
        );
        match outcome {
            DaemonEndpointRetirement::Retired => return None,
            preserved => {
                let now = Instant::now();
                if !retryable || now >= deadline {
                    return Some(preserved.preserved_reason());
                }
                std::thread::sleep(
                    ENDPOINT_TEARDOWN_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
                );
            }
        }
    }
}

/// The probe is injectable because the two arms that matter here are decisions,
/// not observations: whether the wait actually retries, and whether a refused
/// cleanup is reported. Both are invisible to a test that can only run against
/// real processes on one platform, and the Windows arm is precisely where the
/// refusal was observed.
fn retire_daemon_endpoint_with_probe(
    kin_root: &Path,
    teardown_budget: Duration,
    mut retirable: impl FnMut(&Path, u32) -> bool,
) -> DaemonEndpointCleanup {
    // Read the pid before the wait so the wait has something to watch, then take
    // the snapshot after it. A dying daemon unlinks its own endpoint on the way
    // out, so a snapshot captured mid-teardown is a torn read, and the
    // unchanged-comparison would then refuse to act on it — preserving the very
    // record this call exists to retire.
    let judged_pid = read_pid_file(kin_root);
    if let Some(pid) = judged_pid {
        wait_until_retirable(kin_root, pid, teardown_budget, &mut retirable);
    }

    let recorded = daemon_endpoint_snapshot(kin_root);
    let preserved_reason = match recorded.pid {
        Some(pid) if retirable(kin_root, pid) => retire_within_budget(kin_root, teardown_budget),
        Some(pid) => {
            warn!(
                pid,
                pid_path = %repo_daemon_pid_path(kin_root).display(),
                "the endpoint record at {} still names pid {pid}, which this machine will not \
                 confirm dead, so kin left it published; if that pid belongs to something else, \
                 remove the file and re-run",
                repo_daemon_pid_path(kin_root).display()
            );
            Some(format!(
                "recorded owner pid {pid} never became affirmatively dead"
            ))
        }
        None if !recorded.pid_exists => retire_within_budget(kin_root, teardown_budget),
        None => {
            warn!(
                pid_path = %repo_daemon_pid_path(kin_root).display(),
                "the endpoint record at {} does not hold a pid kin can read, so kin left it \
                 published rather than retiring an endpoint it cannot identify; remove the file \
                 if no kin daemon is running for this repository",
                repo_daemon_pid_path(kin_root).display()
            );
            Some("its PID record is unparseable".to_string())
        }
    };

    match preserved_reason {
        None => DaemonEndpointCleanup::Retired,
        Some(reason) => classify_preserved_endpoint(kin_root, judged_pid, reason),
    }
}

/// Decide whether a refused retirement actually left the judged endpoint
/// published.
///
/// Only that case is a defect. A record that now names a different daemon is a
/// successor's, and reporting a successor as a failed stop would be a false
/// alarm on a command operators run constantly.
fn classify_preserved_endpoint(
    kin_root: &Path,
    judged_pid: Option<u32>,
    reason: String,
) -> DaemonEndpointCleanup {
    let pid_path = repo_daemon_pid_path(kin_root);
    let current_pid = read_pid_file(kin_root);
    if current_pid.is_none() && !pid_path.exists() {
        // Nothing publishes an endpoint here: another participant retired it
        // while this call was deciding. Nothing was preserved.
        return DaemonEndpointCleanup::Retired;
    }
    match (current_pid, judged_pid) {
        (Some(current), Some(judged)) if current != judged => DaemonEndpointCleanup::Superseded,
        _ => DaemonEndpointCleanup::Preserved(PreservedDaemonEndpoint { pid_path, reason }),
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
    mut remove_file: F,
) -> std::io::Result<()>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let pid_path = repo_daemon_pid_path(kin_root);
    let port_path = repo_daemon_port_path(kin_root);
    // The owner sidecar attributes the endpoint being retired, so it goes with
    // it. It is not part of the retirement verdict: `daemon.pid` is what makes
    // an endpoint published, and a leftover attribution names nothing.
    let _ = remove_file(&repo_daemon_owner_path(kin_root));
    remove_endpoint_files_with(&pid_path, &port_path, remove_file)
}

/// How long a retirement waits out a contended lifecycle lock before reporting
/// it as held.
///
/// One non-blocking `flock` is not evidence that anybody holds this lock. It was
/// observed failing with `EWOULDBLOCK` on a freshly created file that nothing
/// else had ever opened, with `lsof` naming only the caller's own descriptor and
/// an immediate retry on that same descriptor succeeding. A single syscall that
/// can say "contended" about an uncontended lock cannot be the whole test.
///
/// This matters beyond a flaky read, because of what the caller does with the
/// answer: `LifecycleContended` is a preserve-the-endpoint outcome rather than an
/// error, so a spurious refusal silently abandons a legitimate retirement and
/// leaves a stale endpoint behind with nothing reported. The daemon side already
/// reached this conclusion for its own singleton lock and retries within a
/// budget; this is the same rule for the client-side lifecycle lock.
///
/// The window is short because these are brief authority sections, not a daemon
/// handoff. Genuine contention outlives it and is still reported.
const LIFECYCLE_AUTHORITY_RETRY_BUDGET: Duration = Duration::from_millis(250);

const LIFECYCLE_AUTHORITY_RETRY_INTERVAL: Duration = Duration::from_millis(5);

fn try_acquire_daemon_endpoint_authority(kin_root: &Path) -> std::io::Result<File> {
    let authority = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(kin_root.join("daemon.lifecycle"))?;
    let deadline = Instant::now() + LIFECYCLE_AUTHORITY_RETRY_BUDGET;
    loop {
        match authority.try_lock_exclusive() {
            Ok(()) => return Ok(authority),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(error);
                }
                std::thread::sleep(
                    LIFECYCLE_AUTHORITY_RETRY_INTERVAL.min(deadline.saturating_duration_since(now)),
                );
            }
            Err(error) => return Err(error),
        }
    }
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
            debug!(
                judged_pid = ?judged.pid,
                repo = %kin_root.display(),
                "another kin command holds daemon lifecycle authority for this repository, so \
                 this one left the published endpoint alone"
            );
            return DaemonEndpointRetirement::LifecycleContended;
        }
        Err(error) => {
            debug!(
                judged_pid = ?judged.pid,
                repo = %kin_root.display(),
                %error,
                "daemon lifecycle authority could not be taken for this repository, so this \
                 command left the published endpoint alone"
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
        debug!(
            judged_pid = ?judged.pid,
            successor_pid = ?current.pid,
            repo = %kin_root.display(),
            "a successor kin daemon published its own endpoint for this repository while the \
             previous one was being retired; the successor's record is correct and was left intact"
        );
        return DaemonEndpointRetirement::Changed { current };
    }

    after_comparison();

    match singleton.try_lock_exclusive() {
        Ok(()) => {}
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            debug!(
                judged_pid = ?judged.pid,
                repo = %kin_root.display(),
                "the per-repository daemon singleton is still held, so this command left the \
                 published endpoint alone"
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
            debug!(
                judged_pid = ?judged.pid,
                repo = %kin_root.display(),
                %error,
                "the endpoint files for this repository could not be removed, so kin kept its \
                 startup authority rather than leaving a half-retired endpoint"
            );
            DaemonEndpointRetirement::CoordinationUnavailable(error.to_string())
        }
    }
}

fn supervisor_dir() -> PathBuf {
    kin_core::registry::supervisor_root()
}

const SUPERVISOR_PID_FILE: &str = "supervisor.pid";
const SUPERVISOR_PORT_FILE: &str = "supervisor.port";
const SUPERVISOR_OWNER_FILE: &str = "supervisor.owner";
const SUPERVISOR_TOKEN_FILE: &str = "supervisor.token";
const SUPERVISOR_LIFECYCLE_FILE: &str = "supervisor.lifecycle";
const SUPERVISOR_SINGLETON_FILE: &str = "supervisor.lock";
const SUPERVISOR_STARTUP_FILE: &str = "supervisor.start.lock";
const SUPERVISOR_STARTUP_AUTHORITY_FILE: &str = "authority.lock";
const SUPERVISOR_STARTUP_RECORDS_DIR: &str = "records-v2";
const SUPERVISOR_STARTUP_PROTOCOL: u32 = 2;
const SUPERVISOR_STARTUP_CAPABILITY: &str = "generation-adoption-ack-v2";
const SUPERVISOR_LEGACY_SENTINEL_CAPABILITY: &str = "legacy-directory-sentinel-v1";
const SUPERVISOR_BOUNDED_ROLLBACK_CAPABILITY: &str = "bounded-legacy-rollback-v1";
/// Plain-text notice a current launcher leaves inside the startup sentinel.
///
/// The sentinel path is the only channel a current binary has to the operator
/// of a binary too old to speak this protocol: that binary's timeout message
/// names the path, so listing it is the first thing anyone does after the wait.
const SUPERVISOR_STARTUP_NOTICE_FILE: &str = "README-UPDATE-KIN.txt";
/// Canonical one-line install used by every remedy this crate prints.
pub const KIN_INSTALL_COMMAND: &str = "curl -fsSL https://get.kinlab.dev/install | sh";
/// Byte-stable contents of [`SUPERVISOR_STARTUP_NOTICE_FILE`]. Stability is
/// load-bearing: refresh compares before writing, so an unchanged notice never
/// rewrites the file and never touches the sentinel directory's mtime.
const SUPERVISOR_STARTUP_NOTICE: &str = "\
This directory is the Kin supervisor startup sentinel for startup protocol v2.

A kin binary older than protocol v2 cannot start a supervisor while it exists.
Such a binary sleeps until its startup deadline (300 seconds by default,
KIN_DAEMON_READY_TIMEOUT_SECS) and then reports a startup lock timeout that
names lock contention. There is no contention. Nothing holds a lock here, and
no amount of waiting or retrying can succeed, because that binary cannot speak
the protocol this directory requires.

Update kin, then run `kin doctor` to confirm:

    curl -fsSL https://get.kinlab.dev/install | sh

Deleting this directory does not help. A current kin recreates it on the next
command, and an older kin still cannot start a supervisor.
";
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

/// Path to the sidecar attributing the published supervisor endpoint to one
/// process incarnation.
pub fn supervisor_owner_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_OWNER_FILE)
}

/// Read the owner sidecar for the currently configured supervisor directory.
/// Unknown schemas and malformed records fail closed as `None`.
pub fn read_supervisor_owner_record() -> Option<EndpointOwnerRecord> {
    read_supervisor_owner_record_in_dir(&supervisor_dir())
}

fn read_supervisor_owner_record_in_dir(dir: &Path) -> Option<EndpointOwnerRecord> {
    let raw = std::fs::read_to_string(dir.join(SUPERVISOR_OWNER_FILE)).ok()?;
    let record: EndpointOwnerRecord = serde_json::from_str(&raw).ok()?;
    (record.schema == ENDPOINT_OWNER_SCHEMA).then_some(record)
}

/// Resolve the bearer token used by an authenticated local supervisor. An
/// explicit environment override wins; otherwise adopt the already-provisioned
/// per-install token without creating state on a read-only status/stop path.
fn supervisor_auth_token() -> Option<String> {
    std::env::var("KIN_SUPERVISOR_AUTH_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string(supervisor_dir().join(SUPERVISOR_TOKEN_FILE))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
}

/// Remove the supervisor's pid/port endpoint files. Called after a confirmed
/// supervisor stop so a later `status` never reports the dead endpoint as stale.
pub fn remove_stale_supervisor_files() {
    let dir = supervisor_dir();
    let startup_authority = match try_acquire_supervisor_startup_lock_for_cleanup(&dir) {
        Ok(authority) => authority,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            debug!(
                dir = %dir.display(),
                "another kin command holds supervisor startup authority, so this one left the \
                 published supervisor endpoint alone"
            );
            return;
        }
        Err(error) => {
            debug!(
                dir = %dir.display(),
                %error,
                "supervisor startup authority could not be taken, so this command left the \
                 published supervisor endpoint alone"
            );
            return;
        }
    };
    let recorded = supervisor_endpoint_snapshot(&dir);
    let owner_is_gone = match (recorded.pid, recorded.owner.as_ref()) {
        (Some(pid), Some(owner)) if owner.identity().pid() == pid => {
            matches!(process_identity_is_current(owner.identity()), Ok(false))
        }
        (Some(pid), None) if !recorded.owner_exists => {
            // Mixed-version compatibility: old supervisors did not publish an
            // owner record, so affirmative PID death is still enough to retire
            // their stale endpoint. Stop paths never signal from this fallback.
            process_liveness(pid).authorizes_cleanup()
        }
        (None, Some(owner)) if !recorded.pid_exists => {
            matches!(process_identity_is_current(owner.identity()), Ok(false))
        }
        (None, None) if !recorded.pid_exists && !recorded.owner_exists => true,
        _ => false,
    };
    match recorded.pid {
        Some(_) if owner_is_gone => {
            let _ = retire_supervisor_endpoint_if_unchanged(&dir, recorded, &startup_authority);
        }
        Some(_) => {
            debug!(
                pid = ?recorded.pid,
                dir = %dir.display(),
                "the supervisor endpoint still names an owner this machine will not confirm \
                 dead, so kin left it published"
            );
        }
        None if recorded.pid_exists => {
            debug!(
                dir = %dir.display(),
                "the supervisor endpoint still names an owner this machine will not confirm \
                 dead, so kin left it published"
            );
        }
        None if owner_is_gone => {
            let _ = retire_supervisor_endpoint_if_unchanged(&dir, recorded, &startup_authority);
        }
        None => debug!(
            dir = %dir.display(),
            "the supervisor endpoint carries no complete ownership record, so kin left it \
             published rather than retiring an endpoint it cannot identify"
        ),
    }
}

fn try_acquire_supervisor_startup_lock_for_cleanup(
    dir: &Path,
) -> std::io::Result<SupervisorStartupLock> {
    try_acquire_supervisor_startup_lock_in_dir(dir)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupervisorEndpointSnapshot {
    pid: Option<u32>,
    port: Option<u16>,
    owner: Option<EndpointOwnerRecord>,
    pid_exists: bool,
    port_exists: bool,
    owner_exists: bool,
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
        owner: read_supervisor_owner_record_in_dir(dir),
        pid_exists: pid_path.exists(),
        port_exists: port_path.exists(),
        owner_exists: dir.join(SUPERVISOR_OWNER_FILE).exists(),
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
    match remove_supervisor_endpoint_files_with(dir, remove_file) {
        Ok(()) => SupervisorEndpointRetirement::Retired,
        Err(error) => {
            debug!(
                judged_pid = ?judged.pid,
                dir = %dir.display(),
                %error,
                "the supervisor endpoint files could not be removed, so kin kept its startup \
                 authority rather than leaving a half-retired endpoint"
            );
            SupervisorEndpointRetirement::CoordinationUnavailable(error.to_string())
        }
    }
}

fn remove_supervisor_endpoint_files_with<F>(dir: &Path, mut remove_file: F) -> std::io::Result<()>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let owner_path = dir.join(SUPERVISOR_OWNER_FILE);
    let mut owner_failure = None;
    if let Err(error) = remove_file(&owner_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            owner_failure = Some(format!("remove {}: {error}", owner_path.display()));
        }
    }
    let endpoint_result = remove_endpoint_files_with(
        &dir.join(SUPERVISOR_PID_FILE),
        &dir.join(SUPERVISOR_PORT_FILE),
        |path| remove_file(path),
    );
    match std::fs::symlink_metadata(&owner_path) {
        Ok(_) => {
            owner_failure.get_or_insert_with(|| {
                format!(
                    "endpoint owner component {} still exists after retirement",
                    owner_path.display()
                )
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            owner_failure.get_or_insert_with(|| {
                format!("verify retirement of {}: {error}", owner_path.display())
            });
        }
    }
    match (owner_failure, endpoint_result) {
        (None, Ok(())) => Ok(()),
        (owner, endpoint) => {
            let mut failures = Vec::new();
            if let Some(owner) = owner {
                failures.push(owner);
            }
            if let Err(error) = endpoint {
                failures.push(error.to_string());
            }
            Err(std::io::Error::other(failures.join("; ")))
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

/// One line saying how far a starting repo daemon has come, read from its
/// recorded lifecycle markers alone: the daemon writes `daemon.pid` when its
/// process comes up and `daemon.port` only once it is listening.
///
/// This is the phase string the MCP answer-early path (FIR-2316) folds into
/// its honest still-starting `tools/call` answer. It lives here, in the
/// declared daemon-lifecycle IO boundary, because the transport crate and the
/// `kin mcp` launcher deliberately carry no filesystem primitive at all; they
/// receive this as an injected probe.
pub fn daemon_startup_phase(kin_root: &Path) -> &'static str {
    match repo_daemon_recorded_endpoint(kin_root) {
        (_, Some(_)) => "phase: the daemon is listening and finishing readiness checks",
        (Some(_), None) => "phase: the daemon process is up and loading the repository graph",
        (None, None) => "phase: resolving or spawning the repo daemon process",
    }
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

/// `probe` is the *legacy* arm: it decides only for an endpoint published with
/// no owner record beside it. An attributed endpoint is judged against the
/// recorded incarnation, because that is the only reading that survives PID
/// reuse.
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
    // Read attribution *after* the endpoint it attributes, which is the order
    // that can only ever make this more conservative. Publication installs the
    // owner record before the PID file, so a snapshot showing a successor's
    // endpoint is always accompanied by a readable successor record; reading
    // the record first would instead pair a predecessor's dead identity with a
    // successor's live endpoint, and the compare-and-retire below would then
    // find the successor's files unchanged and delete them.
    if endpoint_owner_liveness_with_probes(kin_root, pid, process_identity_is_current, probe)
        .authorizes_cleanup()
    {
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
        match probe_process::output_with_timeout(command, &label, DAEMON_BINARY_PROBE_TIMEOUT) {
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
    let output = probe_process::output_with_timeout(command, &label, DAEMON_BINARY_PROBE_TIMEOUT)
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

#[cfg(windows)]
const DAEMON_BINARY_FILE_NAME: &str = "kin-daemon.exe";
#[cfg(not(windows))]
const DAEMON_BINARY_FILE_NAME: &str = "kin-daemon";

fn daemon_binary_candidates_for_executable(exe: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![exe.with_file_name(DAEMON_BINARY_FILE_NAME)];
    if exe
        .parent()
        .and_then(|path| path.file_name())
        .is_some_and(|name| name == "deps")
    {
        if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
            candidates.push(target_dir.join(DAEMON_BINARY_FILE_NAME));
        }
    }
    candidates
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
        for candidate in daemon_binary_candidates_for_executable(&exe) {
            if let Some(path) = consider(candidate) {
                return Ok(path);
            }
        }
    }
    if let Ok(path) = which::which(DAEMON_BINARY_FILE_NAME) {
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

/// The idle window a spawn takes when nothing about a particular store applies:
/// the supervisor, and any unit-test build that must not keep a daemon alive.
fn default_idle_timeout_secs() -> String {
    if cfg!(test) {
        "1".to_string()
    } else {
        kin_daemon_spawn::CLI_IDLE_FLOOR_SECS.to_string()
    }
}

/// The idle window a CLI spawn gives a repo daemon, sized against what opening
/// THAT store last cost.
///
/// A fixed window cannot be right for every store: the same 60 seconds that is
/// generous for a small repository is shorter than a converted repository's own
/// cold start, so the daemon expires between two commands and the next command
/// pays the whole open again. Sizing the window against the measured cost makes
/// the window at least as long as the thing it would otherwise force a caller
/// to repeat. The store's record is written by the daemon that paid the cost;
/// see [`kin_daemon_spawn::cli_idle_window`] for the floor and the ceiling.
fn store_idle_timeout_secs(kin_root: &Path) -> String {
    if cfg!(test) {
        return "1".to_string();
    }
    kin_daemon_spawn::cli_idle_window_for_store(kin_root)
        .secs
        .to_string()
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
/// otherwise the window this store's own recorded open cost asks for (1 s in
/// unit-test builds, which must never leave a daemon behind).
///
/// `store_window` is passed in rather than read here so the assembly logic is
/// unit-testable without a store on disk.
fn resolve_idle_timeout_env(
    user_env_is_set: bool,
    caller_override: Option<&str>,
    store_window: &str,
) -> Option<String> {
    if user_env_is_set {
        return None;
    }
    Some(match caller_override {
        Some(value) => value.to_string(),
        None => store_window.to_string(),
    })
}

/// The idle window a caller must carry to a daemon it did not start, in
/// seconds, or `None` when there is nothing to carry.
///
/// Injecting an idle timeout only works on the path that spawns the daemon.
/// Every attach path — a supervisor route, a live repo-local endpoint — hands
/// back a process whose window was fixed by whoever started it, which on a
/// developer machine is almost always an ordinary CLI command taking the short
/// CLI default. An MCP session that attached there inherited 60 seconds and had
/// the daemon expire underneath it between tool calls. A caller with a stated
/// need has to say so to the daemon it actually got.
///
/// `None` means the caller stated no need of its own and is content with
/// whatever the daemon is running, which is the pre-existing behavior for every
/// ordinary CLI command. A user's explicit `KIN_DAEMON_IDLE_TIMEOUT_SECS` is
/// their decision about this host and is never overridden from here.
fn idle_timeout_to_carry(caller_override: Option<&str>, user_env_is_set: bool) -> Option<u64> {
    if user_env_is_set {
        return None;
    }
    caller_override?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs > 0)
}

/// Attach this command to a daemon it did not start.
///
/// Two things are true at exactly this moment and nowhere else: the daemon's
/// idle window was chosen without this session's needs in mind, and every
/// behavior lever this command carries was already decided by whichever command
/// started that daemon. Both are stated here so no caller can take the endpoint
/// and skip one.
async fn attach_to_existing_daemon(
    base_url: &str,
    idle_timeout_override: Option<&'static str>,
) -> std::result::Result<(), AutoStartError> {
    carry_idle_timeout_to_existing_daemon(base_url, idle_timeout_override).await;
    report_behavior_env_ignored_by_existing_daemon(base_url).await
}

/// Say so when this command sets behavior levers the attached daemon cannot
/// honor, instead of letting them be dropped in silence.
///
/// `KIN_DAEMON_AUTO_EMBED` is the case this exists for. An operator sets the
/// opt-out, the store opens against a daemon that started without it, the
/// background embedding pass runs anyway, and the only evidence is the machine
/// getting busy — a rejected opt-out and an honored one look identical from
/// outside. The daemon reports what it is running under, so the mismatch is
/// observable, and attaching is the moment it becomes true.
///
/// Free on the ordinary path: a command that set no behavior variable sends no
/// request. That guard also scopes this to levers *this* command stated; the
/// reverse direction (a daemon carrying a lever this command did not set) stays
/// with the per-command checks, which are already paying for a health read.
///
/// Best-effort otherwise: an unreachable daemon or one predating the surface is
/// silence here, because the command's own request will report a genuine
/// connectivity failure and reporting it twice names one fault as two.
async fn report_behavior_env_ignored_by_existing_daemon(
    base_url: &str,
) -> std::result::Result<(), AutoStartError> {
    let cli = kin_core::behavior_env::snapshot_from_process();
    if !states_a_behavior_lever(&cli) {
        return Ok(());
    }
    let Some(daemon) = fetch_daemon_behavior_env(base_url).await else {
        return Ok(());
    };
    let divergences = kin_core::behavior_env::compare(&cli, &daemon);
    report_behavior_env_divergence(
        &divergences,
        is_transient_bool_env("KIN_STRICT_BEHAVIOR_ENV"),
    )
    .map_err(|error| AutoStartError::BehaviorEnvIgnored(format!("{error}")))
}

/// Whether this command stated a behavior lever at all, which is what decides
/// if the attach check is worth a request.
///
/// A value that is empty after trimming states nothing: the read sites treat it
/// as unset, so asking the daemon about it could only ever produce agreement.
fn states_a_behavior_lever(cli: &kin_core::behavior_env::BehaviorEnv) -> bool {
    cli.values()
        .any(|value| !value.as_deref().unwrap_or_default().trim().is_empty())
}

/// Read the behavior-env surface an already-running daemon reports, or `None`
/// when it cannot be read at all. A daemon predating the surface answers with an
/// empty map, which yields no divergence rather than a false one.
async fn fetch_daemon_behavior_env(base_url: &str) -> Option<kin_core::behavior_env::BehaviorEnv> {
    let mut request =
        daemon_health_client().get(format!("{}/health", base_url.trim_end_matches('/')));
    if let Some(token) = resolve_daemon_auth_token() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response
        .json::<HealthResponse>()
        .await
        .ok()
        .map(|health| health.behavior_env)
}

/// Tell a daemon this process did not start what idle window its session needs.
///
/// Best-effort by construction: an older daemon has no such route, and a
/// refusal here must never turn a working attach into a failed one. What it
/// must not do is fail silently, so a daemon that declines to grow its window
/// says so on stderr rather than leaving the caller believing its stated need
/// was honoured.
async fn carry_idle_timeout_to_existing_daemon(
    base_url: &str,
    caller_override: Option<&'static str>,
) {
    let user_timeout_set = std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_some();
    let Some(at_least_secs) = idle_timeout_to_carry(caller_override, user_timeout_set) else {
        return;
    };
    let mut request = daemon_health_client()
        .post(format!("{}/idle-timeout", base_url.trim_end_matches('/')))
        .json(&serde_json::json!({
            "at_least_secs": at_least_secs,
            "client": "kin mcp",
        }));
    if let Some(token) = resolve_daemon_auth_token() {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let effective = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|body| body.get("effective_secs")?.as_u64());
            match effective {
                Some(effective) if effective >= at_least_secs => {
                    info!(
                        requested_secs = at_least_secs,
                        effective_secs = effective,
                        "attached daemon idle window covers this session"
                    );
                }
                Some(effective) => eprintln!(
                    "Kin: this session needs the repo daemon to survive {at_least_secs}s idle, \
                     but its window is {effective}s; it may exit mid-session. Set \
                     KIN_DAEMON_IDLE_TIMEOUT_SECS={at_least_secs} and restart the daemon."
                ),
                None => eprintln!(
                    "Kin: the repo daemon accepted a {at_least_secs}s idle window request but \
                     reported no effective window; it may exit mid-session."
                ),
            }
        }
        Ok(response) => eprintln!(
            "Kin: the repo daemon refused a {at_least_secs}s idle window request ({}); it may \
             exit mid-session. Set KIN_DAEMON_IDLE_TIMEOUT_SECS={at_least_secs} and restart it.",
            response.status()
        ),
        Err(error) => eprintln!(
            "Kin: could not ask the repo daemon for a {at_least_secs}s idle window ({error}); it \
             may exit mid-session."
        ),
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
             continuing to use it. Run `kin doctor` for details."
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

/// Leave the protocol-upgrade notice inside the startup sentinel.
///
/// Written only when the bytes differ, so a refresh is a no-op rather than a
/// rewrite, and before the sentinel is stamped, so namespace setup never hands
/// back an aged compatibility stamp.
///
/// That ordering is hygiene, not the mechanism. What actually keeps the stamp
/// safe is that every acquisition re-stamps the sentinel and fails closed
/// unless the timestamp reads back in the future, so any dir-mtime bump taken
/// while the namespace is built is repaired before a caller holds the lock.
fn refresh_supervisor_startup_notice(sentinel: &Path) -> std::io::Result<()> {
    let path = sentinel.join(SUPERVISOR_STARTUP_NOTICE_FILE);
    let mut file = open_startup_regular_file(&path, true, false, true)?;
    let mut existing = String::new();
    file.read_to_string(&mut existing)?;
    if existing == SUPERVISOR_STARTUP_NOTICE {
        return Ok(());
    }
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(SUPERVISOR_STARTUP_NOTICE.as_bytes())?;
    file.flush()
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
    // The notice is an operator aid, not a protocol element. A filesystem that
    // refuses it must not take startup down with it, so the failure is reported
    // and startup continues rather than being swallowed or fatal.
    if let Err(error) = refresh_supervisor_startup_notice(&sentinel) {
        warn!(
            sentinel = %sentinel.display(),
            %error,
            "could not leave the supervisor startup protocol notice; startup continues without it"
        );
    }
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
                    debug!(
                        path = %path.display(),
                        "cleared a startup lock left by an interrupted kin command"
                    );
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if Instant::now() >= deadline {
                    bail!(
                        "timed out waiting for daemon startup lock at {} after {}s: another kin \
                         command in this repository still holds it. Wait for it to finish, or \
                         raise KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS (it defaults from \
                         KIN_DAEMON_READY_TIMEOUT_SECS) to wait longer.",
                        path.display(),
                        timeout.as_secs()
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

/// Why a supervisor startup-lock wait reached its deadline.
///
/// The old message named lock contention unconditionally. Contention is only one
/// of the states this deadline is reachable from, and asserting it sends the
/// caller looking for a competing launcher that may no longer exist, or never
/// did. Each cause below is named only from evidence that distinguishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorStartupTimeoutCause {
    /// A live launcher holds the kernel authority lock. The kernel releases an
    /// `flock` when its holder dies, so a contended lock is proof of a live
    /// holder: this is the only cause that is genuine contention.
    Contention,
    /// Nothing holds the lock, no supervisor is running, and the sentinel is
    /// the protocol-v2 directory carrying its deliberate far-future stamp. That
    /// is exactly the state a pre-v2 launcher waits out in silence.
    LegacyProtocolExclusion,
    /// Neither of the above: startup is slower than this caller's patience.
    SlowStartup,
}

/// Probed state behind a startup-lock timeout, kept separate from the
/// classification so the three-way distinction is testable without racing a
/// live filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SupervisorStartupTimeoutState {
    /// `None` where the probe could not decide. A filesystem whose `flock` is
    /// unsupported or emulated answers that way on every attempt, and reading
    /// it as "not held" would convert "contention cannot be observed here" into
    /// "there is no contention".
    authority_held: Option<bool>,
    sentinel_is_protocol_directory: bool,
    sentinel_stamp_is_future: bool,
    supervisor_may_be_alive: bool,
}

fn classify_supervisor_startup_timeout(
    state: SupervisorStartupTimeoutState,
) -> SupervisorStartupTimeoutCause {
    match state.authority_held {
        Some(true) => return SupervisorStartupTimeoutCause::Contention,
        // An undecidable probe is not evidence of absence, so it falls through
        // to the classifier's safe default rather than to a diagnosis that
        // tells the caller their binary is the problem.
        None => return SupervisorStartupTimeoutCause::SlowStartup,
        Some(false) => {}
    }
    // A future stamp exists only where a current launcher set and read one back,
    // so it also stands in for a well-formed v2 namespace: without it this falls
    // through to the plain slow-startup wording rather than guessing.
    if state.sentinel_is_protocol_directory
        && state.sentinel_stamp_is_future
        && !state.supervisor_may_be_alive
    {
        return SupervisorStartupTimeoutCause::LegacyProtocolExclusion;
    }
    SupervisorStartupTimeoutCause::SlowStartup
}

fn probe_supervisor_startup_timeout_state(dir: &Path) -> SupervisorStartupTimeoutState {
    let sentinel = dir.join(SUPERVISOR_STARTUP_FILE);
    let sentinel_is_protocol_directory = std::fs::symlink_metadata(&sentinel)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false);
    let sentinel_stamp_is_future = std::fs::symlink_metadata(&sentinel)
        .and_then(|metadata| metadata.modified())
        .map(|modified| modified.elapsed().is_err())
        .unwrap_or(false);
    let recorded = supervisor_endpoint_snapshot(dir);
    SupervisorStartupTimeoutState {
        authority_held: supervisor_startup_authority_is_held(&sentinel).ok(),
        sentinel_is_protocol_directory,
        sentinel_stamp_is_future,
        supervisor_may_be_alive: recorded
            .pid
            .map(|pid| process_liveness(pid).may_be_alive())
            .unwrap_or(recorded.pid_exists),
    }
}

/// Render a startup-lock timeout so the caller is pointed at the real cause.
///
/// Every branch names `KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS` and the
/// `KIN_DAEMON_READY_TIMEOUT_SECS` it defaults from, because a timeout whose
/// bound is unnamed cannot be raised by the person hitting it.
fn supervisor_startup_timeout_message(
    path: &Path,
    waited_secs: u64,
    cause: SupervisorStartupTimeoutCause,
) -> String {
    let path = path.display();
    let knob = "raise KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS (it defaults from \
                KIN_DAEMON_READY_TIMEOUT_SECS) to wait longer";
    match cause {
        SupervisorStartupTimeoutCause::Contention => format!(
            "timed out waiting for supervisor startup lock at {path} after {waited_secs}s: \
             another kin launcher holds supervisor startup authority and is still alive, so this \
             is real contention. Wait for it to finish, or stop it with `kin daemon stop`; {knob}."
        ),
        SupervisorStartupTimeoutCause::LegacyProtocolExclusion => format!(
            "timed out waiting for supervisor startup lock at {path} after {waited_secs}s, but \
             nothing holds that lock and no supervisor is running, so this is not contention. \
             {path} is the startup protocol v{SUPERVISOR_STARTUP_PROTOCOL} sentinel: a directory \
             carrying a deliberate far-future timestamp. A kin binary older than protocol \
             v{SUPERVISOR_STARTUP_PROTOCOL} cannot start a supervisor while it exists and waits \
             out this same deadline in silence instead of failing. If an older kin is installed \
             on this host, update it with `{KIN_INSTALL_COMMAND}` and run `kin doctor`; {knob} if \
             startup is merely slow."
        ),
        SupervisorStartupTimeoutCause::SlowStartup => format!(
            "timed out waiting for supervisor startup lock at {path} after {waited_secs}s: \
             supervisor startup did not complete inside this deadline. Run `kin doctor` and check \
             the supervisor log; {knob}."
        ),
    }
}

async fn acquire_supervisor_startup_lock() -> Result<SupervisorStartupAcquisition> {
    let dir = supervisor_dir();
    acquire_supervisor_startup_lock_in_dir_with_timeout(
        &dir,
        Duration::from_secs(startup_lock_timeout_secs()),
    )
    .await
}

/// Startup protocol this binary speaks, for diagnostics that report it.
pub fn supervisor_startup_protocol() -> u32 {
    SUPERVISOR_STARTUP_PROTOCOL
}

/// Path of the per-user supervisor startup sentinel.
pub fn supervisor_startup_sentinel_path() -> PathBuf {
    supervisor_dir().join(SUPERVISOR_STARTUP_FILE)
}

/// What the shared startup sentinel looks like to a diagnostic caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorStartupSentinel {
    /// Nothing on disk: no launcher has run against this Kin home yet.
    Absent,
    /// The current protocol's permanent directory. A binary older than the
    /// current protocol cannot start a supervisor while it exists.
    ProtocolDirectory,
    /// A protocol-v1 marker file, which only a pre-v2 launcher creates. Its
    /// presence is proof that a binary too old for this protocol ran here.
    LegacyMarker,
    /// A symlink, or on Windows a reparse point, where the sentinel belongs.
    /// The startup protocol refuses to follow one, so no supervisor can start
    /// against this Kin home until it is replaced by an ordinary directory.
    RefusedLink,
    /// Present, but its metadata could not be read, so nothing is claimed
    /// either way about whether a supervisor could start here.
    Unreadable,
}

/// Classify the shared startup sentinel without taking any authority.
pub fn supervisor_startup_sentinel() -> SupervisorStartupSentinel {
    supervisor_startup_sentinel_in_dir(&supervisor_dir())
}

/// Classify the startup sentinel under an explicit supervisor directory.
///
/// Split out so a test can point at a temporary directory by argument. Reaching
/// the same behavior by setting the registry-path variable would mutate
/// process-global state that every other test in the binary shares, which under
/// `cargo test` (threads in one process, unlike nextest's process per test) is
/// visible to unrelated tests resolving the Kin home.
fn supervisor_startup_sentinel_in_dir(dir: &Path) -> SupervisorStartupSentinel {
    match std::fs::symlink_metadata(dir.join(SUPERVISOR_STARTUP_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            SupervisorStartupSentinel::Absent
        }
        Err(_) => SupervisorStartupSentinel::Unreadable,
        // Deliberately the same predicate `ensure_supervisor_startup_namespace`
        // refuses on, so a state that hard-blocks supervisor startup can never
        // be reported as one startup would accept.
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || startup_metadata_is_reparse_point(&metadata) =>
        {
            SupervisorStartupSentinel::RefusedLink
        }
        Ok(metadata) if metadata.is_dir() => SupervisorStartupSentinel::ProtocolDirectory,
        Ok(_) => SupervisorStartupSentinel::LegacyMarker,
    }
}

/// Verdict on whether some other installed kin speaks the current startup
/// protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledStartupProtocol {
    /// The install acknowledges the current supervisor startup protocol.
    Current,
    /// The install answers, and its answer proves it predates the current
    /// protocol. The string is the exact mismatch, for the operator.
    Predates(String),
    /// No answer could be obtained, so nothing is claimed either way.
    Undetermined(String),
}

/// Installed kin binaries on this host that are not the running one.
///
/// Candidates are whatever `PATH` resolves for `kin`, plus the Kin home's
/// `bin`. That is deliberately the set an operator actually invokes rather than
/// a filtered notion of an install: `PATH` is what decides which binary runs, so
/// a build tree reachable through it is probed like any other install and
/// diagnosed on the same evidence. Paths are canonicalized so one binary
/// reachable by two names is probed once, and so the running binary is excluded
/// even when it was invoked through a symlink.
fn other_installed_kin_binaries() -> Vec<PathBuf> {
    let running = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok());
    let mut candidates = Vec::new();
    if let Some(path) = crate::commands::setup::check_binary_in_path("kin") {
        candidates.push(path);
    }
    if let Ok(home) = crate::commands::setup::kin_dir() {
        candidates.push(home.join("bin").join("kin"));
    }

    let mut found: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        let Ok(resolved) = candidate.canonicalize() else {
            continue;
        };
        if running.as_ref() == Some(&resolved) || found.contains(&resolved) {
            continue;
        }
        found.push(resolved);
    }
    found
}

/// Every installed kin other than the running one, with its probed verdict on
/// the supervisor startup protocol.
///
/// Enumeration and probing both live here rather than in the health reporter,
/// because this module is the declared process and install boundary: resolving
/// installed binaries is boundary IO, and a diagnostic surface should consume
/// the verdict rather than reach for the filesystem to compute it.
pub fn installed_kin_startup_protocols() -> Vec<(PathBuf, InstalledStartupProtocol)> {
    other_installed_kin_binaries()
        .into_iter()
        .map(|path| {
            let protocol = probe_installed_startup_protocol(&path);
            (path, protocol)
        })
        .collect()
}

/// Ask an installed kin whether it speaks the current supervisor startup
/// protocol, by probing the `kin-daemon` shipped beside it.
///
/// The CLI has no protocol probe of its own; the daemon's `--compat-json` does,
/// and an install ships and version-locks the two together, so the daemon's
/// answer is the available proof. A pre-v2 install answers with the v1 compat
/// schema and no supervisor protocol field at all, which is a positive
/// discriminator rather than an absence of evidence.
pub fn probe_installed_startup_protocol(kin_binary: &Path) -> InstalledStartupProtocol {
    let daemon = kin_binary.with_file_name(DAEMON_BINARY_FILE_NAME);
    if !daemon.is_file() {
        return InstalledStartupProtocol::Undetermined(format!(
            "no kin-daemon beside {}",
            kin_binary.display()
        ));
    }
    let mut command = Command::new(&daemon);
    command.arg("--compat-json");
    let label = format!("{} --compat-json", daemon.display());
    let output =
        match probe_process::output_with_timeout(command, &label, DAEMON_BINARY_PROBE_TIMEOUT) {
            Ok(output) if output.status.success() => output,
            Ok(output) => {
                // A binary predating the flag itself exits non-zero on it. That
                // is consistent with age but is not the protocol's own answer,
                // so it is reported as undetermined rather than asserted.
                return InstalledStartupProtocol::Undetermined(format!(
                    "compat probe exited with {} ({})",
                    output.status,
                    compact_probe_output(&output)
                ));
            }
            Err(error) => {
                return InstalledStartupProtocol::Undetermined(format!(
                    "compat probe failed to execute: {error}"
                ))
            }
        };
    let compat: DaemonCompatResponse = match serde_json::from_slice(&output.stdout) {
        Ok(compat) => compat,
        Err(error) => {
            return InstalledStartupProtocol::Undetermined(format!(
                "compat probe returned invalid JSON: {error}"
            ))
        }
    };
    match compat.supervisor_startup_protocol {
        Some(SUPERVISOR_STARTUP_PROTOCOL) => InstalledStartupProtocol::Current,
        Some(protocol) => InstalledStartupProtocol::Predates(format!(
            "it reports supervisor startup protocol v{protocol}, not \
             v{SUPERVISOR_STARTUP_PROTOCOL}"
        )),
        None => InstalledStartupProtocol::Predates(format!(
            "it reports compat schema {} and no supervisor startup protocol at all",
            if compat.schema.is_empty() {
                "<none>"
            } else {
                &compat.schema
            }
        )),
    }
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
                    bail!(supervisor_startup_timeout_message(
                        &path,
                        timeout.as_secs(),
                        classify_supervisor_startup_timeout(
                            probe_supervisor_startup_timeout_state(dir)
                        ),
                    ));
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
        // Judged against the recorded incarnation, not the bare PID. `Invalid`
        // authorizes the caller to clear this endpoint and respawn, so it needs
        // positive evidence of death; a recycled PID that merely *exists* is
        // not a live daemon, and treating it as one is what left autostart
        // reporting LiveNotReady forever with nothing able to clear the record.
        let owner = endpoint_owner_liveness(kin_root, endpoint.pid);
        if owner.authorizes_cleanup() {
            return EndpointVerdict::Invalid(if owner.identity_verified() {
                format!(
                    "the daemon that published this endpoint is gone; pid {} now names \
                     a different process",
                    endpoint.pid
                )
            } else {
                format!("recorded daemon process {} is not alive", endpoint.pid)
            });
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
        "waited {:.1}s: {}; {}; raise KIN_DAEMON_READY_TIMEOUT_SECS if this repository needs \
         longer to load; recent log:\n{}",
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
///
/// It also names what the wait is for. A silent daemon is not idle: it is
/// running the blocking load that `DaemonState::open` performs before any
/// listener binds, so there is no endpoint to ask and the only honest account
/// of the delay is what that load consists of. Reporting the elapsed timeout
/// alone told a waiting user the one number that does not explain the wait,
/// because the cost tracks repository size rather than the budget. The daemon
/// records each phase's real cost for this repository once it is up, which is
/// a truthful per-repository number where a hardcoded typical would not be.
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
         {detail}. Startup loads this repository before it binds a port: it opens the repository \
         authority, materializes the workspace graph, then restores the text and vector indexes. \
         That cost scales with repository size rather than with this timeout, and \
         `.kin/daemon.log` records what each phase took. It is running, so kin will not replace \
         it. Wait for it to finish, or stop it with `kin daemon stop`; raise \
         KIN_DAEMON_READY_TIMEOUT_SECS if this repo needs longer."
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
                     complete within {}s: {detail}. Kin will not start a second supervisor; raise \
                     KIN_DAEMON_READY_TIMEOUT_SECS to wait longer",
                    timeout.as_secs()
                ));
            }
            resolved => return resolved,
        }
    }
}

fn supervisor_log_path() -> PathBuf {
    supervisor_dir().join("supervisor.log")
}

fn supervisor_log_len() -> u64 {
    std::fs::metadata(supervisor_log_path())
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

/// Render the supervisor output produced by this start attempt only, mirroring
/// [`daemon_log_tail_since`]. The exit status of a supervisor that died on
/// launch is a symptom; the reason is in this log and was previously never read.
fn supervisor_log_tail_since(since_offset: u64) -> String {
    let path = supervisor_log_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return format!("supervisor log unavailable at {}", path.display());
    };
    let fresh = content
        .get(since_offset as usize..)
        .unwrap_or(&content)
        .trim();
    if fresh.is_empty() {
        return format!(
            "no fresh supervisor output captured for this start attempt at {}",
            path.display()
        );
    }
    let lines: Vec<&str> = fresh.lines().rev().take(20).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn open_supervisor_log() -> Result<File> {
    let dir = supervisor_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create supervisor state directory {}", dir.display()))?;
    let log_path = supervisor_log_path();
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
    log_offset: u64,
) -> Result<String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let client = daemon_health_client();
    let mut last_error = String::from("supervisor did not report its port");
    let mut next_startup_heartbeat = Instant::now();

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().context("check supervisor child status")? {
            bail!(
                "the kin supervisor exited during startup with status {status}; recent log from \
                 {}:\n{}",
                supervisor_log_path().display(),
                supervisor_log_tail_since(log_offset)
            );
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
        "supervisor failed to become ready within {:.1}s: {}. Raise \
         KIN_DAEMON_READY_TIMEOUT_SECS if this host needs longer, and check the supervisor log \
         under the Kin registry directory.",
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

    // Everything past this point is spawn authority. `KIN_NO_DAEMON` is the
    // process-wide no-spawn contract (the probe mode behind `kin mcp start
    // --no-spawn` and the update watchdog's checks), and every caller that
    // honors it gates earlier, so reaching here under it is already a bug;
    // refusing here makes the invariant hold at the chokepoint instead of at
    // each caller. An already-running supervisor was returned above, so this
    // refusal costs a probe nothing it was entitled to.
    if is_transient_bool_env("KIN_NO_DAEMON") {
        bail!(
            "KIN_NO_DAEMON is set and no supervisor is running, so none may be started; unset \
             KIN_NO_DAEMON (or drop --no-spawn) to let kin start one"
        );
    }

    // Validate the binary's explicit protocol acknowledgement before taking
    // cleanup or spawn authority. In particular, an immutable base daemon is
    // rejected here and is never started under a marker it cannot adopt.
    let daemon_bin = find_daemon_binary()?;
    // Lock order is install lease -> supervisor startup authority, matching
    // full uninstall (exclusive install lease -> startup authority). Taking
    // these in the opposite order would deadlock a spawn racing uninstall.
    let _install_spawn_fence =
        crate::commands::update::InstallSpawnFence::acquire_for_daemon_binary(&daemon_bin)?;
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
    let log_offset = supervisor_log_len();
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
    let base_url =
        wait_for_supervisor_ready(&mut child, deadline, &mut startup_authority, log_offset).await?;
    if let Err(error) = startup_authority.verify_adoption(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context(
            "supervisor became healthy without acknowledging the exact startup generation",
        );
    }
    // A supervisor is the same binary under `--supervisor`, so an unreaped one
    // prints as `[kin-daemon] <defunct>` exactly like a repo daemon does.
    kin_daemon_spawn::adopt_detached_daemon_child(child);
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

    /// The route `kin doctor`'s `daemon_running` check reports from, verbatim.
    ///
    /// Sharing the function rather than reimplementing the lookup is the whole
    /// point: MCP and `kin doctor` can no longer answer opposite things about
    /// the same repository at the same instant, because there is only one
    /// answer to give.
    fn route_if_running(
        &self,
        kin_root: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>> {
        Box::pin(
            async move { resolve_daemon_url_if_running_async(&KinLayout::new(kin_root)).await },
        )
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
    refuse_incompatible_store(kin_root)?;
    install_spawn_registrar();
    let supervisor_url = ensure_supervisor_running()
        .await
        .map_err(map_supervisor_auto_start_error)?;
    if let Some(base_url) = supervisor_route_for_repo(kin_root, &supervisor_url).await {
        attach_to_existing_daemon(&base_url, idle_timeout_override).await?;
        return Ok(base_url);
    }

    match wait_for_existing_daemon(kin_root).await {
        ExistingDaemon::Connected(base_url) => {
            register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
                .await
                .map_err(AutoStartError::spawn)?;
            attach_to_existing_daemon(&base_url, idle_timeout_override).await?;
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
        attach_to_existing_daemon(&base_url, idle_timeout_override).await?;
        return Ok(base_url);
    }
    match wait_for_existing_daemon(kin_root).await {
        ExistingDaemon::Connected(base_url) => {
            register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
                .await
                .map_err(AutoStartError::spawn)?;
            attach_to_existing_daemon(&base_url, idle_timeout_override).await?;
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
    let _install_spawn_fence =
        crate::commands::update::InstallSpawnFence::acquire_for_daemon_binary(&daemon_bin)
            .map_err(AutoStartError::spawn)?;
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
    let store_window = store_idle_timeout_secs(kin_root);
    let plan = kin_daemon_spawn::DaemonSpawnPlan {
        daemon_bin,
        working_dir: working_dir.to_path_buf(),
        idle_timeout_secs: resolve_idle_timeout_env(
            user_timeout_set,
            idle_timeout_override,
            &store_window,
        ),
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

    // Opened before the spawn: attributing a kill to memory needs the kernel's
    // counter from before this daemon existed, not one read after it died.
    let watch = kin_daemon_spawn::DaemonWatch::begin(kin_root);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn kin-daemon for {}", working_dir.display()))
        .map_err(AutoStartError::spawn)?;

    let timeout_secs = daemon_ready_timeout_secs();
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let readiness = wait_for_daemon_ready(kin_root, &mut child, deadline, log_offset).await;
    // The daemon outlives this call either way, and this process may outlive the
    // daemon: `kin mcp start` reaches here for a whole agent session. Dropping
    // the handle waits on nothing, so hand it to the reaper before the borrow
    // ends rather than leaving a corpse behind for the session's duration.
    kin_daemon_spawn::adopt_watched_daemon_child(child, watch);
    let base_url = readiness.map_err(|error| match error {
        DaemonReadinessError::Failed(error) => AutoStartError::spawn(format!("{error:#}")),
        DaemonReadinessError::Timeout(detail) => AutoStartError::StartupTimeout(detail),
    })?;
    register_repo_daemon_with_supervisor(kin_root, &base_url, &supervisor_url)
        .await
        .map_err(AutoStartError::spawn)?;
    // A death note explains the outage that made this spawn necessary, and
    // nothing after it. Left in place it would be quoted as the cause of the
    // next unrelated transport failure.
    kin_daemon_spawn::clear_daemon_death_note(kin_root);
    info!(daemon = %base_url, "daemon is up and ready");
    Ok(base_url)
}

/// Refuse a `.kin/` store this build cannot serve before anything is spawned.
///
/// The daemon holds the same gate, but reaching it costs a supervisor, a binary
/// probe and a daemon process that all exist only to die, and it turns the
/// answer into a line quoted out of a log tail underneath "kin daemon is
/// required". Checking the on-disk marker here is one file read and it makes the
/// version gap the thing the reader is told.
///
/// Only the version gap is answered here. Any other failure to read the marker
/// is recorded and left to the daemon, whose gate sees the same file.
fn refuse_incompatible_store(kin_root: &Path) -> std::result::Result<(), AutoStartError> {
    match kin_core::KinLayout::new(kin_root.to_path_buf()).check_version() {
        Ok(()) => Ok(()),
        Err(error @ kin_core::KinError::IncompatibleVersion { .. }) => {
            Err(AutoStartError::IncompatibleStore(
                crate::commands::incompatible_store_refusal(kin_root, &error),
            ))
        }
        Err(error) => {
            tracing::debug!(%error, kin_root = %kin_root.display(), "could not read the .kin/ layout version before starting a daemon");
            Ok(())
        }
    }
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

/// The refusal a command gets when daemon resolution produced no endpoint.
///
/// [`resolve_daemon_url`] answers `Ok(None)` in exactly one situation:
/// `KIN_NO_DAEMON` is set and no supervisor route is already published for this
/// repository. Every other outcome returns `Err` carrying its own reason, so
/// this branch is the one case where the cause is known exactly.
pub fn daemon_required_error(command: &str, layout: &KinLayout) -> anyhow::Error {
    anyhow::anyhow!(
        "KIN_NO_DAEMON is set and no kin daemon is already running for {}, so there is no \
         repository authority to answer {command}; unset KIN_NO_DAEMON and re-run, and kin will \
         start one",
        layout.root().display()
    )
}

/// The refusal a caller gets when it needs a daemon that is already serving.
///
/// [`resolve_daemon_url_if_running_async`] never starts one, so an absent
/// endpoint here means no daemon holds this repository yet rather than anything
/// the caller asked for wrongly.
pub fn running_daemon_required_error(command: &str, layout: &KinLayout) -> anyhow::Error {
    anyhow::anyhow!(
        "no kin daemon is serving {}, so there is no repository authority to record {command}; run \
         `kin status` in that repository to start one, then re-run",
        layout.root().display()
    )
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
        // A store this build cannot open is the whole answer, and so is a
        // strict-mode environment divergence: neither is a daemon that failed
        // to start. Adding the daemon framing over either would promote the
        // consequence to the headline and demote the reason to a nested cause.
        Err(
            err @ (AutoStartError::IncompatibleStore(_) | AutoStartError::BehaviorEnvIgnored(_)),
        ) => Err(anyhow::Error::new(err)),
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

    /// The startup-phase line the MCP answer-early path injects must track the
    /// daemon's lifecycle markers: pid file means the process is up and
    /// loading, port file means it is listening, neither means it is still
    /// being resolved or spawned.
    #[test]
    fn daemon_startup_phase_tracks_the_lifecycle_markers() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_root = tmp.path();
        assert!(
            daemon_startup_phase(kin_root).contains("resolving or spawning"),
            "no markers is the resolve/spawn phase"
        );
        std::fs::write(kin_root.join(kin_daemon_spawn::PID_FILE_NAME), "12345").unwrap();
        assert!(
            daemon_startup_phase(kin_root).contains("loading the repository graph"),
            "a pid file with no port file is the graph-load phase"
        );
        std::fs::write(kin_root.join(kin_daemon_spawn::PORT_FILE_NAME), "50000").unwrap();
        assert!(
            daemon_startup_phase(kin_root).contains("finishing readiness checks"),
            "a published port is the readiness phase"
        );
    }

    #[test]
    fn windows_daemon_candidates_use_the_target_platform_executable_name() {
        let executable = Path::new("target")
            .join("debug")
            .join("deps")
            .join(if cfg!(windows) {
                "kin-test.exe"
            } else {
                "kin-test"
            });
        let candidates = daemon_binary_candidates_for_executable(&executable);
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.file_name() == Some(DAEMON_BINARY_FILE_NAME.as_ref())));
        assert_eq!(
            candidates[0],
            executable.with_file_name(DAEMON_BINARY_FILE_NAME)
        );
        assert_eq!(
            candidates[1],
            Path::new("target")
                .join("debug")
                .join(DAEMON_BINARY_FILE_NAME)
        );
    }

    async fn spawn_fixed_response_server_at(
        route: &'static str,
        status: axum::http::StatusCode,
        body: impl Into<String>,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{routing::post, Router};

        let body = body.into();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handler_requests = requests.clone();
        let app = Router::new().route(
            route,
            post(move || {
                let requests = handler_requests.clone();
                let body = body.clone();
                async move {
                    requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (status, body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), requests, server)
    }

    async fn spawn_fixed_response_server(
        status: axum::http::StatusCode,
        body: &'static str,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_fixed_response_server_at("/commands/test", status, body).await
    }

    async fn read_complete_http_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::AsyncReadExt;

        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before a complete HTTP request arrived",
                ));
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                return Ok(());
            }
        }
    }

    async fn spawn_dropped_ack_server() -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_requests = requests.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                if read_complete_http_request(&mut stream).await.is_ok() {
                    server_requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                drop(stream);
            }
        });
        (format!("http://{address}"), requests, server)
    }

    async fn spawn_truncated_ack_server() -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::AsyncWriteExt;

        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_requests = requests.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                if read_complete_http_request(&mut stream).await.is_ok() {
                    server_requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Content-Length: 64\r\nConnection: close\r\n\r\n{",
                        )
                        .await;
                }
                drop(stream);
            }
        });
        (format!("http://{address}"), requests, server)
    }

    async fn spawn_redirect_server() -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{http::header, routing::post, Router};

        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_requests = requests.clone();
        let replayed_requests = requests.clone();
        let app = Router::new()
            .route(
                "/commands/test",
                post(move || {
                    let requests = first_requests.clone();
                    async move {
                        requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        (
                            axum::http::StatusCode::TEMPORARY_REDIRECT,
                            [(header::LOCATION, "/commands/replayed")],
                        )
                    }
                }),
            )
            .route(
                "/commands/replayed",
                post(move || {
                    let requests = replayed_requests.clone();
                    async move {
                        requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        axum::Json(serde_json::json!({"accepted": true}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), requests, server)
    }

    fn stable_test_operation_id() -> OperationId {
        OperationId::from_uuid(Uuid::from_u128(0x12345678_90ab_cdef_0123_456789abcdef))
    }

    struct UnserializableRequest;

    impl serde::Serialize for UnserializableRequest {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    fn assert_indeterminate(error: &anyhow::Error, operation_id: OperationId) {
        let indeterminate = error
            .downcast_ref::<IndeterminateDaemonCommandError>()
            .expect("failure must retain the typed indeterminate outcome");
        assert_eq!(indeterminate.operation_id, operation_id);
        let rendered = format!("{error:#}");
        assert!(rendered.contains("outcome is indeterminate"));
        assert!(rendered.contains(&operation_id.to_string()));
        assert!(rendered.contains("do not retry automatically"));
    }

    #[tokio::test]
    async fn merge_requires_a_corroborated_acknowledgement_and_dispatches_once() {
        let operation_id = stable_test_operation_id();
        let other_operation_id =
            OperationId::from_uuid(Uuid::from_u128(0xfedcba09_8765_4321_fedc_ba0987654321));
        let cases = [
            (
                "empty acknowledgement",
                "{}".to_string(),
                "omitted operation_id",
            ),
            (
                "mismatched operation identity",
                serde_json::json!({"operation_id": other_operation_id}).to_string(),
                "expected",
            ),
            (
                "missing report",
                serde_json::json!({"operation_id": operation_id}).to_string(),
                "omitted its authoritative report",
            ),
        ];

        for (case, body, detail) in cases {
            let (base_url, requests, server) =
                spawn_fixed_response_server_at("/commands/merge", axum::http::StatusCode::OK, body)
                    .await;
            let client =
                DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
            let request = crate::commands::merge::MergeRequest {
                source: kin_model::RefName::branch(b"source").unwrap(),
                operation_id,
                actor: kin_model::AuthorId::new("ack-test"),
            };

            let error = client
                .merge(&request)
                .await
                .expect_err("an uncorroborated merge acknowledgement must be indeterminate");
            server.abort();

            assert_indeterminate(&error, operation_id);
            assert_eq!(
                requests.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{case} must not be redispatched"
            );
            assert!(
                format!("{error:#}").contains(detail),
                "{case} should report {detail}: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn resolve_requires_a_corroborated_acknowledgement_and_dispatches_once() {
        let operation_id = stable_test_operation_id();
        let other_operation_id =
            OperationId::from_uuid(Uuid::from_u128(0xfedcba09_8765_4321_fedc_ba0987654321));
        let cases = [
            (
                "empty acknowledgement",
                "{}".to_string(),
                "omitted operation_id",
            ),
            (
                "mismatched operation identity",
                serde_json::json!({"operation_id": other_operation_id}).to_string(),
                "expected",
            ),
            (
                "missing report",
                serde_json::json!({"operation_id": operation_id}).to_string(),
                "omitted its authoritative report",
            ),
        ];

        for (case, body, detail) in cases {
            let (base_url, requests, server) = spawn_fixed_response_server_at(
                "/commands/resolve",
                axum::http::StatusCode::OK,
                body,
            )
            .await;
            let client =
                DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
            let request = crate::commands::resolve::ResolveRequest {
                operation_id,
                actor: kin_model::AuthorId::new("ack-test"),
                action: crate::commands::resolve::ResolveAction::Abort,
                expected_record: None,
            };

            let error = client
                .resolve(&request)
                .await
                .expect_err("an uncorroborated resolve acknowledgement must be indeterminate");
            server.abort();

            assert_indeterminate(&error, operation_id);
            assert_eq!(
                requests.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{case} must not be redispatched"
            );
            assert!(
                format!("{error:#}").contains(detail),
                "{case} should report {detail}: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn non_idempotent_post_serialization_failure_is_direct_and_never_dispatched() {
        let (base_url, requests, server) =
            spawn_fixed_response_server(axum::http::StatusCode::OK, "{}").await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &UnserializableRequest,
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("serialization must fail before dispatch");
        server.abort();

        assert!(
            error
                .downcast_ref::<IndeterminateDaemonCommandError>()
                .is_none(),
            "a pre-dispatch serialization failure has a proven direct outcome"
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(format!("{error:#}").contains("encode non-idempotent daemon request"));
    }

    #[tokio::test]
    async fn non_idempotent_post_dropped_ack_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) = spawn_dropped_ack_server().await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a dropped acknowledgement must be indeterminate");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_idempotent_post_truncated_body_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) = spawn_truncated_ack_server().await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a truncated acknowledgement body must be indeterminate");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("read daemon response body failed"));
    }

    #[tokio::test]
    async fn non_idempotent_post_server_error_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) =
            spawn_fixed_response_server(axum::http::StatusCode::SERVICE_UNAVAILABLE, "try later")
                .await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a server error must be indeterminate");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("503 Service Unavailable"));
    }

    #[tokio::test]
    async fn non_idempotent_post_malformed_success_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) =
            spawn_fixed_response_server(axum::http::StatusCode::OK, "not-json").await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("an undecodable success acknowledgement must be indeterminate");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("decode daemon response failed"));
    }

    #[tokio::test]
    async fn non_idempotent_post_client_error_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) =
            spawn_fixed_response_server(axum::http::StatusCode::CONFLICT, "stale merge record")
                .await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a 4xx response cannot prove the mutation was rejected");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("409 Conflict: stale merge record"));
    }

    #[tokio::test]
    async fn non_idempotent_post_bad_request_is_indeterminate_and_dispatched_once() {
        let (base_url, requests, server) =
            spawn_fixed_response_server(axum::http::StatusCode::BAD_REQUEST, "finalization failed")
                .await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a 400 response cannot prove the mutation was rejected");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("400 Bad Request: finalization failed"));
    }

    #[tokio::test]
    async fn non_idempotent_post_does_not_redispatch_through_redirects() {
        let (base_url, requests, server) = spawn_redirect_server().await;
        let client =
            DaemonClient::from_base_url_with_explicit_authority(base_url, None, None).unwrap();
        let operation_id = stable_test_operation_id();

        let error = client
            .post_non_idempotent_json::<_, serde_json::Value>(
                "/commands/test",
                &serde_json::json!({"operation_id": operation_id}),
                operation_id,
                "test one-dispatch post",
            )
            .await
            .expect_err("a redirect is not authority to redispatch a mutation");
        server.abort();

        assert_indeterminate(&error, operation_id);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(format!("{error:#}").contains("307 Temporary Redirect"));
    }

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
        let _token =
            kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_AUTH_TOKEN", "explicit-token");

        let resolved = resolve_daemon_auth_token_for_layout(&layout);

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

    /// A loopback port guaranteed to answer no probe for as long as this
    /// guard lives, so a test's unreachable endpoint stays unreachable for the
    /// width of the test.
    ///
    /// That guarantee has to hold for the width of the probe, not just at
    /// acquisition. This test binary runs hundreds of sibling tests that bind
    /// ephemeral loopback listeners the whole time, so a port that was merely
    /// observed closed and then released can be handed by the kernel to a
    /// sibling's mock daemon mid-probe. The probe then receives a real health
    /// answer naming a different repository, which is positive evidence of a
    /// stale record, and the verdict the test meant to be about "nothing
    /// listens here" becomes a retirement. Holding the socket bound but never
    /// listening keeps the port unanswerable and unbindable at once: no other
    /// socket can take it, and with no listen queue a connect gets a reset on
    /// Linux and Windows and an unanswered SYN on macOS. Both read as "no
    /// usable answer" to every prober here, which judges through its own
    /// deadline rather than through the shape of the connect failure.
    struct ReservedClosedPort {
        port: u16,
        _reservation: tokio::net::TcpSocket,
    }

    fn reserved_closed_loopback_port() -> ReservedClosedPort {
        let socket = tokio::net::TcpSocket::new_v4().expect("create the port reservation socket");
        socket
            .bind("127.0.0.1:0".parse().expect("loopback bind address"))
            .expect("bind the port reservation");
        let port = socket.local_addr().expect("read the reserved port").port();
        ReservedClosedPort {
            port,
            _reservation: socket,
        }
    }

    #[test]
    fn a_reserved_closed_port_answers_no_connection_and_cannot_be_rebound() {
        let reserved = reserved_closed_loopback_port();
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], reserved.port));

        let error = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500))
            .expect_err("a reserved closed port must never yield a connection while held");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            ),
            "the connect failure must be refusal or silence, not a different failure: {error}"
        );
        assert!(
            std::net::TcpListener::bind(address).is_err(),
            "no listener may take the port while the reservation is held"
        );
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
        let closed = reserved_closed_loopback_port();
        write_endpoint_files(root, std::process::id(), closed.port);

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
        let closed = reserved_closed_loopback_port();
        write_endpoint_files(root, pid, closed.port);

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
        let predecessor_port = reserved_closed_loopback_port();
        write_endpoint_files(&root, predecessor.id(), predecessor_port.port);

        let successor_reservation = reserved_closed_loopback_port();
        let successor_port = successor_reservation.port;
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

    /// Take supervisor startup authority immediately after a previous holder
    /// released it, waiting out a contended acquire.
    ///
    /// `try_acquire_supervisor_startup_lock_in_dir` is the non-waiting
    /// primitive, and one non-blocking `flock` can report contention on a lock
    /// whose holder has already dropped. Production never sees this because it
    /// reaches the primitive through
    /// `acquire_supervisor_startup_lock_in_dir_with_timeout`, which already
    /// retries within a deadline. A test that takes the authority as a setup
    /// step needs the same rule, or it fails on the release window while
    /// asserting something else entirely.
    fn take_supervisor_startup_authority_after_release(dir: &Path) -> SupervisorStartupLock {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match try_acquire_supervisor_startup_lock_in_dir(dir) {
                Ok(authority) => return authority,
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("supervisor startup authority at {dir:?}: {error}"),
            }
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

        let launcher_b = take_supervisor_startup_authority_after_release(dir.path());
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
        let launcher_c = take_supervisor_startup_authority_after_release(dir.path());
        assert!(launcher_c.authorizes(dir.path()));
        drop(launcher_c);
        assert!(
            namespace.is_dir(),
            "no Drop edge removes the old-client-blocking directory sentinel"
        );
    }

    /// The startup-lock deadline has three distinct causes, and the old message
    /// named the one that is false in the case that reaches users. Each state
    /// below must reach its own cause, so a wrong diagnosis fails here.
    #[test]
    fn startup_timeout_diagnosis_separates_contention_from_legacy_exclusion() {
        let contended = SupervisorStartupTimeoutState {
            authority_held: Some(true),
            sentinel_is_protocol_directory: true,
            sentinel_stamp_is_future: true,
            supervisor_may_be_alive: false,
        };
        assert_eq!(
            classify_supervisor_startup_timeout(contended),
            SupervisorStartupTimeoutCause::Contention,
            "a held authority lock proves a live holder, because the kernel drops an flock when \
             its holder dies"
        );

        let excluded = SupervisorStartupTimeoutState {
            authority_held: Some(false),
            ..contended
        };
        assert_eq!(
            classify_supervisor_startup_timeout(excluded),
            SupervisorStartupTimeoutCause::LegacyProtocolExclusion
        );

        assert_eq!(
            classify_supervisor_startup_timeout(SupervisorStartupTimeoutState {
                supervisor_may_be_alive: true,
                ..excluded
            }),
            SupervisorStartupTimeoutCause::SlowStartup,
            "a running supervisor means the wait was about startup, not about protocol age"
        );
        assert_eq!(
            classify_supervisor_startup_timeout(SupervisorStartupTimeoutState {
                sentinel_stamp_is_future: false,
                ..excluded
            }),
            SupervisorStartupTimeoutCause::SlowStartup,
            "without the compatibility stamp there is no evidence of the excluding state"
        );
        assert_eq!(
            classify_supervisor_startup_timeout(SupervisorStartupTimeoutState {
                sentinel_is_protocol_directory: false,
                ..excluded
            }),
            SupervisorStartupTimeoutCause::SlowStartup
        );
        assert_eq!(
            classify_supervisor_startup_timeout(SupervisorStartupTimeoutState {
                authority_held: None,
                ..excluded
            }),
            SupervisorStartupTimeoutCause::SlowStartup,
            "a filesystem that cannot report contention must not have its silence read as proof \
             of absence and turned into a verdict on the caller's binary"
        );
    }

    /// A timeout whose bound is unnamed cannot be raised by whoever hits it, and
    /// only one of these paths used to name it.
    #[test]
    fn every_startup_timeout_message_names_its_knob_and_its_own_cause() {
        let path = Path::new("/home/dev/.kin/supervisor.start.lock");
        let contention = supervisor_startup_timeout_message(
            path,
            300,
            SupervisorStartupTimeoutCause::Contention,
        );
        let exclusion = supervisor_startup_timeout_message(
            path,
            300,
            SupervisorStartupTimeoutCause::LegacyProtocolExclusion,
        );
        let slow = supervisor_startup_timeout_message(
            path,
            300,
            SupervisorStartupTimeoutCause::SlowStartup,
        );

        for message in [&contention, &exclusion, &slow] {
            assert!(
                message.contains("KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS")
                    && message.contains("KIN_DAEMON_READY_TIMEOUT_SECS"),
                "every timeout must name the knob that bounds it: {message}"
            );
            assert!(
                message.contains("timed out waiting for supervisor startup lock")
                    && message.contains("300s"),
                "every timeout must stay identifiable and say how long it waited: {message}"
            );
        }

        assert!(contention.contains("real contention"));
        assert!(
            !contention.contains(KIN_INSTALL_COMMAND),
            "real contention must not be blamed on binary age: {contention}"
        );
        assert!(
            exclusion.contains("not contention")
                && exclusion.contains("older than protocol v2")
                && exclusion.contains(KIN_INSTALL_COMMAND),
            "the excluding state must name binary age and the update remedy: {exclusion}"
        );
        assert!(
            !slow.contains("contention") && !slow.contains(KIN_INSTALL_COMMAND),
            "plain slowness must not be diagnosed as either of the other two: {slow}"
        );
    }

    /// The sentinel path is the only channel a current binary has to the
    /// operator of a binary too old to speak this protocol, and the far-future
    /// stamp that keeps such a binary bounded must survive using it.
    ///
    /// The guarded property is stamp survival, not write ordering.
    /// `ensure_supervisor_startup_namespace` does write the notice before it
    /// stamps, and the first block below pins that directly, but the ordering is
    /// hygiene rather than the mechanism. Every acquisition stamps the sentinel
    /// again and fails closed unless the timestamp reads back in the future, so
    /// a dir-mtime bump taken while the namespace is built is repaired before
    /// any caller holds the lock. The aged-sentinel block asserts that repair on
    /// its own, which is the property that holds whatever order the writes
    /// happen in.
    #[test]
    fn startup_notice_reaches_the_sentinel_without_aging_its_compatibility_stamp() {
        // Observed at the seam rather than only after a full acquire, because
        // the outer re-stamp would otherwise mask a notice write moved after
        // the inner one.
        let fresh = tempfile::tempdir().unwrap();
        let namespace = ensure_supervisor_startup_namespace(fresh.path()).unwrap();
        assert!(
            namespace
                .sentinel
                .join(SUPERVISOR_STARTUP_NOTICE_FILE)
                .is_file(),
            "the notice must be written while the namespace is built, not afterwards"
        );
        assert!(
            !startup_lock_is_stale(&namespace.sentinel, Duration::ZERO),
            "namespace setup must hand back a sentinel already stamped into the future, so no \
             write it performs can leave the stamp aged even momentarily"
        );
        drop(namespace);
        drop(fresh);

        let dir = tempfile::tempdir().unwrap();
        let launcher = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let sentinel = launcher.path().to_path_buf();
        let notice = launcher.path().join(SUPERVISOR_STARTUP_NOTICE_FILE);

        assert_eq!(
            std::fs::read_to_string(&notice).unwrap(),
            SUPERVISOR_STARTUP_NOTICE
        );
        assert!(
            SUPERVISOR_STARTUP_NOTICE.contains(KIN_INSTALL_COMMAND)
                && SUPERVISOR_STARTUP_NOTICE.contains("KIN_DAEMON_READY_TIMEOUT_SECS"),
            "the notice must carry the remedy an older binary's operator needs"
        );
        assert!(
            !startup_lock_is_stale(launcher.path(), Duration::ZERO),
            "writing the notice must not age the stamp that keeps a legacy launcher bounded"
        );

        let written_at = std::fs::metadata(&notice).unwrap().modified().unwrap();
        drop(launcher);
        let refreshed = take_supervisor_startup_authority_after_release(dir.path());
        assert_eq!(
            std::fs::metadata(&notice).unwrap().modified().unwrap(),
            written_at,
            "an unchanged notice must not be rewritten on every launch"
        );
        assert!(!startup_lock_is_stale(refreshed.path(), Duration::ZERO));

        std::fs::write(&notice, "clobbered by something else\n").unwrap();
        drop(refreshed);
        let repaired = take_supervisor_startup_authority_after_release(dir.path());
        assert_eq!(
            std::fs::read_to_string(&notice).unwrap(),
            SUPERVISOR_STARTUP_NOTICE,
            "a damaged notice must be restored rather than left wrong"
        );
        assert!(!startup_lock_is_stale(repaired.path(), Duration::ZERO));

        // Aging the sentinel by hand reaches the same end state as any write
        // ordered after a stamp, without depending on where in setup that write
        // sits. An acquisition owes the future stamp back either way.
        drop(repaired);
        filetime::set_file_mtime(
            &sentinel,
            filetime::FileTime::from_system_time(
                std::time::SystemTime::now() - Duration::from_secs(3600),
            ),
        )
        .unwrap();
        assert!(
            startup_lock_is_stale(&sentinel, Duration::ZERO),
            "the aging must be visible here, or the repair assertion below could not fail"
        );
        let restamped = take_supervisor_startup_authority_after_release(dir.path());
        assert!(
            !startup_lock_is_stale(restamped.path(), Duration::ZERO),
            "an acquisition must restore a compatibility stamp it finds aged, whatever aged it"
        );
    }

    /// The doctor's sentinel classification decides which diagnosis it prints,
    /// so a directory must never read as a legacy marker or the reverse.
    /// Takes its directory by argument on purpose. An earlier version set
    /// `KIN_REGISTRY_PATH` instead, and because environment variables are
    /// process-global while `cargo test` runs the binary's tests as threads in
    /// one process, unrelated tests resolving the Kin home saw the temporary
    /// path and failed. `#[serial]` does not help: it orders a test only against
    /// other serial tests, not against the rest of the suite running in
    /// parallel. Under nextest, which gives each test its own process, the same
    /// bug is invisible.
    #[test]
    fn sentinel_classification_separates_the_protocol_directory_from_a_legacy_marker() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("kin-home");
        std::fs::create_dir_all(&home).unwrap();
        let sentinel = home.join(SUPERVISOR_STARTUP_FILE);

        assert_eq!(
            supervisor_startup_sentinel_in_dir(&home),
            SupervisorStartupSentinel::Absent
        );

        std::fs::write(&sentinel, "legacy v1 marker").unwrap();
        assert_eq!(
            supervisor_startup_sentinel_in_dir(&home),
            SupervisorStartupSentinel::LegacyMarker,
            "only a launcher older than this protocol writes a regular file here"
        );

        std::fs::remove_file(&sentinel).unwrap();
        let launcher = try_acquire_supervisor_startup_lock_in_dir(&home).unwrap();
        assert_eq!(
            launcher.path(),
            sentinel,
            "the classifier must read the same sentinel the launcher writes"
        );
        drop(launcher);
        assert_eq!(
            supervisor_startup_sentinel_in_dir(&home),
            SupervisorStartupSentinel::ProtocolDirectory
        );
        assert_eq!(supervisor_startup_protocol(), SUPERVISOR_STARTUP_PROTOCOL);
    }

    /// A link at the sentinel path hard-blocks supervisor startup, so it must
    /// classify as its own state rather than as the directory it points at or
    /// as merely unreadable. The refusal is asserted in fact, not assumed: the
    /// classification is only honest while startup really does refuse.
    #[cfg(unix)]
    #[test]
    fn sentinel_classification_marks_a_link_the_startup_protocol_refuses_to_follow() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("kin-home");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(SUPERVISOR_STARTUP_FILE)).unwrap();

        assert_eq!(
            supervisor_startup_sentinel_in_dir(&home),
            SupervisorStartupSentinel::RefusedLink,
            "a symlink must not be reported as the protocol directory it points at"
        );

        let refusal = ensure_supervisor_startup_namespace(&home).unwrap_err();
        assert_eq!(
            refusal.kind(),
            std::io::ErrorKind::PermissionDenied,
            "no supervisor can start against this sentinel: {refusal}"
        );
        assert!(refusal.to_string().contains("refuses symlink"), "{refusal}");
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
        let adopted_dir = tempfile::tempdir().unwrap();
        let adopted_launcher =
            try_acquire_supervisor_startup_lock_in_dir(adopted_dir.path()).unwrap();
        let adopted_generation = adopted_launcher.generation().to_string();
        let mut generation = kin_core::test_env::EnvVarGuard::set(
            SUPERVISOR_STARTUP_GENERATION_ENV,
            &adopted_generation,
        );
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
        generation.apply(
            SUPERVISOR_STARTUP_GENERATION_ENV,
            Some(crashed_launcher.generation()),
        );
        drop(crashed_launcher);
        let error = validate_supervisor_runtime_startup(crashed_dir.path()).unwrap_err();

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
        let _generation = kin_core::test_env::EnvVarGuard::unset(SUPERVISOR_STARTUP_GENERATION_ENV);
        let error = validate_supervisor_runtime_startup(dir.path()).unwrap_err();

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

    /// A recorded identity whose boot microsecond has slewed still names the
    /// same boot, and one whose boot second differs does not.
    ///
    /// This is the defect in one assertion pair. The reported case measured the
    /// microsecond moving 57,694 on a machine that never rebooted, which made
    /// `kin daemon stop` answer "nothing to stop" about a daemon pinning a core.
    /// The second half is what keeps the fix from being a hole: tolerating the
    /// microsecond must not tolerate a different boot.
    #[test]
    fn legacy_boot_identity_survives_clock_slew_but_still_refuses_another_boot() {
        let live_seconds = 1_785_713_468_i64;

        // Recorded before the slew, live value after it. Only the microsecond
        // differs, which is exactly the field the clock moves.
        assert!(
            macos_legacy_boottime_matches("macos-kern-boottime:1785713468:118135", live_seconds),
            "a slewed boot microsecond must not read as a different boot"
        );
        assert!(
            macos_legacy_boottime_matches("macos-kern-boottime:1785713468:175829", live_seconds),
            "the same boot must match whatever the microsecond has drifted to"
        );
        // The seconds-only form this build mints as a fallback.
        assert!(macos_legacy_boottime_matches(
            "macos-kern-boottime:1785713468",
            live_seconds
        ));

        // Falsification: change the second, keep everything else. A real reboot
        // must still be refused, or the guard protects nothing.
        assert!(
            !macos_legacy_boottime_matches("macos-kern-boottime:1785713469:118135", live_seconds),
            "a different boot second must still be refused"
        );
        assert!(!macos_legacy_boottime_matches(
            "macos-kern-boottime:1785799868:118135",
            live_seconds
        ));
        // Neither a foreign scheme nor an unparseable second may match.
        assert!(!macos_legacy_boottime_matches(
            "linux-boot-id:1785713468",
            live_seconds
        ));
        assert!(!macos_legacy_boottime_matches(
            "macos-kern-boottime:not-a-number",
            live_seconds
        ));
        assert!(!macos_legacy_boottime_matches("", live_seconds));
    }

    /// The minted identity must not carry a field the clock can move.
    ///
    /// The assertion this replaces sampled `stable_boot_identity()` twice ten
    /// milliseconds apart and required them equal, with the message "boot
    /// identity must be a kernel boot token, not wall-clock-minus-uptime". It
    /// was written for this exact defect and could never observe it: the slew
    /// arrives in sporadic NTP steps, so five samples over four seconds are
    /// byte-identical on a host actively exhibiting the bug. A test that cannot
    /// fail is not evidence, so this asserts the shape of the identity instead
    /// of the stability of two samples taken a moment apart.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_boot_identity_carries_no_wall_clock_microsecond() {
        let identity = stable_boot_identity().unwrap();
        assert!(
            !identity.starts_with("macos-kern-boottime:")
                || !identity
                    .trim_start_matches("macos-kern-boottime:")
                    .contains(':'),
            "minted boot identity still carries a boot microsecond: {identity}"
        );
        if let Some(uuid) = identity.strip_prefix("macos-boot-session:") {
            assert!(!uuid.is_empty(), "empty boot session uuid");
            assert_eq!(
                uuid,
                macos_boot_session_uuid().unwrap(),
                "the boot session uuid must be stable across reads"
            );
        }
    }

    #[test]
    fn process_identity_rejects_pid_reuse_and_reboot_boundaries() {
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
        let legacy_reservation = reserved_closed_loopback_port();
        let legacy_port = legacy_reservation.port;

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
                owner: None,
                pid_exists: true,
                port_exists: true,
                owner_exists: false,
            },
            "the post-snapshot legacy publication must survive the read-only probe"
        );

        drop(legacy_startup_authority);
        let current_startup_authority = take_supervisor_startup_authority_after_release(dir.path());
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

        let cleanup = remove_stale_daemon_files(root);

        assert_eq!(read_pid_file(root), Some(std::process::id()));
        assert_eq!(read_port_file(root), Some(51000));
        let preserved = cleanup
            .preserved()
            .expect("a live owner's endpoint is preserved, and the caller must be told");
        assert_eq!(preserved.pid_path(), repo_daemon_pid_path(root));
    }

    /// A probe refusing retirement for the first `refusals` calls and allowing it
    /// after, so the wait's retry is exercised as a decision rather than as a
    /// timing accident. Counts every call so a caller can prove how many probes
    /// a budget actually spent.
    fn probe_that_flips_after(
        refusals: usize,
        calls: std::rc::Rc<std::cell::Cell<usize>>,
    ) -> impl FnMut(&Path, u32) -> bool {
        move |_, _| {
            let seen = calls.get();
            calls.set(seen + 1);
            seen >= refusals
        }
    }

    #[test]
    fn stopped_endpoint_retirement_waits_out_a_teardown_window() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let cleanup = retire_daemon_endpoint_with_probe(
            root,
            Duration::from_secs(5),
            probe_that_flips_after(3, calls.clone()),
        );

        assert_eq!(cleanup, DaemonEndpointCleanup::Retired);
        assert!(!root.join("daemon.pid").exists());
        assert!(!root.join("daemon.port").exists());
        assert!(
            calls.get() > 1,
            "a single probe cannot have observed the flip; the wait must retry"
        );
    }

    #[test]
    fn a_single_probe_would_have_preserved_the_same_endpoint() {
        // The falsification of the test above: the identical fixture, decided on
        // one probe, keeps the endpoint. Without this, "retired" says nothing
        // about whether the wait did any work.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let cleanup = retire_daemon_endpoint_with_probe(
            root,
            Duration::ZERO,
            probe_that_flips_after(3, calls),
        );

        assert!(cleanup.preserved().is_some());
        assert!(root.join("daemon.pid").exists());
    }

    #[test]
    fn a_permanently_indeterminate_owner_reports_the_surviving_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let cleanup =
            retire_daemon_endpoint_with_probe(root, Duration::from_millis(120), |_, _| false);

        let preserved = cleanup.preserved().expect(
            "an endpoint that outlived a confirmed stop must be reported, not warned about",
        );
        assert_eq!(preserved.pid_path(), repo_daemon_pid_path(root));
        assert!(
            preserved.reason().contains("4242"),
            "the reason must name the owner that never died: {}",
            preserved.reason()
        );
        assert!(root.join("daemon.pid").exists());
    }

    #[test]
    fn a_successors_endpoint_is_not_reported_as_a_failed_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        // Republish under a different pid at the instant the wait ends, the way a
        // successor daemon would. Preserving that record is correct, and calling
        // it a failed stop would be a false alarm.
        let republished = std::cell::Cell::new(false);
        let cleanup = retire_daemon_endpoint_with_probe(root, Duration::ZERO, |_, _| {
            if !republished.replace(true) {
                write_endpoint_files(root, 4243, 51001);
            }
            false
        });

        assert_eq!(cleanup, DaemonEndpointCleanup::Superseded);
        assert_eq!(read_pid_file(root), Some(4243));
    }

    #[test]
    fn an_unparseable_pid_record_is_a_preserved_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.pid"), "indeterminate").unwrap();
        std::fs::write(root.join("daemon.port"), "51000").unwrap();

        let cleanup =
            retire_daemon_endpoint_with_probe(root, Duration::from_millis(120), |_, _| {
                panic!("an unparseable record names no process to probe")
            });

        assert!(cleanup.preserved().is_some());
        assert!(root.join("daemon.pid").exists());
    }

    /// A recycled PID must not become a loud, permanent, WRONG stop failure.
    ///
    /// This is what forced the retirement probe to judge the recorded
    /// incarnation rather than the bare PID. Reporting a preserved endpoint is
    /// only worth doing if the report is right, and a bare probe answers `Alive`
    /// about a live stranger holding the dead publisher's number — forever. The
    /// old code merely warned about that and moved on; a bounded wait followed by
    /// a nonzero exit would have promoted it to a hard error on a command
    /// operators run constantly.
    #[test]
    fn a_recycled_pid_does_not_fail_a_stop_that_worked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let pid =
            write_attributed_endpoint_files(root, recycled_identity_for_this_process(), 51000);
        // The bare probe every earlier version used still calls this PID alive:
        // it is this test process.
        assert_eq!(process_liveness(pid), ProcessLiveness::Alive);

        let cleanup = retire_stopped_daemon_endpoint(root);

        assert_eq!(
            cleanup,
            DaemonEndpointCleanup::Retired,
            "the daemon that published this endpoint is gone, so the stop succeeded"
        );
        assert!(!root.join("daemon.pid").exists());
    }

    /// A lock a DEAD daemon has not finished releasing must not decide the
    /// endpoint's fate.
    ///
    /// This is the half the first fix missed, and the miss was an assumption
    /// rather than an oversight: waiting for affirmative death was treated as
    /// also waiting out the dead process's locks. It is not. CI caught it on
    /// Windows with the endpoint preserved because "the repository daemon
    /// singleton is still held by a current or legacy owner" AFTER the owner was
    /// confirmed dead.
    ///
    /// Holds `daemon.lock` for real and releases it partway through the budget,
    /// which is the actual contention rather than a simulation of it.
    #[test]
    fn a_singleton_still_held_by_a_dead_owner_is_waited_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        write_endpoint_files(&root, 4242, 51000);

        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("daemon.lock"))
            .unwrap();
        singleton.try_lock_exclusive().expect("take the singleton");

        let holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let _ = fs2::FileExt::unlock(&singleton);
        });

        let cleanup = retire_daemon_endpoint_with_probe(&root, Duration::from_secs(5), |_, _| true);
        holder.join().unwrap();

        assert_eq!(
            cleanup,
            DaemonEndpointCleanup::Retired,
            "a lock the dead owner had not yet released must be waited out, not reported"
        );
        assert!(!root.join("daemon.pid").exists());
    }

    /// The falsification of the test above: the SAME contention with no budget
    /// to wait in still reports the survivor. Without this, "retired" would say
    /// nothing about whether the retry did any work.
    #[test]
    fn a_held_singleton_with_no_budget_still_reports_the_survivor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let singleton = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("daemon.lock"))
            .unwrap();
        singleton.try_lock_exclusive().expect("take the singleton");

        let cleanup = retire_daemon_endpoint_with_probe(root, Duration::ZERO, |_, _| true);

        let preserved = cleanup
            .preserved()
            .expect("contention that outlives the budget is still reported");
        assert!(
            preserved.reason().contains("singleton"),
            "the reason must name what actually blocked it: {}",
            preserved.reason()
        );
        assert!(root.join("daemon.pid").exists());
        let _ = fs2::FileExt::unlock(&singleton);
    }

    #[test]
    fn an_absent_endpoint_is_retired_rather_than_reported() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let cleanup =
            retire_daemon_endpoint_with_probe(root, Duration::from_millis(120), |_, _| {
                panic!("there is no recorded owner to probe")
            });

        assert_eq!(cleanup, DaemonEndpointCleanup::Retired);
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
        let closed = reserved_closed_loopback_port();
        write_endpoint_files(root, 999_999_999, closed.port);
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
        // Nothing here asserts patience expiry; that invariant belongs to
        // `unpublished_daemon_singleton_owner_forbids_spawn` and to
        // `a_health_probe_that_never_answers_is_not_evidence_against_the_daemon`,
        // which set deliberately tiny patiences. Putting it out of reach is what
        // keeps a slow machine from turning a followed owner into `LiveNotReady`.
        const FOLLOW_PATIENCE: Duration = Duration::from_secs(600);
        // Strictly smaller than the patience it wraps, so a hang is reported as
        // this test hanging rather than as the waiter giving up.
        const HANG_GUARD: Duration = Duration::from_secs(60);

        let waiter_root = root.clone();
        let waiter = tokio::spawn(async move {
            wait_for_existing_daemon_within(
                &waiter_root,
                Duration::from_millis(20),
                FOLLOW_PATIENCE,
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
        // Synchronise on a value the code owns rather than on a sleep: the
        // waiter's own probe connection is the proof it read the published
        // endpoint. Dropping the accepted socket is safe by the probe's
        // documented contract, which records an unanswered health connection as
        // no evidence either way, so it retries into the real server below.
        let probe = tokio::time::timeout(HANG_GUARD, listener.accept())
            .await
            .expect("the waiter must probe the endpoint it was told about")
            .expect("accept the waiter's probe connection");
        assert!(
            !waiter.is_finished(),
            "a complete endpoint that has not served yet must remain owned"
        );
        drop(probe);

        let server = serve_repo_daemon_health(listener, repo.path());
        let outcome = tokio::time::timeout(HANG_GUARD, waiter)
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
        let reservation = reserved_closed_loopback_port();
        let port = reservation.port;
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
        let closed = reserved_closed_loopback_port();
        write_endpoint_files(root, 999_999_999, closed.port);

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

    // ── Endpoint owner liveness ───────────────────────────────────────────
    //
    // The failure these close: the start path decided from `daemon.pid` alone.
    // A SIGKILLed daemon leaves its endpoint behind, the kernel hands that PID
    // to an unrelated process, `kill(pid, 0)` reports it alive, and autostart
    // concluded forever that a live daemon it could not reach owned the repo.
    // The endpoint was never proven invalid, so nothing retired it and nothing
    // respawned.

    /// Publish an endpoint attributed to a given incarnation, the way the daemon
    /// does: the owner record first, then the endpoint it attributes.
    fn write_attributed_endpoint_files(
        kin_root: &Path,
        identity: ProcessIdentity,
        port: u16,
    ) -> u32 {
        let pid = identity.pid();
        std::fs::write(
            repo_daemon_owner_path(kin_root),
            serde_json::to_string(&EndpointOwnerRecord::for_identity(identity)).unwrap(),
        )
        .unwrap();
        write_endpoint_files(kin_root, pid, port);
        pid
    }

    /// The same live PID, a different incarnation of it: exactly the shape PID
    /// reuse produces once the daemon that published the endpoint is gone.
    fn recycled_identity_for_this_process() -> ProcessIdentity {
        let current = current_process_identity().expect("read this process's identity");
        let forged = ProcessIdentity {
            pid: current.pid,
            boot_id: current.boot_id.clone(),
            birth_token: format!("{}9", current.birth_token),
        };
        assert_ne!(
            forged, current,
            "the forged identity must name a different incarnation"
        );
        forged
    }

    #[test]
    fn a_recycled_pid_does_not_keep_a_dead_daemons_endpoint_alive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let pid =
            write_attributed_endpoint_files(root, recycled_identity_for_this_process(), 51000);

        // The bare-PID probe every earlier version used: this PID is running,
        // so the endpoint looked live and wedged autostart permanently.
        assert_eq!(process_liveness(pid), ProcessLiveness::Alive);

        let owner = endpoint_owner_liveness(root, pid);
        assert!(
            owner.identity_verified(),
            "an attributed endpoint must be judged against its recorded incarnation"
        );
        assert!(
            owner.authorizes_cleanup(),
            "the daemon that published this endpoint is gone, so it must be retirable"
        );
        assert_eq!(
            live_daemon_endpoint(root),
            None,
            "a recycled PID is not the daemon that published the endpoint"
        );
        assert!(
            !root.join("daemon.pid").exists()
                && !root.join("daemon.port").exists()
                && !repo_daemon_owner_path(root).exists(),
            "the proven-stale endpoint must be retired so a replacement can start"
        );
    }

    #[tokio::test]
    async fn probing_a_recycled_pid_endpoint_proves_it_invalid() {
        // The other half: `probe_daemon_endpoint` re-checked liveness from the
        // bare PID, so a recycled PID returned LiveNotReady until the deadline
        // on every attempt, forever, and the caller is forbidden from clearing
        // an endpoint that was never proven wrong.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(".kin");
        std::fs::create_dir_all(&root).unwrap();
        let closed = reserved_closed_loopback_port();
        let port = closed.port;
        let pid =
            write_attributed_endpoint_files(&root, recycled_identity_for_this_process(), port);

        let verdict = probe_daemon_endpoint(
            &root,
            LiveDaemonEndpoint { pid, port },
            Duration::from_millis(50),
        )
        .await;

        match verdict {
            EndpointVerdict::Invalid(detail) => assert!(
                detail.contains("different process"),
                "the diagnostic must say the publisher is gone, not that a number is: {detail}"
            ),
            other => panic!("a recycled PID must prove the record wrong, got {other:?}"),
        }
    }

    #[test]
    fn an_endpoint_owned_by_a_live_incarnation_survives() {
        // The inverse, so the fix cannot be "always delete": this process really
        // did publish this endpoint, and it must keep it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let identity = current_process_identity().expect("read this process's identity");
        let pid = write_attributed_endpoint_files(root, identity, 51000);

        let owner = endpoint_owner_liveness(root, pid);
        assert!(owner.identity_verified());
        assert!(
            !owner.authorizes_cleanup(),
            "a verified live owner's endpoint must never be retirable"
        );
        assert_eq!(
            live_daemon_endpoint(root),
            Some(LiveDaemonEndpoint { pid, port: 51000 })
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_uninspectable_owner_is_preserved_rather_than_retired() {
        // The indeterminate arm, driven through a real foreign process so the
        // record names an incarnation that really exists. An owner this process
        // cannot inspect is not a dead one, and the removal decision fails
        // closed.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut foreign = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in foreign owner");
        let identity = process_identity(foreign.id())
            .expect("read the foreign owner's identity")
            .expect("the foreign owner is running");
        let pid = write_attributed_endpoint_files(root, identity, 51000);

        let unreadable = |_: &ProcessIdentity| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cannot read birth identity for a foreign process",
            ))
        };
        assert!(
            !endpoint_owner_liveness_with_probes(root, pid, unreadable, process_liveness)
                .authorizes_cleanup(),
            "an owner that cannot be inspected must not authorize retirement"
        );
        assert_eq!(
            live_daemon_endpoint(root),
            Some(LiveDaemonEndpoint { pid, port: 51000 }),
            "a foreign live owner keeps its endpoint"
        );
        assert!(root.join("daemon.pid").exists() && root.join("daemon.port").exists());

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    #[test]
    fn attribution_that_names_another_pid_falls_back_to_the_endpoint_it_describes() {
        // A torn or mixed-version write: the record and the PID file disagree,
        // so the record describes a different process than the endpoint being
        // judged. Judging the PID the endpoint actually names is the only
        // reading that cannot act on a statement about somebody else.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            repo_daemon_owner_path(root),
            serde_json::to_string(&EndpointOwnerRecord::for_identity(
                recycled_identity_for_this_process(),
            ))
            .unwrap(),
        )
        .unwrap();
        write_endpoint_files(root, 4242, 51000);

        let owner = endpoint_owner_liveness_with_probes(
            root,
            4242,
            |_| Ok(false),
            |_| ProcessLiveness::Unknown,
        );
        assert!(
            !owner.identity_verified(),
            "a record for a different PID does not attribute this endpoint"
        );
        assert!(!owner.authorizes_cleanup());
    }

    #[test]
    fn a_legacy_endpoint_is_still_judged_by_its_pid() {
        // No owner record, so a bare PID is all there is. The legacy arm must
        // keep working: an endpoint published by a compatible older daemon is
        // retired when its PID is provably gone.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_endpoint_files(root, 4242, 51000);

        let owner = endpoint_owner_liveness(root, 4242);
        assert!(
            !owner.identity_verified(),
            "an unattributed endpoint cannot be identity verified"
        );
        assert_eq!(
            live_daemon_endpoint_with_probe(root, |_| ProcessLiveness::Dead),
            None
        );
        assert!(!root.join("daemon.pid").exists() && !root.join("daemon.port").exists());
    }

    #[test]
    fn live_daemon_endpoint_returns_alive_pid_even_before_port_binds() {
        let dir = tempfile::tempdir().unwrap();
        let closed = reserved_closed_loopback_port();
        let port = closed.port;
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

    /// A child that has exited but has not been waited on is a corpse, not a
    /// running daemon.
    ///
    /// This is the exact topology of an agent session: a long-lived MCP server
    /// starts a repo daemon and never reaps it, so `kill(pid, 0)` keeps
    /// answering for the daemon after it exits. Judging that "alive" is what
    /// made `kin daemon stop --all` report `timeout` for a daemon that had
    /// already stopped, no matter how long it waited.
    ///
    /// Deliberately never calls `wait()` before the assertion — reaping is the
    /// thing whose absence is under test.
    #[cfg(unix)]
    #[test]
    fn a_terminated_child_that_was_never_reaped_is_not_alive() {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn a child that exits immediately");
        let pid = child.id();

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut liveness = process_liveness(pid);
        while liveness != ProcessLiveness::Dead && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
            liveness = process_liveness(pid);
        }

        // Reap before asserting so a failure cannot leak the corpse into the
        // rest of the test binary, but assert on what was observed while it
        // was still unreaped.
        let reaped = child.wait();
        assert_eq!(
            liveness,
            ProcessLiveness::Dead,
            "an exited child nobody waited on must read as dead, not as a live daemon"
        );
        reaped.expect("reap the child");
    }

    /// The Linux state field is read from the right place.
    ///
    /// Runs on every platform: the `/proc` read is Linux-only, but a parser
    /// that picks the wrong field would report every corpse as still running,
    /// which is indistinguishable from having no fix at all.
    #[test]
    fn linux_stat_state_is_read_after_the_command_name() {
        assert!(linux_stat_line_is_zombie(
            "4242 (kin-daemon) Z 4240 4242 0 0 -1 4194560 0 0"
        ));
        assert!(!linux_stat_line_is_zombie(
            "4242 (kin-daemon) S 4240 4242 0 0 -1 4194560 0 0"
        ));
        assert!(!linux_stat_line_is_zombie(
            "4242 (kin-daemon) R 4240 4242 0 0 -1 4194560 0 0"
        ));
        // `comm` may contain spaces and its own parentheses, which is why the
        // FINAL `)` is the delimiter. A naive first-`)` split reads "weird" as
        // the state and answers "not a zombie" for a real corpse.
        assert!(linux_stat_line_is_zombie(
            "4242 (weird ) name) Z 4240 4242 0 0 -1 4194560 0 0"
        ));
        assert!(!linux_stat_line_is_zombie(
            "4242 (weird ) name) S 4240 4242 0 0 -1 4194560 0 0"
        ));
        // A truncated or unparseable line is never affirmative evidence.
        assert!(!linux_stat_line_is_zombie("4242 (kin-daemon)"));
        assert!(!linux_stat_line_is_zombie(""));
    }

    /// The corpse probe must not be a blanket "dead": a child that is genuinely
    /// running has to keep reading alive, or the fix above would turn every
    /// stop into a false success.
    #[cfg(unix)]
    #[test]
    fn a_running_child_is_still_alive() {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 30")
            .spawn()
            .expect("spawn a long-running child");
        let pid = child.id();

        std::thread::sleep(Duration::from_millis(250));
        let liveness = process_liveness(pid);
        let identity = process_identity(pid);

        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(
            liveness,
            ProcessLiveness::Alive,
            "a running child must not be mistaken for a corpse"
        );
        assert!(
            matches!(identity, Ok(Some(_))),
            "a running child must still have a readable birth identity, got {identity:?}"
        );
    }

    /// The stop path decides purely on `process_identity_is_current(..) ==
    /// Ok(false)`. An unreaped corpse must reach that verdict, otherwise the
    /// wait loop runs its whole budget and reports `timeout` for a process that
    /// is already gone.
    #[cfg(unix)]
    #[test]
    fn an_unreaped_corpse_is_not_the_current_incarnation() {
        // Hold the child open on stdin so its identity can be recorded while it
        // is unambiguously live. A fabricated identity would compare unequal
        // for a live process too, which would make this test pass without the
        // fix — the recorded incarnation has to be the real one.
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("read _; exit 0")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn a child that waits for stdin");
        let pid = child.id();

        let identity = process_identity(pid)
            .expect("read the live child's birth identity")
            .expect("a running child has an identity");
        assert!(
            matches!(process_identity_is_current(&identity), Ok(true)),
            "control: the recorded identity must be current while the child runs"
        );

        // Closing stdin ends the child. Nothing waits on it, so it stays in the
        // process table as a corpse — which is the state under test.
        drop(child.stdin.take());

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut verdict = process_identity_is_current(&identity);
        while !matches!(verdict, Ok(false)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
            verdict = process_identity_is_current(&identity);
        }

        let reaped = child.wait();
        assert!(
            matches!(verdict, Ok(false)),
            "an exited, unreaped child must compare as a finished incarnation so the \
             stop wait can conclude; got {verdict:?}"
        );
        reaped.expect("reap the child");
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
    fn strict_mode_refuses_every_time_the_warning_is_said_once() {
        // The warning is suppressed after the first telling because it would
        // repeat itself exactly. A refusal must not be: a strict run that fails
        // the first command and passes the next has stopped being strict.
        assert!(report_behavior_env_divergence(&one_divergence(), false).is_ok());
        assert!(report_behavior_env_divergence(&one_divergence(), false).is_ok());
        assert!(report_behavior_env_divergence(&one_divergence(), true).is_err());
        assert!(report_behavior_env_divergence(&one_divergence(), true).is_err());
    }

    #[test]
    fn attaching_asks_the_daemon_only_when_this_command_stated_a_lever() {
        // The attach check costs a health read, so it must not run for the
        // ordinary command that set nothing. An empty value states nothing
        // either: the read sites treat it as unset, so it can only agree.
        let stated_nothing = kin_core::behavior_env::snapshot_with(|_| None);
        assert!(!states_a_behavior_lever(&stated_nothing));

        let stated_blanks = kin_core::behavior_env::snapshot_with(|_| Some("  ".to_string()));
        assert!(!states_a_behavior_lever(&stated_blanks));

        let stated_the_opt_out = kin_core::behavior_env::snapshot_with(|name| {
            (name == "KIN_DAEMON_AUTO_EMBED").then(|| "0".to_string())
        });
        assert!(
            states_a_behavior_lever(&stated_the_opt_out),
            "a command that set the background-embedding opt-out must reach the attach check"
        );
    }

    #[test]
    fn an_ignored_opt_out_is_named_without_a_daemon_startup_framing() {
        // Nothing failed to start here, so the message is the whole answer, the
        // same way an incompatible store is.
        let error = AutoStartError::BehaviorEnvIgnored(behavior_env_divergence_message(&[
            kin_core::behavior_env::Divergence {
                var: "KIN_DAEMON_AUTO_EMBED".to_string(),
                cli: Some("0".to_string()),
                daemon: None,
            },
        ]));
        let text = error.to_string();
        assert!(text.contains("KIN_DAEMON_AUTO_EMBED: cli=\"0\" daemon=(unset)"));
        assert!(
            !text.contains("daemon startup failed"),
            "an ignored lever was reported as a failed daemon start: {text}"
        );
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

    /// Block until `pid` has terminated, leaving it unreaped.
    ///
    /// `WNOWAIT` is what makes this a synchronization point rather than a
    /// substitute for the code under test: it returns exactly when the child
    /// becomes reapable and leaves it in that state, so the classifier's own
    /// `try_wait` is still the call that observes the corpse and reaps it.
    /// Anything that consumed the child here, including a plain `wait`, would
    /// leave the classifier reading a cached status down a branch the daemon
    /// path never takes.
    #[cfg(unix)]
    fn block_until_terminated_leaving_it_reapable(pid: u32) {
        let pid = libc::pid_t::try_from(pid).expect("a pid we spawned fits pid_t");
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let observed = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if observed == 0 {
                return;
            }
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EINTR),
                "a child we spawned must stay observable until we reap it: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_that_already_exited_is_reaped() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a child that exits immediately");
        block_until_terminated_leaving_it_reapable(child.id());

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
    fn resolve_idle_timeout_uses_the_store_window_when_nothing_set() {
        // No user env, no caller override → the window this store's own
        // recorded open cost asked for, verbatim.
        assert_eq!(
            resolve_idle_timeout_env(false, None, "600"),
            Some("600".to_string())
        );
    }

    #[test]
    fn resolve_idle_timeout_mcp_override_propagates() {
        // MCP-path caller passes Some(MCP_IDLE_TIMEOUT_SECS) → "1800" reaches
        // the daemon, whatever the store window would have been.
        assert_eq!(
            resolve_idle_timeout_env(false, Some(MCP_IDLE_TIMEOUT_SECS), "600"),
            Some("1800".to_string())
        );
    }

    #[test]
    fn resolve_idle_timeout_user_env_always_wins() {
        // When user has set KIN_DAEMON_IDLE_TIMEOUT_SECS we must not inject anything,
        // regardless of the caller override or the store window.
        assert_eq!(resolve_idle_timeout_env(true, None, "600"), None);
        assert_eq!(
            resolve_idle_timeout_env(true, Some(MCP_IDLE_TIMEOUT_SECS), "600"),
            None
        );
    }

    /// FIR-2426. A CLI spawn used one compiled 60-second window for every
    /// store, and a converted repository's own cold start measured 48 to 71
    /// seconds, so the daemon expired between two commands and the next command
    /// paid the whole open again. The window a spawn takes now comes from what
    /// opening THAT store last cost.
    #[test]
    fn a_slow_store_gets_a_window_longer_than_its_own_cold_start() {
        let window = kin_daemon_spawn::cli_idle_window(Some(60_000));
        assert!(
            window.secs >= 600,
            "a store whose open costs 60s must get at least ten minutes, got {}s",
            window.secs
        );
        assert!(
            resolve_idle_timeout_env(false, None, &window.secs.to_string())
                .is_some_and(|value| value == "600"),
            "the spawn plan must carry the store's window, not the floor"
        );
    }

    /// Control for the rule: a store with no recorded cost keeps exactly the
    /// window every CLI spawn used before, so the change cannot be passing by
    /// making every window longer.
    #[test]
    fn a_store_with_no_recorded_cost_keeps_the_old_window() {
        assert_eq!(
            kin_daemon_spawn::cli_idle_window(None).secs,
            kin_daemon_spawn::CLI_IDLE_FLOOR_SECS
        );
        assert_eq!(kin_daemon_spawn::CLI_IDLE_FLOOR_SECS, 60);
    }

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        // Regression guard: the MCP path must inject 1800s (30 min), not the
        // 60-second CLI default.
        assert_eq!(MCP_IDLE_TIMEOUT_SECS, "1800");
    }

    // ── idle-timeout carried to a daemon this process did not start ────────

    /// Both sides. Injecting at spawn only helps the caller that spawns, and an
    /// MCP session usually attaches to a daemon an ordinary CLI command already
    /// started at the 60-second default. A caller with a stated need must carry
    /// it; a caller with none must leave the daemon alone.
    #[test]
    fn an_mcp_session_carries_its_window_to_a_daemon_it_did_not_start() {
        assert_eq!(
            idle_timeout_to_carry(Some(MCP_IDLE_TIMEOUT_SECS), false),
            Some(1800),
            "an MCP attach must state its 1800s need to the daemon it got"
        );
        assert_eq!(
            idle_timeout_to_carry(None, false),
            None,
            "an ordinary CLI attach states no need and must not touch the window"
        );
    }

    /// A user who set `KIN_DAEMON_IDLE_TIMEOUT_SECS` decided this host's policy.
    /// The attach path must respect that exactly as the spawn path does, or the
    /// two would disagree about whose value wins.
    #[test]
    fn an_explicit_user_window_is_never_overridden_from_the_attach_path() {
        assert_eq!(
            idle_timeout_to_carry(Some(MCP_IDLE_TIMEOUT_SECS), true),
            None
        );
        assert_eq!(idle_timeout_to_carry(None, true), None);
    }

    /// Nothing usable is carried rather than carried as a zero, which the
    /// daemon would have to reject as "a floor of forever".
    #[test]
    fn an_unusable_window_value_is_not_carried_at_all() {
        assert_eq!(idle_timeout_to_carry(Some("0"), false), None);
        assert_eq!(idle_timeout_to_carry(Some(""), false), None);
        assert_eq!(idle_timeout_to_carry(Some("later"), false), None);
        assert_eq!(idle_timeout_to_carry(Some(" 900 "), false), Some(900));
    }

    #[test]
    fn a_dropped_request_names_the_endpoint_the_command_and_the_way_back() {
        // A store this process could not resolve, which is also what a store
        // that never lost a daemon reads as. The idle window is the ordinary
        // cause and must still be offered here.
        let message = daemon_send_failure_message("http://127.0.0.1:51234", "locate", None);
        assert!(
            message.contains("http://127.0.0.1:51234"),
            "the reader cannot tell which daemon went away without its endpoint: {message}"
        );
        assert!(
            message.contains("locate"),
            "the command in flight is the subject of this failure: {message}"
        );
        assert!(
            message.contains("idle window") && message.contains("re-run"),
            "an idle-window exit is recoverable and the message must say how: {message}"
        );
        assert!(
            !message.starts_with("send "),
            "the dispatch verb was the defect being fixed: {message}"
        );
    }

    /// The store's own record replaces the idle window when it can prove a
    /// death, and leaves it alone when it cannot.
    ///
    /// The FIR-2650 pair, on the surface the measured sentence came from. Both
    /// arms run against a real directory, so the difference between them is the
    /// record and nothing else: a check that only ever saw the killed arm would
    /// pass a build that had simply stopped offering the idle window at all,
    /// which would be a second defect wearing the first one's fix.
    #[test]
    fn a_dropped_request_over_a_killed_daemon_stops_offering_the_idle_window() {
        let dir = tempfile::tempdir().unwrap();
        let quiet = daemon_send_failure_message(
            "http://127.0.0.1:39767",
            "lsp sweep status",
            Some(dir.path()),
        );
        assert!(
            quiet.contains("idle window") && quiet.contains("re-run"),
            "a store that has lost no daemon must read exactly as it always did: {quiet}"
        );

        // The trace a killed daemon leaves: a serving record it published at
        // start and never reached the line to retire. The pid cannot be alive,
        // so this is deterministic rather than a race against whatever holds
        // that number today.
        std::fs::write(
            kin_daemon_spawn::serving_path(dir.path()),
            serde_json::to_vec(&kin_daemon_spawn::ServingDaemon {
                pid: u32::MAX,
                oom_kills_at_start: Some(0),
                at_unix: 1_000,
            })
            .unwrap(),
        )
        .unwrap();

        let killed = daemon_send_failure_message(
            "http://127.0.0.1:39767",
            "lsp sweep status",
            Some(dir.path()),
        );
        assert!(
            killed.contains("killed"),
            "the daemon died and the message has to say so: {killed}"
        );
        assert!(
            !killed.contains("idle window, so re-run"),
            "re-running is the advice that cannot terminate when the cause recurs: {killed}"
        );
        assert!(
            killed.contains("http://127.0.0.1:39767") && killed.contains("lsp sweep status"),
            "the endpoint and the request in flight are still the subject: {killed}"
        );
    }

    #[test]
    fn an_empty_refusal_body_names_the_log_instead_of_rendering_a_bare_colon() {
        let message = daemon_http_error("http://127.0.0.1:51234", "locate", 500, "   ").to_string();
        assert!(
            !message.ends_with(": "),
            "a status code with nothing after the colon is the shape being removed: {message}"
        );
        assert!(
            message.contains(".kin/daemon.log"),
            "a body-less refusal leaves the log as the only remaining evidence: {message}"
        );
        assert!(
            message.contains("500") && message.contains("http://127.0.0.1:51234"),
            "{message}"
        );
    }

    /// A refusal the daemon stayed alive to explain is surfaced verbatim: it has
    /// already mapped its own error class onto a status and a body, and
    /// rewording it here would hide which authority refused and why.
    #[test]
    fn a_refusal_with_a_body_keeps_the_daemons_own_words() {
        let message = daemon_http_error(
            "http://127.0.0.1:51234",
            "merge",
            409,
            "branch main is ahead",
        )
        .to_string();
        assert_eq!(
            message,
            "kin merge refused (HTTP 409): branch main is ahead"
        );
    }

    #[test]
    fn the_one_endpointless_resolution_names_the_variable_that_caused_it() {
        let layout = KinLayout::new(std::path::PathBuf::from("/tmp/kin-fixture-repo"));
        let message = daemon_required_error("commit", &layout).to_string();
        assert!(
            message.contains("KIN_NO_DAEMON"),
            "this branch is reached only when KIN_NO_DAEMON is set, so it must say so: {message}"
        );
        assert!(
            message.contains("/tmp/kin-fixture-repo"),
            "the repository with no authority is the subject: {message}"
        );
        assert!(
            message.contains("commit"),
            "the command that went unanswered belongs in the message: {message}"
        );
        assert!(
            message.contains("unset KIN_NO_DAEMON"),
            "the remedy is one word away and must be stated: {message}"
        );
    }

    /// The autostart path and the already-running path fail for different
    /// reasons, so naming `KIN_NO_DAEMON` in the second would be a fabrication.
    #[test]
    fn a_caller_needing_a_live_daemon_is_not_told_an_unset_variable_caused_it() {
        let layout = KinLayout::new(std::path::PathBuf::from("/tmp/kin-fixture-repo"));
        let message = running_daemon_required_error("semantic graph commits", &layout).to_string();
        assert!(!message.contains("KIN_NO_DAEMON"), "{message}");
        assert!(
            message.contains("/tmp/kin-fixture-repo") && message.contains("kin status"),
            "{message}"
        );
    }
}
