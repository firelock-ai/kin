// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! KinDB graph backend — daemon-as-runtime.
//!
//! The primary entry point is [`open_snapshot_daemon_first`] which auto-starts
//! the daemon if needed, then fetches the warm graph from the daemon's
//! `/graph/bootstrap` endpoint. Direct local snapshot reads are only for
//! daemon internals and lower-level storage tests.
//!
//! The synchronous [`open_kindb_snapshot`] is kept for daemon internals
//! and tests that cannot use the async runtime.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SNAPSHOT_OPEN_MAX_ATTEMPTS: usize = 6;
const SNAPSHOT_OPEN_INITIAL_DELAY_MS: u64 = 10;

/// Path where KinDB stores its snapshot file within a `.kin/` layout.
pub fn kindb_snapshot_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_snapshot_path()
}

fn is_transient_lock_error(message: &str) -> bool {
    message.contains("another process may be using this database")
        || message.contains("another process may be writing this database")
        || message.contains("Resource temporarily unavailable")
        || message.contains("failed to acquire exclusive lock")
        || message.contains("failed to acquire shared lock")
}

/// Open a snapshot directly from disk. Used by daemon internals, tests,
/// and explicit direct-snapshot maintenance paths.
pub fn open_kindb_snapshot(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    open_kindb_snapshot_with_mode(layout, false)
}

pub fn open_kindb_snapshot_read_only(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    open_kindb_snapshot_with_mode(layout, true)
}

fn open_kindb_snapshot_with_mode(
    layout: &kin_core::KinLayout,
    read_only: bool,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let _span = tracing::info_span!(
        "kindb.open_snapshot",
        path = %kindb_snapshot_path(layout).display(),
        read_only = read_only
    )
    .entered();
    let path = kindb_snapshot_path(layout);
    let mut attempts = 0usize;
    let mut delay = Duration::from_millis(SNAPSHOT_OPEN_INITIAL_DELAY_MS);

    loop {
        let open_result = if read_only {
            kin_db::SnapshotManager::open_read_only(&path)
        } else {
            kin_db::SnapshotManager::open(&path)
        };
        match open_result {
            Ok(snapshot) => return Ok(snapshot),
            Err(kin_db::KinDbError::LockError(message))
                if attempts + 1 < SNAPSHOT_OPEN_MAX_ATTEMPTS
                    && is_transient_lock_error(&message) =>
            {
                attempts += 1;
                thread::sleep(delay);
                delay = std::cmp::min(delay.saturating_mul(2), Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
}

/// Path where the HNSW vector index is stored alongside the graph snapshot.
pub fn vector_index_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_vector_index_path()
}

/// Open snapshot directly from disk without involving the daemon.
/// Keep this out of product command paths; it exists for daemon bootstrap,
/// maintenance internals, and lower-level storage tests.
pub fn open_snapshot_local(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let snap = open_kindb_snapshot_with_mode(layout, true)?;
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Open snapshot directly from disk using the lightweight locate-only
/// read path. Keep this out of product command paths; `kin locate` itself
/// runs through the daemon.
pub fn open_snapshot_local_for_locate(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let snap = kin_db::SnapshotManager::open_read_only_for_locate(kindb_snapshot_path(layout))?;
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Daemon-required graph open for legacy read-only callers.
///
/// This fetches an in-memory bootstrap snapshot from the repo daemon and never
/// opens `.kin/kindb/graph.kndb` in the CLI process. Writable product paths must
/// use daemon endpoints instead of asking the CLI for a local `SnapshotManager`.
pub async fn open_snapshot_daemon_first(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    open_snapshot_daemon_first_with_mode(layout, false).await
}

pub async fn open_snapshot_daemon_first_read_only(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    open_snapshot_daemon_first_with_mode(layout, true).await
}

/// Read-only graph open for commands that analyze graph truth in-process
/// (e.g. `kin merge`, `kin release`, `kin git export`) and route every
/// mutation back through daemon endpoints.
///
/// Authority order (graph-first):
/// 1. The repo daemon (`/graph/bootstrap`). This is the canonical live
///    authority and is auto-started if needed, so these commands work by
///    default in a warm repo.
/// 2. If the daemon is unavailable AND `KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN` is
///    set, a direct local read-only snapshot is used. This is the explicit
///    offline/admin/debug escape hatch — never the default product path.
/// 3. Otherwise, a clear, actionable error (not a raw storage failure).
///
/// `command_name` is the user-facing verb (e.g. "kin merge") used only in the
/// fallback message.
pub async fn open_snapshot_explicit_admin_read_only(
    layout: &kin_core::KinLayout,
    command_name: &str,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    // 1. Daemon-first: the canonical live authority. Auto-starts if needed.
    match open_snapshot_daemon_first_read_only(layout).await {
        Ok(snapshot) => Ok(snapshot),
        Err(daemon_err) => {
            // 2. Offline/admin escape hatch: explicit local snapshot read.
            if daemon_bootstrap_admin_allowed() {
                tracing::warn!(
                    command = command_name,
                    error = %daemon_err,
                    "daemon unavailable; reading local snapshot directly (KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN)"
                );
                return open_snapshot_local(layout);
            }
            // 3. Friendly, actionable failure — no internal jargon.
            Err(kin_db::KinDbError::StorageError(format!(
                "{command_name} needs the Kin daemon, which could not be reached.\n\
                 Start it with `kin status` (it auto-starts the daemon) or run inside a Kin repo with a live daemon, then retry.\n\
                 For offline/admin use only, set KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN=1 to read the local snapshot directly.\n\
                 (daemon error: {daemon_err})"
            )))
        }
    }
}

/// Carry a failed daemon resolution into a channel that can only hold a string.
///
/// A store this build cannot open answers the question by itself, so it passes
/// through as the whole message rather than as a cause under a missing daemon.
/// Anything else keeps the daemon framing and brings its cause with it:
/// rendering an `anyhow` chain with `{error}` prints the outermost context only,
/// which reduced every failure here to "kin daemon is required but unavailable:
/// kin daemon is required".
fn daemon_resolution_storage_error(error: anyhow::Error) -> kin_db::KinDbError {
    if let Some(crate::daemon_client::AutoStartError::IncompatibleStore(message)) =
        error.downcast_ref::<crate::daemon_client::AutoStartError>()
    {
        return kin_db::KinDbError::StorageError(message.clone());
    }
    kin_db::KinDbError::StorageError(format!("kin daemon is required but unavailable: {error:#}"))
}

/// Whether the offline/admin local-snapshot escape hatch is enabled.
fn daemon_bootstrap_admin_allowed() -> bool {
    std::env::var("KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

async fn open_snapshot_daemon_first_with_mode(
    layout: &kin_core::KinLayout,
    read_only: bool,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let _span = tracing::info_span!(
        "kin.backend.open_snapshot_daemon_first",
        snapshot = %kindb_snapshot_path(layout).display(),
        read_only = read_only
    )
    .entered();
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await
        .map_err(daemon_resolution_storage_error)?
        .ok_or_else(|| {
            kin_db::KinDbError::StorageError(
                "kin daemon is required but no daemon endpoint is available".to_string(),
            )
        })?;

    // Try daemon bootstrap using the repo-scoped URL
    let snapshot = fetch_daemon_graph(&daemon_url, layout)
        .await
        .map_err(|error| {
            kin_db::KinDbError::StorageError(format!(
                "kin daemon bootstrap failed from {daemon_url}: {error}"
            ))
        })?;

    if !read_only {
        return Err(kin_db::KinDbError::StorageError(
            "writable CLI graph opens are disabled; use a daemon mutation endpoint".to_string(),
        ));
    }

    let graph = graph_from_bootstrap_snapshot(layout, snapshot, true)?;
    let snap =
        kin_db::SnapshotManager::from_bootstrap_graph_read_only(kindb_snapshot_path(layout), graph);
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Load the persisted HNSW vector index only when its sidecar metadata proves
/// that the model and graph root match this daemon bootstrap.
///
/// Non-fatal: absence or incompatibility leaves semantic search without an ANN
/// index. The unchecked loader is intentionally unavailable outside KinDB
/// tests because accepting a stale sidecar would return silently-wrong
/// neighbors.
#[cfg(feature = "vector")]
fn load_vector_index_if_exists(snap: &kin_db::SnapshotManager, layout: &kin_core::KinLayout) {
    let _span = tracing::info_span!(
        "kindb.load_vector_index_if_exists",
        path = %kindb_snapshot_path(layout).display()
    )
    .entered();
    let snapshot_path = kindb_snapshot_path(layout);
    let graph = snap.graph();
    match kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
        graph.as_ref(),
        &snapshot_path,
        None,
    ) {
        Ok(true) => {
            tracing::debug!(
                path = %vector_index_path(layout).display(),
                "loaded validated vector index from disk"
            );
        }
        Ok(false) => {
            tracing::debug!(
                path = %vector_index_path(layout).display(),
                "no compatible vector index available"
            );
        }
        Err(error) => {
            tracing::debug!(%error, "failed to validate vector index (non-fatal)");
        }
    }
}

#[cfg(not(feature = "vector"))]
fn load_vector_index_if_exists(_snap: &kin_db::SnapshotManager, _layout: &kin_core::KinLayout) {}

/// Fetch the graph from the daemon's `/graph/bootstrap` endpoint.
/// Returns `None` if the daemon is unreachable or returns an error.
fn graph_from_bootstrap_snapshot(
    layout: &kin_core::KinLayout,
    snapshot: kin_db::GraphSnapshot,
    read_only: bool,
) -> std::result::Result<kin_db::InMemoryGraph, kin_db::KinDbError> {
    // Prefer the on-disk text index's stored root hash so the hash check
    // passes without an expensive Merkle recomputation.  Falls back to
    // computing the hash from the snapshot when no text index exists.
    let ti_dir = layout.text_index_dir();
    let graph_root_hash = kin_db::TextIndex::peek_root_hash(&ti_dir)
        .unwrap_or_else(|| kin_db::compute_graph_root_hash(&snapshot));
    if read_only {
        kin_db::InMemoryGraph::from_snapshot_with_text_index_and_root_hash_read_only(
            snapshot,
            ti_dir,
            graph_root_hash,
        )
    } else {
        kin_db::InMemoryGraph::from_snapshot_with_text_index_and_root_hash(
            snapshot,
            ti_dir,
            graph_root_hash,
        )
    }
}

/// Attach the daemon's bearer token to a request built against a bare
/// `reqwest::Client` (as opposed to `DaemonClient`, which attaches this
/// automatically at construction). Every helper in this module talks to the
/// repo-scoped daemon directly rather than through `DaemonClient`, so each
/// one needs the token resolved from that repo's layout explicitly.
fn with_daemon_auth(
    request: reqwest::RequestBuilder,
    layout: &kin_core::KinLayout,
) -> reqwest::RequestBuilder {
    match crate::daemon_client::resolve_daemon_auth_token_for_layout(layout) {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

async fn fetch_daemon_graph(
    daemon_url: &str,
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::GraphSnapshot, String> {
    let _span = tracing::info_span!("kin.backend.fetch_daemon_graph").entered();
    let bootstrap_timeout_secs = std::env::var("KIN_DAEMON_BOOTSTRAP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(bootstrap_timeout_secs))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .map_err(|error| format!("build daemon bootstrap client: {error}"))?;

    let resp = with_daemon_auth(
        client.get(format!(
            "{}/graph/bootstrap",
            daemon_url.trim_end_matches('/')
        )),
        layout,
    )
    .send()
    .await
    .map_err(|error| format!("send graph bootstrap request: {error}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {body}"));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|error| format!("read graph bootstrap body: {error}"))?;
    kin_db::GraphSnapshot::from_bytes(&bytes)
        .map_err(|error| format!("decode graph bootstrap snapshot: {error}"))
}

// ── Daemon Mutation Helpers ────────────────────────────────────────────────

/// POST a fast-forward branch update to the repo-scoped daemon.
/// Fails instead of writing locally when the daemon is missing or rejects it.
pub async fn require_daemon_update_head(
    layout: &kin_core::KinLayout,
    branch_name: &str,
    head_id: &str,
    expected_head_id: &str,
) -> anyhow::Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or_else(|| {
            crate::daemon_client::running_daemon_required_error("branch head updates", layout)
        })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let payload = serde_json::json!({
        "head": head_id,
        "expected_head": expected_head_id,
    });

    let resp = with_daemon_auth(
        client.put(format!(
            "{}/v2/graph/branches/{}/head",
            daemon_url.trim_end_matches('/'),
            branch_name
        )),
        layout,
    )
    .json(&payload)
    .send()
    .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "daemon head update rejected for branch {branch_name}: HTTP {status}: {body}"
        );
    }
    Ok(())
}

/// POST a new SemanticChange (commit, merge, resolve) to the repo-scoped daemon.
/// Fails instead of writing locally when the daemon is missing or rejects it.
pub async fn require_daemon_commit(
    layout: &kin_core::KinLayout,
    change: &kin_model::SemanticChange,
    branch_name: &str,
) -> anyhow::Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or_else(|| {
            crate::daemon_client::running_daemon_required_error("semantic graph commits", layout)
        })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let payload = serde_json::json!({
        "change": change,
        "branch_name": branch_name,
    });

    let resp = with_daemon_auth(
        client.post(format!(
            "{}/v1/graph/commit",
            daemon_url.trim_end_matches('/')
        )),
        layout,
    )
    .json(&payload)
    .send()
    .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon commit rejected for branch {branch_name}: HTTP {status}: {body}");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonReleaseFailureKind {
    /// The daemon returned a non-retryable client/policy response, so the
    /// request did not become release authority.
    Definitive,
    /// A transport error, timeout, or exhausted 5xx response leaves the caller
    /// unable to know whether the daemon committed before the response failed.
    Uncertain,
}

#[derive(Debug)]
pub struct DaemonReleaseCommitError {
    pub kind: DaemonReleaseFailureKind,
    /// The daemon serialized this exact change against graph authority and
    /// explicitly proved it was not materialized before returning a stale-head
    /// rejection. A durable recovery journal may be abandoned instead of
    /// wedging every later release.
    pub safe_to_abandon: bool,
    message: String,
}

impl std::fmt::Display for DaemonReleaseCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DaemonReleaseCommitError {}

fn release_finalization_timeout() -> Duration {
    // A release request performs a full authority snapshot and durable
    // generation-marker finalization before responding. Ten seconds was a
    // normal mutation timeout, not a realistic finalization budget.
    Duration::from_secs(120)
}

async fn send_serialized_release_request(
    layout: &kin_core::KinLayout,
    daemon_url: &str,
    serialized_payload: &[u8],
    branch_name: &str,
    timeout: Duration,
    max_attempts: usize,
    initial_backoff: Duration,
) -> Result<(), DaemonReleaseCommitError> {
    let expected_change_id = serde_json::from_slice::<serde_json::Value>(serialized_payload)
        .ok()
        .and_then(|request| request.pointer("/change/id")?.as_str().map(str::to_owned));
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(|error| DaemonReleaseCommitError {
            kind: DaemonReleaseFailureKind::Uncertain,
            safe_to_abandon: false,
            message: format!("build daemon release client: {error}"),
        })?;
    let endpoint = format!("{}/v1/graph/commit", daemon_url.trim_end_matches('/'));
    let attempts = max_attempts.max(1);
    let mut backoff = initial_backoff;
    let mut last_uncertain = String::new();
    let mut saw_uncertain = false;

    for attempt in 0..attempts {
        let response = with_daemon_auth(
            client
                .post(&endpoint)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                // Clone the already-serialized bytes. Retries must never
                // regenerate the change, timestamp, ID, or JSON request.
                .body(serialized_payload.to_vec()),
            layout,
        )
        .send()
        .await;

        match response {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT =>
            {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                last_uncertain = format!("HTTP {status}: {body}");
                saw_uncertain = true;
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let kind = if saw_uncertain {
                    // A later rejection can describe the exact retry (for
                    // example, a stale-head 409) without proving that an
                    // earlier timed-out/5xx attempt was not committed. Keep
                    // the durable request journal until an exact retry
                    // succeeds.
                    DaemonReleaseFailureKind::Uncertain
                } else {
                    DaemonReleaseFailureKind::Definitive
                };
                return Err(DaemonReleaseCommitError {
                    kind,
                    safe_to_abandon: !saw_uncertain
                        && expected_change_id.as_deref().is_some_and(|change_id| {
                            stale_release_rejection_proves_change_absent(&body, change_id)
                        }),
                    message: if saw_uncertain {
                        format!(
                            "daemon release outcome remains uncertain for branch {branch_name}: an earlier exact-payload attempt had an uncertain outcome, then a retry was rejected with HTTP {status}: {body}"
                        )
                    } else {
                        format!(
                            "daemon release rejected for branch {branch_name}: HTTP {status}: {body}"
                        )
                    },
                });
            }
            Err(error) => {
                last_uncertain = format!("transport/finalization error: {error}");
                saw_uncertain = true;
            }
        }

        if attempt + 1 < attempts {
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2).min(Duration::from_secs(2));
        }
    }

    Err(DaemonReleaseCommitError {
        kind: DaemonReleaseFailureKind::Uncertain,
        safe_to_abandon: false,
        message: format!(
            "daemon release outcome is uncertain for branch {branch_name} after {attempts} exact-payload attempt(s): {last_uncertain}"
        ),
    })
}

/// POST an already-serialized release request and retry transport, timeout,
/// and 5xx outcomes with those exact bytes. The caller persists the payload
/// before calling so an exhausted uncertain result can be resumed by a later
/// process without manufacturing another marker.
pub async fn require_daemon_release_commit(
    layout: &kin_core::KinLayout,
    serialized_payload: &[u8],
    branch_name: &str,
) -> Result<(), DaemonReleaseCommitError> {
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await
        .map_err(|error| DaemonReleaseCommitError {
            kind: DaemonReleaseFailureKind::Uncertain,
            safe_to_abandon: false,
            message: format!("start or resolve Kin daemon for pending semantic release: {error:#}"),
        })?
        .ok_or_else(|| DaemonReleaseCommitError {
            kind: DaemonReleaseFailureKind::Uncertain,
            safe_to_abandon: false,
            message: "Kin daemon is disabled; exact semantic release request remains pending"
                .to_string(),
        })?;
    send_serialized_release_request(
        layout,
        &daemon_url,
        serialized_payload,
        branch_name,
        release_finalization_timeout(),
        3,
        Duration::from_millis(100),
    )
    .await
}

fn stale_release_rejection_proves_change_absent(body: &str, expected_change_id: &str) -> bool {
    let Ok(body) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    body.get("error").and_then(serde_json::Value::as_str) == Some("stale_branch_head")
        && body
            .get("mutation_applied")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && body
            .get("change_materialized")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && body.get("change_id").and_then(serde_json::Value::as_str) == Some(expected_change_id)
}

/// Build the canonical daemon request bytes once. These bytes are persisted
/// and reused verbatim for every recovery attempt.
pub fn serialize_daemon_release_request(
    change: &kin_model::SemanticChange,
    branch_name: &str,
    force: bool,
    require_proof: bool,
    require_approval: bool,
) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "change": change,
        "branch_name": branch_name,
        "release_policy": {
            "force": force,
            "require_proof": require_proof,
            "require_approval": require_approval,
        },
    }))
    .map_err(Into::into)
}

#[derive(Default, serde::Serialize)]
pub struct GraphMutationBatch {
    #[serde(default)]
    pub work_items: Vec<kin_model::WorkItem>,
    #[serde(default)]
    pub work_links: Vec<kin_model::WorkLink>,
    #[serde(default)]
    pub annotations: Vec<kin_model::Annotation>,
    #[serde(default)]
    pub work_status_updates: Vec<WorkStatusMutation>,
    #[serde(default)]
    pub audit_events: Vec<AuditMutation>,
}

#[derive(serde::Serialize)]
pub struct WorkStatusMutation {
    pub work_id: kin_model::WorkId,
    pub status: kin_model::WorkStatus,
}

#[derive(serde::Serialize)]
pub struct AuditMutation {
    pub action: String,
    pub target_scope: Option<kin_model::WorkScope>,
    pub details: Option<String>,
}

/// Apply non-change graph mutations through the repo-scoped daemon.
pub async fn require_daemon_graph_mutations(
    layout: &kin_core::KinLayout,
    batch: GraphMutationBatch,
) -> anyhow::Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("graph mutations", layout))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let resp = with_daemon_auth(
        client.post(format!(
            "{}/v1/graph/mutations",
            daemon_url.trim_end_matches('/')
        )),
        layout,
    )
    .json(&batch)
    .send()
    .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon graph mutation failed: HTTP {status}: {body}");
    }
    Ok(())
}

// ── Spine Federation Helpers ──────────────────────────────────────────────

/// Query the daemon for federated impact analysis across the spine.
///
/// Returns a [`kin_spine::SpineQuery`] so the caller can tell apart a spine
/// that is not configured (no daemon endpoint), one that is configured but
/// unreachable/non-2xx (e.g. `503` when the spine is disabled), and a healthy
/// answer that is genuinely empty — instead of collapsing a transport/HTTP
/// failure into a silent "no impact" result. Mirrors [`get_spine_xref`].
pub async fn get_spine_impact(
    layout: &kin_core::KinLayout,
    repo_id: &str,
    entity_id: &kin_model::EntityId,
    depth: u32,
) -> anyhow::Result<::kin_spine::SpineQuery<::kin_spine::FederatedImpact>> {
    use ::kin_spine::{classify_spine_probe, SpineProbe, SpineQuery};

    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(SpineQuery::NotConfigured);
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = with_daemon_auth(
        client.get(format!("{}/spine/impact", daemon_url.trim_end_matches('/'))),
        layout,
    )
    .query(&[
        ("repo", repo_id),
        ("entity", &entity_id.to_string()),
        ("depth", &depth.to_string()),
    ])
    .send()
    .await;
    let status = resp.as_ref().ok().map(|r| r.status().as_u16());

    match classify_spine_probe(true, status) {
        SpineProbe::Healthy => {
            let impact = resp?.json::<::kin_spine::FederatedImpact>().await?;
            Ok(SpineQuery::Found(impact))
        }
        SpineProbe::Unavailable(reason) => Ok(SpineQuery::Unavailable(reason)),
        SpineProbe::NotConfigured => Ok(SpineQuery::Unavailable(
            "spine endpoint unexpectedly unconfigured".to_string(),
        )),
    }
}

/// Query the daemon for cross-repo edges (xrefs) for a specific entity.
///
/// Returns a [`kin_spine::SpineQuery`] so the caller can tell apart a spine
/// that is not configured (no daemon endpoint), one that is configured but
/// unreachable/non-2xx (e.g. `503` when the spine is disabled), and a healthy
/// answer that is genuinely empty — instead of collapsing the failure into a
/// silent "no references" result.
pub async fn get_spine_xref(
    layout: &kin_core::KinLayout,
    repo_id: &str,
    entity_id: &kin_model::EntityId,
) -> anyhow::Result<::kin_spine::SpineQuery<::kin_spine::SpineXrefResponse>> {
    use ::kin_spine::{classify_spine_probe, SpineProbe, SpineQuery};

    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(SpineQuery::NotConfigured);
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = with_daemon_auth(
        client.get(format!("{}/spine/xref", daemon_url.trim_end_matches('/'))),
        layout,
    )
    .query(&[("repo", repo_id), ("entity", &entity_id.to_string())])
    .send()
    .await;
    let status = resp.as_ref().ok().map(|r| r.status().as_u16());

    match classify_spine_probe(true, status) {
        SpineProbe::Healthy => {
            let bytes = resp?.bytes().await?;
            let body = ::kin_spine::SpineXrefResponse::from_slice_for(&bytes, repo_id, entity_id)?;
            Ok(SpineQuery::Found(body))
        }
        SpineProbe::Unavailable(reason) => Ok(SpineQuery::Unavailable(reason)),
        SpineProbe::NotConfigured => Ok(SpineQuery::Unavailable(
            "spine endpoint unexpectedly unconfigured".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{send_serialized_release_request, stale_release_rejection_proves_change_absent};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use kin_model::EntityStore;
    use kin_model::WorkStore;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        Hash256, LanguageId, RetrievalKey, SemanticFingerprint, Visibility,
    };

    #[derive(Clone, Default)]
    struct ReleaseRetryServerState {
        attempts: Arc<AtomicUsize>,
        received: Arc<Mutex<Vec<Vec<u8>>>>,
        markers: Arc<Mutex<HashSet<String>>>,
        head: Arc<Mutex<Option<String>>>,
        first_response: Arc<Mutex<Option<StatusCode>>>,
        first_delay: Arc<Mutex<Option<Duration>>>,
        later_response: Arc<Mutex<Option<StatusCode>>>,
    }

    async fn release_retry_handler(
        State(state): State<ReleaseRetryServerState>,
        body: Bytes,
    ) -> StatusCode {
        state.received.lock().unwrap().push(body.to_vec());
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let change_id = request["change"]["id"].as_str().unwrap().to_string();
        state.markers.lock().unwrap().insert(change_id.clone());
        *state.head.lock().unwrap() = Some(change_id);

        if state.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            let delay = *state.first_delay.lock().unwrap();
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            return state
                .first_response
                .lock()
                .unwrap()
                .unwrap_or(StatusCode::OK);
        }
        state
            .later_response
            .lock()
            .unwrap()
            .unwrap_or(StatusCode::OK)
    }

    async fn release_retry_server(
        state: ReleaseRetryServerState,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/v1/graph/commit", post(release_retry_handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    fn serialized_release_fixture() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "change": {
                "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "parents": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
                "author": "kin-release",
                "message": "release: v0.3.0",
            },
            "branch_name": "main",
            "release_policy": {
                "force": true,
                "require_proof": false,
                "require_approval": false,
            }
        }))
        .unwrap()
    }

    #[test]
    fn only_identity_bound_stale_rejection_proves_pending_change_absent() {
        let expected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let exact = serde_json::json!({
            "error": "stale_branch_head",
            "mutation_applied": false,
            "change_materialized": false,
            "change_id": expected,
        })
        .to_string();
        assert!(stale_release_rejection_proves_change_absent(
            &exact, expected
        ));

        for body in [
            serde_json::json!({
                "error": "stale_branch_head",
                "mutation_applied": false,
                "change_materialized": false,
                "change_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            })
            .to_string(),
            serde_json::json!({
                "error": "stale_branch_head",
                "mutation_applied": false,
                "change_materialized": true,
                "change_id": expected,
            })
            .to_string(),
            serde_json::json!({
                "error": "stale_branch_head",
                "mutation_applied": false,
                "change_id": expected,
            })
            .to_string(),
            serde_json::json!({
                "error": "release_policy_failed",
                "mutation_applied": false,
                "change_materialized": false,
                "change_id": expected,
            })
            .to_string(),
            "not-json".to_string(),
        ] {
            assert!(!stale_release_rejection_proves_change_absent(
                &body, expected
            ));
        }
    }

    #[tokio::test]
    async fn release_5xx_retry_reuses_identical_serialized_bytes() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let state = ReleaseRetryServerState::default();
        *state.first_response.lock().unwrap() = Some(StatusCode::INTERNAL_SERVER_ERROR);
        let (url, server) = release_retry_server(state.clone()).await;
        let payload = serialized_release_fixture();

        send_serialized_release_request(
            &layout,
            &url,
            &payload,
            "main",
            Duration::from_secs(1),
            3,
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        server.abort();

        let received = state.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert!(received.iter().all(|request| request == &payload));
    }

    #[tokio::test]
    async fn release_timeout_retry_keeps_exactly_one_marker_and_head() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let state = ReleaseRetryServerState::default();
        *state.first_delay.lock().unwrap() = Some(Duration::from_millis(80));
        let (url, server) = release_retry_server(state.clone()).await;
        let payload = serialized_release_fixture();

        send_serialized_release_request(
            &layout,
            &url,
            &payload,
            "main",
            Duration::from_millis(20),
            3,
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        server.abort();

        let received = state.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert!(received.iter().all(|request| request == &payload));
        let markers = state.markers.lock().unwrap();
        assert_eq!(
            markers.len(),
            1,
            "timeout retry manufactured a second marker"
        );
        assert_eq!(
            state.head.lock().unwrap().as_deref(),
            markers.iter().next().map(String::as_str)
        );
    }

    #[tokio::test]
    async fn release_retry_rejection_after_request_timeout_remains_uncertain() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let state = ReleaseRetryServerState::default();
        *state.first_response.lock().unwrap() = Some(StatusCode::REQUEST_TIMEOUT);
        *state.later_response.lock().unwrap() = Some(StatusCode::CONFLICT);
        let (url, server) = release_retry_server(state.clone()).await;
        let payload = serialized_release_fixture();

        let error = send_serialized_release_request(
            &layout,
            &url,
            &payload,
            "main",
            Duration::from_secs(1),
            2,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();
        server.abort();

        assert_eq!(error.kind, super::DaemonReleaseFailureKind::Uncertain);
        assert!(
            error.to_string().contains("HTTP 409 Conflict"),
            "later rejection must stay attached to the uncertain result: {error}"
        );
        let received = state.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert!(received.iter().all(|request| request == &payload));
        let markers = state.markers.lock().unwrap();
        assert_eq!(markers.len(), 1);
        assert_eq!(
            state.head.lock().unwrap().as_deref(),
            markers.iter().next().map(String::as_str)
        );
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(format!("doc for {name}")),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn bootstrap_graph_preserves_persistent_text_index_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path();
        let layout = kin_core::init(repo_root).unwrap().layout;

        let source = kin_db::InMemoryGraph::with_text_index(layout.text_index_dir());
        let entity = test_entity("bootstrap_entity");
        source.upsert_entity(&entity).unwrap();
        let snapshot = source.to_snapshot();
        let expected_root = kin_db::compute_graph_root_hash(&snapshot);
        // The sidecar records the retrieval-authority digest, not the legacy
        // graph root. The legacy root covers entity and relation topology only,
        // so it cannot detect an exact repository-tree or artifact-enrichment
        // change that moves retrieval results. Bind the identity the sidecar
        // actually carries.
        let expected_sidecar_identity =
            kin_db::storage::compute_retrieval_authority_hash(&snapshot);

        let graph = kin_db::InMemoryGraph::from_snapshot_with_text_index_and_root_hash(
            snapshot,
            layout.text_index_dir(),
            expected_root,
        )
        .unwrap();
        kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), &graph).unwrap();

        let persisted = kin_db::TextIndex::open_read_only(Some(&layout.text_index_dir())).unwrap();
        assert_eq!(persisted.graph_root_hash(), Some(expected_sidecar_identity));
        let reopened_hits = persisted.fuzzy_search("bootstrap_entity", 10).unwrap();
        assert!(
            reopened_hits
                .iter()
                .any(|(key, _)| *key == RetrievalKey::Entity(entity.id)),
            "persisted text index should reopen with the bootstrap entity queryable"
        );
        let monolithic = layout.text_index_dir().join("index.bin");
        let segmented_manifest = layout.text_index_dir().join("index.bin.kinseg-manifest");
        assert!(
            monolithic.exists() || segmented_manifest.exists(),
            "persistent text index should leave either monolithic or segmented sidecar storage"
        );
    }

    #[test]
    fn work_only_mutation_changes_repo_truth_hash() {
        let graph = kin_db::InMemoryGraph::new();
        let snap_before = graph.to_snapshot();
        let hash_before = kin_db::compute_repo_truth_hash(&snap_before);

        let item = kin_model::WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: kin_model::WorkKind::Task,
            title: "regression test".into(),
            description: String::new(),
            status: kin_model::WorkStatus::Proposed,
            priority: kin_model::Priority::None,
            scopes: vec![],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: kin_model::IdentityRef::human("test"),
            created_at: kin_model::Timestamp::now(),
        };
        graph.create_work_item(&item).unwrap();
        let snap_after = graph.to_snapshot();
        let hash_after = kin_db::compute_repo_truth_hash(&snap_after);

        assert_ne!(
            hash_before, hash_after,
            "work-only mutation must change repo truth hash"
        );

        let entity_hash_before = kin_db::compute_graph_root_hash(&snap_before);
        let entity_hash_after = kin_db::compute_graph_root_hash(&snap_after);
        assert_eq!(
            entity_hash_before, entity_hash_after,
            "entity-only hash should be unchanged"
        );
    }
}
