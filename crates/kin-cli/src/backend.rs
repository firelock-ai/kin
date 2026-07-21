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
        .map_err(|error| {
            kin_db::KinDbError::StorageError(format!(
                "kin daemon is required but unavailable: {error}"
            ))
        })?
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

    let graph = graph_from_bootstrap_snapshot(layout, snapshot, true);
    let snap =
        kin_db::SnapshotManager::from_bootstrap_graph_read_only(kindb_snapshot_path(layout), graph);
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Load the persisted HNSW vector index into the graph if available.
/// Non-fatal: if the file doesn't exist or fails to load, semantic search
/// gracefully returns empty results.
#[cfg(feature = "vector")]
fn load_vector_index_if_exists(snap: &kin_db::SnapshotManager, layout: &kin_core::KinLayout) {
    let _span = tracing::info_span!(
        "kindb.load_vector_index_if_exists",
        path = %vector_index_path(layout).display()
    )
    .entered();
    let path = vector_index_path(layout);
    if path.exists() {
        let graph = snap.graph();
        match graph.load_vector_index(&path) {
            Ok(count) => {
                if count > 0 {
                    tracing::debug!(count, path = %path.display(), "loaded vector index from disk");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed to load vector index (non-fatal)");
            }
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
) -> kin_db::InMemoryGraph {
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
) -> anyhow::Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for branch head updates"))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let payload = serde_json::json!({
        "head": head_id,
    });

    let resp = with_daemon_auth(
        client.put(format!(
            "{}/v1/graph/branches/{}/head",
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
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for semantic graph commits"))?;
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
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for graph mutations"))?;
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
        client.get(format!(
            "{}/v1/spine/impact",
            daemon_url.trim_end_matches('/')
        )),
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
) -> anyhow::Result<::kin_spine::SpineQuery<Vec<::kin_spine::CrossRepoEdge>>> {
    use ::kin_spine::{classify_spine_probe, SpineProbe, SpineQuery};

    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(SpineQuery::NotConfigured);
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = with_daemon_auth(
        client.get(format!(
            "{}/v1/spine/xref",
            daemon_url.trim_end_matches('/')
        )),
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
            Ok(SpineQuery::Found(body.edges))
        }
        SpineProbe::Unavailable(reason) => Ok(SpineQuery::Unavailable(reason)),
        SpineProbe::NotConfigured => Ok(SpineQuery::Unavailable(
            "spine endpoint unexpectedly unconfigured".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use kin_model::EntityStore;
    use kin_model::WorkStore;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        Hash256, LanguageId, RetrievalKey, SemanticFingerprint, Visibility,
    };

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

        let graph = kin_db::InMemoryGraph::from_snapshot_with_text_index_and_root_hash(
            snapshot,
            layout.text_index_dir(),
            expected_root,
        );
        kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), &graph).unwrap();

        let persisted = kin_db::TextIndex::open_read_only(Some(&layout.text_index_dir())).unwrap();
        assert_eq!(persisted.graph_root_hash(), Some(expected_root));
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
