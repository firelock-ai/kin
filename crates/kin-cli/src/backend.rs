// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! KinDB graph backend — daemon-as-runtime.
//!
//! The primary entry point is [`open_snapshot_daemon_first`] which auto-starts
//! the daemon if needed, then fetches the warm graph from the daemon's
//! `/graph/bootstrap` endpoint. Falls back to the local snapshot only when
//! the daemon fails to start.
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
/// and as the offline fallback in [`open_snapshot_daemon_first`].
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
/// Used by read-only commands that don't need daemon federation.
pub fn open_snapshot_local(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let snap = open_kindb_snapshot_with_mode(layout, true)?;
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Open snapshot directly from disk using the lightweight locate-only
/// read path. This skips decoding persisted adjacency lists and unrelated
/// domains that `kin locate` never touches.
pub fn open_snapshot_local_for_locate(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let snap = kin_db::SnapshotManager::open_read_only_for_locate(kindb_snapshot_path(layout))?;
    load_vector_index_if_exists(&snap, layout);
    Ok(snap)
}

/// Daemon-first graph open: auto-starts the daemon if needed, then fetches
/// the warm, authoritative graph snapshot from the daemon's `/graph/bootstrap`
/// endpoint. Falls back to the local snapshot only when the daemon fails
/// to start.
///
/// When the daemon is reachable the returned `SnapshotManager` holds:
///   - the daemon's live graph (swapped in via RCU)
///   - the local snapshot path + lock (so `.save()` still persists locally)
///
/// This makes every CLI command daemon-consistent without changing callers.
/// Also loads the HNSW vector index if it exists on disk, enabling semantic
/// search in `kin locate` and `kin search --semantic`.
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
    // Auto-start daemon if not running. On failure, fall back to direct snapshot.
    // The returned URL is repo-scoped (each repo gets its own port).
    // KIN_NO_DAEMON=1: skip auto-start but still connect to an already-running
    // daemon (benchmark harnesses start their own daemons separately).
    let no_daemon_autostart = std::env::var("KIN_NO_DAEMON").unwrap_or_default() == "1";
    let explicit_daemon_url = std::env::var("KIN_DAEMON_URL").ok();
    let daemon_url = if no_daemon_autostart {
        // Benchmark harnesses may provide an explicit daemon URL while also
        // disabling CLI auto-start. Prefer that URL over repo-local discovery.
        explicit_daemon_url.clone().or_else(|| {
            crate::daemon_client::daemon_is_up(layout.root())
                .map(|port| format!("http://127.0.0.1:{port}"))
        })
    } else {
        match crate::daemon_client::ensure_daemon_running(layout.root()).await {
            Ok(url) => Some(url),
            Err(e) => {
                tracing::warn!(error = %e, "daemon auto-start failed, falling back to direct snapshot");
                None
            }
        }
    };

    // Try daemon bootstrap using the repo-scoped URL
    match fetch_daemon_graph(daemon_url.as_deref()).await {
        Some(snapshot) => {
            if read_only && explicit_daemon_url.is_some() {
                let graph = graph_from_bootstrap_snapshot(layout, snapshot, true);
                let snap = kin_db::SnapshotManager::from_bootstrap_graph_read_only(
                    kindb_snapshot_path(layout),
                    graph,
                );
                load_vector_index_if_exists(&snap, layout);
                return Ok(snap);
            }

            let snap = open_kindb_snapshot_with_mode(layout, read_only)?;
            let daemon_root = kin_db::compute_graph_root_hash(&snapshot);
            let local_graph = snap.graph();
            let local_root = kin_db::compute_graph_root_hash(&local_graph.to_snapshot());

            if should_use_daemon_bootstrap(&local_graph, &snapshot) {
                let graph = graph_from_bootstrap_snapshot(layout, snapshot, read_only);
                snap.swap(graph);
            } else {
                tracing::debug!(
                    local_root = %hex::encode(local_root),
                    daemon_root = %hex::encode(daemon_root),
                    "skipping daemon bootstrap because local repo snapshot does not match daemon graph"
                );
            }
            load_vector_index_if_exists(&snap, layout);
            Ok(snap)
        }
        None => {
            let snap = open_kindb_snapshot_with_mode(layout, read_only)?;
            load_vector_index_if_exists(&snap, layout);
            Ok(snap)
        }
    }
}

/// Load the persisted HNSW vector index into the graph if available.
/// Non-fatal: if the file doesn't exist or fails to load, semantic search
/// gracefully returns empty results.
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

fn should_use_daemon_bootstrap(
    local_graph: &kin_db::InMemoryGraph,
    daemon_snapshot: &kin_db::GraphSnapshot,
) -> bool {
    let local_snapshot = local_graph.to_snapshot();
    let local_hash = kin_db::compute_repo_truth_hash(&local_snapshot);
    let daemon_hash = kin_db::compute_repo_truth_hash(daemon_snapshot);
    if local_hash == daemon_hash {
        return true;
    }
    let empty_hash = kin_db::compute_repo_truth_hash(&kin_db::GraphSnapshot::empty());
    local_hash == empty_hash
}

async fn fetch_daemon_graph(daemon_url: Option<&str>) -> Option<kin_db::GraphSnapshot> {
    let _span = tracing::info_span!("kin.backend.fetch_daemon_graph").entered();
    let base_url = daemon_url
        .map(|s| s.to_string())
        .or_else(|| std::env::var("KIN_DAEMON_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:4219".to_string());
    let bootstrap_timeout_secs = std::env::var("KIN_DAEMON_BOOTSTRAP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(bootstrap_timeout_secs))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let resp = client
        .get(format!(
            "{}/graph/bootstrap",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let bytes = resp.bytes().await.ok()?;
    kin_db::GraphSnapshot::from_bytes(&bytes).ok()
}

// ── Daemon Mutation Helpers ────────────────────────────────────────────────

/// Attempt to POST a fast-forward branch update to the daemon.
/// Returns true if the daemon accepted it; false if unreachable.
pub fn try_daemon_update_head(branch_name: &str, head_id: &str) -> anyhow::Result<bool> {
    let daemon_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let payload = serde_json::json!({
        "head": head_id,
    });

    let resp = client
        .put(format!(
            "{}/v1/graph/branches/{}/head",
            daemon_url.trim_end_matches('/'),
            branch_name
        ))
        .json(&payload)
        .send()?;

    let ok = resp.status().is_success();
    if !ok {
        tracing::debug!(status = %resp.status(), branch = branch_name, "daemon head update rejected");
    }
    Ok(ok)
}

/// Attempt to POST a new SemanticChange (commit, merge, resolve) to the daemon.
/// Returns true if the daemon accepted it; false if unreachable.
pub fn try_daemon_commit(
    change: &kin_model::SemanticChange,
    branch_name: &str,
) -> anyhow::Result<bool> {
    let daemon_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let payload = serde_json::json!({
        "change": change,
        "branch_name": branch_name,
    });

    let resp = client
        .post(format!(
            "{}/v1/graph/commit",
            daemon_url.trim_end_matches('/')
        ))
        .json(&payload)
        .send()?;

    let ok = resp.status().is_success();
    if !ok {
        tracing::debug!(status = %resp.status(), branch = branch_name, "daemon commit rejected");
    }
    Ok(ok)
}

// ── Spine Federation Helpers ──────────────────────────────────────────────

/// Query the daemon for federated impact analysis across the spine.
pub async fn get_spine_impact(
    repo_id: &str,
    entity_id: &kin_model::EntityId,
    depth: u32,
) -> anyhow::Result<Option<::kin_spine::FederatedImpact>> {
    let daemon_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(format!(
            "{}/v1/spine/impact",
            daemon_url.trim_end_matches('/')
        ))
        .query(&[
            ("repo", repo_id),
            ("entity", &entity_id.to_string()),
            ("depth", &depth.to_string()),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let impact = resp.json::<::kin_spine::FederatedImpact>().await?;
    Ok(Some(impact))
}

/// Query the daemon for cross-repo edges (xrefs) for a specific entity.
pub async fn get_spine_xref(
    repo_id: &str,
    entity_id: &kin_model::EntityId,
) -> anyhow::Result<Option<Vec<::kin_spine::CrossRepoEdge>>> {
    let daemon_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(format!(
            "{}/v1/spine/xref",
            daemon_url.trim_end_matches('/')
        ))
        .query(&[("repo", repo_id), ("entity", &entity_id.to_string())])
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body: serde_json::Value = resp.json().await?;
    let edges = serde_json::from_value(body["edges"].clone())?;
    Ok(Some(edges))
}

#[cfg(test)]
mod tests {
    use super::should_use_daemon_bootstrap;
    use kin_model::EntityStore;
    use kin_model::WorkStore;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        Hash256, LanguageId, SemanticFingerprint, Visibility,
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
        source
            .upsert_entity(&test_entity("bootstrap_entity"))
            .unwrap();
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
        assert!(layout.text_index_dir().join("index.bin").exists());
    }

    #[test]
    fn daemon_bootstrap_is_rejected_when_local_repo_truth_differs() {
        let local = kin_db::InMemoryGraph::new();
        local.upsert_entity(&test_entity("local_only")).unwrap();

        let daemon = kin_db::InMemoryGraph::new();
        daemon.upsert_entity(&test_entity("daemon_only")).unwrap();
        let daemon_snapshot = daemon.to_snapshot();

        assert!(!should_use_daemon_bootstrap(&local, &daemon_snapshot));
    }

    #[test]
    fn daemon_bootstrap_is_allowed_for_empty_local_graph() {
        let local = kin_db::InMemoryGraph::new();

        let daemon = kin_db::InMemoryGraph::new();
        daemon.upsert_entity(&test_entity("daemon_only")).unwrap();
        let daemon_snapshot = daemon.to_snapshot();

        assert!(should_use_daemon_bootstrap(&local, &daemon_snapshot));
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

    #[test]
    fn daemon_bootstrap_rejected_when_local_has_work_items() {
        let local = kin_db::InMemoryGraph::new();
        let item = kin_model::WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: kin_model::WorkKind::Task,
            title: "local work".into(),
            description: String::new(),
            status: kin_model::WorkStatus::Proposed,
            priority: kin_model::Priority::None,
            scopes: vec![],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: kin_model::IdentityRef::human("test"),
            created_at: kin_model::Timestamp::now(),
        };
        local.create_work_item(&item).unwrap();

        let daemon = kin_db::InMemoryGraph::new();
        let daemon_snapshot = daemon.to_snapshot();

        assert!(
            !should_use_daemon_bootstrap(&local, &daemon_snapshot),
            "must reject daemon bootstrap when local has work items that daemon lacks"
        );
    }
}
