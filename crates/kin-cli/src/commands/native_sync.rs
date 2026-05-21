// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use kin_model::{FilePathId, Hash256};
use serde::Deserialize;

use crate::commands::remote;

const IGNORED_WORKTREE_DIRS: &[&str] = &[".git", ".git-export", ".kin"];

#[derive(Debug, Clone)]
pub(crate) struct NativeRepoSnapshot {
    pub default_branch: String,
    pub files: Vec<NativeRepoFile>,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeRepoFile {
    pub path: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NativeSyncStats {
    pub written_files: usize,
    pub removed_files: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeRepoSnapshotResponse {
    repository: NativeRepoRepository,
    files: Vec<NativeRepoSnapshotFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeRepoRepository {
    default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NativeRepoSnapshotFile {
    path: String,
    content: String,
}

fn native_repo_snapshot_endpoint(target: &remote::NativeRemoteTarget) -> String {
    format!("{}/snapshot", target.repo_locator())
}

fn resolve_repo_file_path(root: &Path, relative_path: &str) -> Result<PathBuf> {
    let candidate = Path::new(relative_path);
    if candidate.is_absolute() {
        anyhow::bail!(
            "native sync rejected absolute remote path: {}",
            relative_path
        );
    }

    if candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!(
            "native sync rejected escaping remote path: {}",
            relative_path
        );
    }

    Ok(root.join(candidate))
}

async fn fetch_native_repo_snapshot(
    client: &reqwest::Client,
    target: &remote::NativeRemoteTarget,
) -> Result<NativeRepoSnapshotResponse> {
    let response = remote::attach_native_remote_auth(
        client.get(native_repo_snapshot_endpoint(target)),
        &target.base_url,
    )
    .send()
    .await?;
    let status = response.status();
    let payload = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to fetch KinLab snapshot from {}: {} {}",
            target.repo_locator(),
            status,
            payload.trim()
        );
    }
    Ok(serde_json::from_str(&payload)?)
}

pub(crate) async fn fetch_snapshot(
    target: &remote::NativeRemoteTarget,
) -> Result<NativeRepoSnapshot> {
    let client = reqwest::Client::new();
    let repo_snapshot = fetch_native_repo_snapshot(&client, target).await?;
    let mut files = Vec::with_capacity(repo_snapshot.files.len());
    for file in repo_snapshot.files {
        files.push(NativeRepoFile {
            path: file.path,
            content: file.content.into_bytes(),
        });
    }

    Ok(NativeRepoSnapshot {
        default_branch: repo_snapshot
            .repository
            .default_branch
            .unwrap_or_else(|| "main".to_string()),
        files,
    })
}

fn hash_bytes(bytes: &[u8]) -> Hash256 {
    kin_blobs::digest(bytes)
}

fn open_snapshot_daemon_first_blocking(
    layout: &kin_core::KinLayout,
) -> Result<kin_db::SnapshotManager> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build runtime for graph access: {}", e))?;
    runtime
        .block_on(crate::backend::open_snapshot_explicit_admin_read_only(
            layout,
            "kin native sync",
        ))
        .map_err(|e| anyhow::anyhow!("failed to open graph store: {}", e))
}

fn collect_workspace_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut collected = Vec::new();
    collect_workspace_files_recursive(root, root, &mut collected)?;
    Ok(collected)
}

fn collect_workspace_files_recursive(
    workspace_root: &Path,
    current: &Path,
    collected: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("failed to inspect {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let relative = path.strip_prefix(workspace_root).unwrap_or(&path);

        if file_type.is_dir() {
            if relative.components().count() == 1 {
                let name = relative.to_string_lossy();
                if IGNORED_WORKTREE_DIRS.contains(&name.as_ref()) {
                    continue;
                }
            }
            collect_workspace_files_recursive(workspace_root, &path, collected)?;
            continue;
        }

        if file_type.is_file() {
            collected.push(path);
        }
    }
    Ok(())
}

pub(crate) fn ensure_clean_working_tree(
    layout: &kin_core::KinLayout,
) -> Result<HashMap<FilePathId, Hash256>> {
    let snap = open_snapshot_daemon_first_blocking(layout)?;
    let graph = &*snap.graph();
    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' is missing from the local graph",
            branch_name
        )
    })?;
    let genesis = kin_core::build_genesis_change();
    let current_tree = kin_core::build_file_tree(graph, &genesis.id, &branch.head)?;
    let source_root = kin_core::source_dir(layout);
    let workspace_files = collect_workspace_files(&source_root)?;
    let mut seen_paths = HashSet::new();

    for file_path in workspace_files {
        let relative = file_path
            .strip_prefix(&source_root)
            .with_context(|| format!("failed to relativize {}", file_path.display()))?
            .to_string_lossy()
            .to_string();
        let file_id = FilePathId::new(&relative);
        let expected_hash = current_tree.get(&file_id).ok_or_else(|| {
            anyhow::anyhow!(
                "working tree has uncommitted file '{}'. Commit or remove local changes before `kin pull`.",
                relative
            )
        })?;
        let bytes = fs::read(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;
        if hash_bytes(&bytes) != *expected_hash {
            anyhow::bail!(
                "working tree has uncommitted changes in '{}'. Commit or discard local changes before `kin pull`.",
                relative
            );
        }
        seen_paths.insert(relative);
    }

    for file_id in current_tree.keys() {
        if !seen_paths.contains(&file_id.0) {
            anyhow::bail!(
                "working tree is missing tracked file '{}'. Restore or commit local changes before `kin pull`.",
                file_id.0
            );
        }
    }

    Ok(current_tree)
}

pub(crate) fn sync_snapshot_to_working_tree(
    layout: &kin_core::KinLayout,
    snapshot: &NativeRepoSnapshot,
    current_tree: &HashMap<FilePathId, Hash256>,
) -> Result<NativeSyncStats> {
    let workspace_root = kin_core::source_dir(layout);
    let mut stats = NativeSyncStats::default();
    let mut remote_paths = HashSet::new();

    for file in &snapshot.files {
        remote_paths.insert(file.path.clone());
    }

    for file_id in current_tree.keys() {
        if remote_paths.contains(&file_id.0) {
            continue;
        }
        let path = resolve_repo_file_path(&workspace_root, &file_id.0)?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            prune_empty_parent_dirs(&workspace_root, path.parent());
            stats.removed_files += 1;
        }
    }

    for file in &snapshot.files {
        let destination = resolve_repo_file_path(&workspace_root, &file.path)?;
        let current_hash = current_tree.get(&FilePathId::new(&file.path));
        let incoming_hash = hash_bytes(&file.content);
        if current_hash.is_some_and(|existing| *existing == incoming_hash) {
            continue;
        }

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&destination, &file.content)
            .with_context(|| format!("failed to write {}", destination.display()))?;
        stats.written_files += 1;
    }

    Ok(stats)
}

fn prune_empty_parent_dirs(workspace_root: &Path, mut current: Option<&Path>) {
    while let Some(dir) = current {
        if dir == workspace_root {
            break;
        }
        match fs::remove_dir(dir) {
            Ok(()) => current = dir.parent(),
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Delta sync: request only changed files since last sync
// ---------------------------------------------------------------------------

/// A delta response from the remote containing only changed files.
#[derive(Debug, Clone)]
pub(crate) struct NativeRepoDelta {
    pub default_branch: String,
    /// The remote semantic head after this delta.
    pub remote_head: String,
    /// Files that were added or modified since the `since` timestamp.
    pub changed_files: Vec<NativeRepoFile>,
    /// Paths of files that were removed since the `since` timestamp.
    pub removed_paths: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NativeDeltaSyncStats {
    pub written_files: usize,
    pub removed_files: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeRepoDeltaResponse {
    repository: NativeRepoRepository,
    /// The remote semantic head after this delta.
    remote_head: String,
    /// Files added or modified since the requested point.
    #[serde(default)]
    changed_files: Vec<NativeRepoSnapshotFile>,
    /// Paths removed since the requested point.
    #[serde(default)]
    removed_paths: Vec<String>,
}

fn native_repo_delta_endpoint(
    target: &remote::NativeRemoteTarget,
    since: &chrono::DateTime<chrono::Utc>,
    since_head: &str,
) -> String {
    format!(
        "{}/delta?since={}&sinceHead={}",
        target.repo_locator(),
        urlencoded(&since.to_rfc3339()),
        urlencoded(since_head),
    )
}

/// Minimal percent-encoding for URL query parameters.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Attempt to fetch a delta from the remote. Returns `Ok(None)` if the remote
/// does not support delta sync (404 or missing endpoint), so callers can fall
/// back to full snapshot.
pub(crate) async fn fetch_delta(
    target: &remote::NativeRemoteTarget,
    since: &chrono::DateTime<chrono::Utc>,
    since_head: &str,
) -> Result<Option<NativeRepoDelta>> {
    let client = reqwest::Client::new();
    let url = native_repo_delta_endpoint(target, since, since_head);
    let response = remote::attach_native_remote_auth(client.get(&url), &target.base_url)
        .send()
        .await?;
    let status = response.status();

    // If the server returns 404 or 501, delta sync is not available — fall back.
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::NOT_IMPLEMENTED {
        return Ok(None);
    }

    // 409 Conflict means the since_head is too old or the server can't compute
    // a delta (e.g. history was compacted). Fall back to full snapshot.
    if status == reqwest::StatusCode::CONFLICT {
        return Ok(None);
    }

    let payload = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to fetch delta from {}: {} {}",
            target.repo_locator(),
            status,
            payload.trim()
        );
    }

    let delta_resp: NativeRepoDeltaResponse = serde_json::from_str(&payload)?;
    let mut changed_files = Vec::with_capacity(delta_resp.changed_files.len());
    for file in delta_resp.changed_files {
        changed_files.push(NativeRepoFile {
            path: file.path,
            content: file.content.into_bytes(),
        });
    }

    Ok(Some(NativeRepoDelta {
        default_branch: delta_resp
            .repository
            .default_branch
            .unwrap_or_else(|| "main".to_string()),
        remote_head: delta_resp.remote_head,
        changed_files,
        removed_paths: delta_resp.removed_paths,
    }))
}

/// Apply a delta to the working tree. Only touches files that changed.
pub(crate) fn apply_delta_to_working_tree(
    layout: &kin_core::KinLayout,
    delta: &NativeRepoDelta,
    current_tree: &HashMap<FilePathId, Hash256>,
) -> Result<NativeDeltaSyncStats> {
    let workspace_root = kin_core::source_dir(layout);
    let mut stats = NativeDeltaSyncStats::default();

    // Remove deleted files
    for removed_path in &delta.removed_paths {
        let path = resolve_repo_file_path(&workspace_root, removed_path)?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            prune_empty_parent_dirs(&workspace_root, path.parent());
            stats.removed_files += 1;
        }
    }

    // Write added/modified files
    for file in &delta.changed_files {
        let destination = resolve_repo_file_path(&workspace_root, &file.path)?;
        let current_hash = current_tree.get(&FilePathId::new(&file.path));
        let incoming_hash = hash_bytes(&file.content);

        // Skip if content is identical (shouldn't happen in a well-formed delta,
        // but defensive).
        if current_hash.is_some_and(|existing| *existing == incoming_hash) {
            continue;
        }

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&destination, &file.content)
            .with_context(|| format!("failed to write {}", destination.display()))?;
        stats.written_files += 1;
    }

    Ok(stats)
}
