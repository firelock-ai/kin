// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{ChangeStore, FilePathId, Hash256, SemanticChangeId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutRequest {
    pub path: String,
    #[serde(default)]
    pub change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run(path: String, change_id: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_checkout(&layout, &CheckoutRequest { path, change_id }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_checkout(
    layout: &kin_core::KinLayout,
    request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for checkout but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .checkout(request)
        .await
        .context("daemon checkout failed")
}

pub fn execute_checkout_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let genesis = kin_core::build_genesis_change();

    let target_head = match &request.change_id {
        Some(id) => {
            let hash = Hash256::from_hex(id).map_err(|_| {
                anyhow::anyhow!(
                    "invalid change id '{}': expected a 64-character hex string",
                    id
                )
            })?;
            SemanticChangeId::from_hash(hash)
        }
        None => {
            let branch_name = kin_core::read_current_branch(layout)?;
            let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "current branch '{}' not found in graph. Run `kin init` first.",
                    branch_name
                )
            })?;
            branch.head
        }
    };

    let tree = kin_core::build_file_tree(graph, &genesis.id, &target_head)
        .map_err(|e| anyhow::anyhow!("failed to build file tree: {}", e))?;

    let normalized = normalize_checkout_path(&request.path);
    let file_id = FilePathId(normalized.to_string());

    let blob_hash = tree.get(&file_id).ok_or_else(|| {
        anyhow::anyhow!(
            "file '{}' not found in the semantic tree at change {}",
            normalized,
            target_head
        )
    })?;

    let blob_key = kin_blobs::Hash256(*blob_hash.as_bytes());
    let content = blob_store
        .read(&blob_key)
        .map_err(|e| anyhow::anyhow!("failed to read blob for '{}': {}", normalized, e))?;

    let dest = layout.working_dir().join(normalized);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("failed to create directory {}: {}", parent.display(), e)
        })?;
    }

    std::fs::write(&dest, &content)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {}", dest.display(), e))?;

    Ok(CheckoutResponse {
        lines: vec![format!(
            "Restored '{}' from change {}",
            normalized, target_head
        )],
    })
}

fn normalize_checkout_path(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_path_prefix() {
        assert_eq!(normalize_checkout_path("./src/main.rs"), "src/main.rs");
    }

    #[test]
    fn absolute_path_unchanged_by_normalization() {
        assert_eq!(normalize_checkout_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn invalid_change_id_produces_helpful_error() {
        let bad_id = "not-a-hex-string";
        let result = Hash256::from_hex(bad_id);
        assert!(result.is_err());
    }

    #[test]
    fn file_path_id_equality() {
        let a = FilePathId("src/main.rs".to_string());
        let b = FilePathId("src/main.rs".to_string());
        assert_eq!(a, b);
    }
}
