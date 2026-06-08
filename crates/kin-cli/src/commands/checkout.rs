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

    if normalized == "." || normalized == "*" || normalized.is_empty() {
        // Checkout the entire tree!
        // 1. Write/restore all files in the tree
        for (file_id, blob_hash) in &tree {
            let blob_key = kin_blobs::Hash256(*blob_hash.as_bytes());
            let content = blob_store
                .read(&blob_key)
                .map_err(|e| anyhow::anyhow!("failed to read blob for '{}': {}", file_id.0, e))?;

            let dest = layout.working_dir().join(&file_id.0);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    anyhow::anyhow!("failed to create directory {}: {}", parent.display(), e)
                })?;
            }
            std::fs::write(&dest, &content)
                .map_err(|e| anyhow::anyhow!("failed to write {}: {}", dest.display(), e))?;
        }

        // 2. Clean up any files in the working directory that are NOT in the tree
        let source_root = layout.working_dir();
        let mut files_to_delete = Vec::new();
        collect_non_tree_files(&source_root, &source_root, &tree, &mut files_to_delete)?;

        for file_path in files_to_delete {
            let _ = std::fs::remove_file(file_path);
        }

        // Clean up empty directories
        clean_empty_dirs(&source_root, &source_root)?;

        return Ok(CheckoutResponse {
            lines: vec![format!("Checked out all files from change {}", target_head)],
        });
    }

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

fn collect_non_tree_files(
    root: &std::path::Path,
    current: &std::path::Path,
    tree: &std::collections::HashMap<FilePathId, Hash256>,
    files_to_delete: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;
        let rel_str = rel.to_string_lossy().to_string();

        if should_skip_checkout_clean(rel) {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_non_tree_files(root, &path, tree, files_to_delete)?;
        } else if ft.is_file() {
            let file_id = FilePathId(rel_str);
            if !tree.contains_key(&file_id) {
                files_to_delete.push(path);
            }
        }
    }
    Ok(())
}

fn should_skip_checkout_clean(rel: &std::path::Path) -> bool {
    const SKIP_DIRS: &[&str] = &[
        ".kin",
        ".git",
        "node_modules",
        "target",
        "__pycache__",
        ".next",
        "dist",
        "build",
        "vendor",
    ];

    rel.components().any(|component| {
        if let std::path::Component::Normal(name) = component {
            SKIP_DIRS
                .iter()
                .any(|skip| name == std::ffi::OsStr::new(skip))
        } else {
            false
        }
    })
}

fn clean_empty_dirs(root: &std::path::Path, current: &std::path::Path) -> Result<bool> {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(false),
    };

    let mut is_empty = true;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let rel = path.strip_prefix(root)?;
            if should_skip_checkout_clean(rel) {
                is_empty = false;
                continue;
            }
            let child_empty = clean_empty_dirs(root, &path)?;
            if child_empty {
                let _ = std::fs::remove_dir(&path);
            } else {
                is_empty = false;
            }
        } else {
            is_empty = false;
        }
    }
    Ok(is_empty)
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

    #[test]
    fn checkout_clean_skip_is_component_aware() {
        assert!(should_skip_checkout_clean(std::path::Path::new(".kin")));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            ".git/config"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "target/debug/app"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "crates/app/target/debug/app"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "web/node_modules/pkg/index.js"
        )));
        assert!(!should_skip_checkout_clean(std::path::Path::new(
            "src/lib.rs"
        )));
    }

    #[test]
    fn collect_non_tree_files_ignores_tracked_and_skip_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".kin")).unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "tracked").unwrap();
        std::fs::write(root.join("src/old.rs"), "delete").unwrap();
        std::fs::write(root.join(".kin/state"), "keep").unwrap();
        std::fs::write(root.join("target/debug/app"), "keep").unwrap();

        let mut tree = std::collections::HashMap::new();
        tree.insert(
            FilePathId("src/lib.rs".to_string()),
            Hash256::from_bytes([0; 32]),
        );

        let mut files = Vec::new();
        collect_non_tree_files(root, root, &tree, &mut files).unwrap();
        let rels: Vec<_> = files
            .iter()
            .map(|path| path.strip_prefix(root).unwrap().to_path_buf())
            .collect();

        assert_eq!(rels, vec![std::path::PathBuf::from("src/old.rs")]);
    }

    #[test]
    fn clean_empty_dirs_removes_only_untracked_empty_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("src/empty/nested")).unwrap();
        std::fs::create_dir_all(root.join(".kin/empty")).unwrap();
        std::fs::create_dir_all(root.join("crates/app/target")).unwrap();

        let root_empty = clean_empty_dirs(root, root).unwrap();

        assert!(!root_empty);
        assert!(!root.join("src/empty").exists());
        assert!(root.join(".kin/empty").exists());
        assert!(root.join("crates/app/target").exists());
    }
}
