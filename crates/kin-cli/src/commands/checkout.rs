// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{FilePathId, GraphStore, Hash256, SemanticChangeId};

pub async fn run(path: String, change_id: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*snap.graph();
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let genesis = kin_core::build_genesis_change();

    let target_head = match change_id {
        Some(id) => {
            let hash = Hash256::from_hex(&id).map_err(|_| {
                anyhow::anyhow!(
                    "invalid change id '{}': expected a 64-character hex string",
                    id
                )
            })?;
            SemanticChangeId::from_hash(hash)
        }
        None => {
            let branch_name = kin_core::read_current_branch(&layout)?;
            let branch = graph
                .get_branch(&branch_name)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "current branch '{}' not found in graph. Run `kin commit` or `kin git import` first.",
                        branch_name
                    )
                })?;
            branch.head
        }
    };

    let tree = kin_core::build_file_tree(graph, &genesis.id, &target_head)
        .map_err(|e| anyhow::anyhow!("failed to build file tree: {}", e))?;

    // Normalize path: strip leading ./ if present
    let normalized = path.strip_prefix("./").unwrap_or(&path);
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

    println!("Restored '{}' from change {}", normalized, target_head);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_path_prefix() {
        let input = "./src/main.rs";
        let normalized = input.strip_prefix("./").unwrap_or(input);
        assert_eq!(normalized, "src/main.rs");
    }

    #[test]
    fn absolute_path_unchanged_by_normalization() {
        let input = "src/lib.rs";
        let normalized = input.strip_prefix("./").unwrap_or(input);
        assert_eq!(normalized, "src/lib.rs");
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
