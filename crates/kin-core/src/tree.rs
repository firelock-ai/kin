// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::{ArtifactDeltaKind, FilePathId, GraphStore, Hash256, SemanticChangeId};

use crate::{KinError, KinLayout, Result};

/// Walk the SemanticChange DAG from genesis to branch_head and build
/// the current file tree: Map<FilePathId, Hash256>.
pub fn build_file_tree<G: GraphStore>(
    graph: &G,
    genesis_id: &SemanticChangeId,
    branch_head: &SemanticChangeId,
) -> Result<HashMap<FilePathId, Hash256>> {
    let changes = graph
        .get_changes_since(genesis_id, branch_head)
        .map_err(|e| KinError::Graph(format!("{}", e)))?;

    let mut tree: HashMap<FilePathId, Hash256> = HashMap::new();
    for change in &changes {
        for delta in &change.artifact_deltas {
            match delta.kind {
                ArtifactDeltaKind::Added | ArtifactDeltaKind::Modified => {
                    if let Some(hash) = delta.new_hash {
                        tree.insert(delta.file_id.clone(), hash);
                    }
                }
                ArtifactDeltaKind::Removed => {
                    tree.remove(&delta.file_id);
                }
            }
        }
    }
    Ok(tree)
}

/// Re-project the working directory to match a branch's committed file state.
///
/// Returns the number of files written.
pub fn checkout_branch<G: GraphStore>(
    graph: &G,
    blob_store: &kin_blobs::BlobStore,
    layout: &KinLayout,
    genesis_id: &SemanticChangeId,
    branch_head: &SemanticChangeId,
) -> Result<usize> {
    // VFS projects files from the graph — no physical checkout needed.
    // Kept for backward compatibility with repos that don't have VFS yet.
    // Once VFS is universal, this entire function can be removed.

    let tree = build_file_tree(graph, genesis_id, branch_head)?;
    let work_dir = layout.working_dir();
    let mut count = 0;

    for (file_id, hash) in &tree {
        // Convert kin_model::Hash256 to kin_blobs::Hash256
        let blob_hash = kin_blobs::Hash256(*hash.as_bytes());
        match blob_store.read(&blob_hash) {
            Ok(content) => {
                let path = work_dir.join(&file_id.0);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| KinError::io(parent, e))?;
                }
                std::fs::write(&path, &content).map_err(|e| KinError::io(&path, e))?;
                count += 1;
            }
            Err(_) => {
                tracing::warn!(file = %file_id, "blob not found in store, skipping");
            }
        }
    }

    Ok(count)
}
