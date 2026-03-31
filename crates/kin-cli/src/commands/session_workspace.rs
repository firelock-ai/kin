// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_runtime::workspace::{MaterializeStrategy, MaterializedWorkspace};

pub(crate) async fn create_session_workspace(
    layout: &kin_core::KinLayout,
    session_dir: &std::path::Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    if kin_core::read_repo_mode(layout) != kin_core::RepoMode::Native {
        let source = kin_core::source_dir(layout);
        return Ok(MaterializedWorkspace::create(
            &source,
            session_dir,
            strategy,
            scope,
        )?);
    }

    if let Some(strategy) = strategy {
        if strategy != MaterializeStrategy::Copy {
            return Err(anyhow::anyhow!(
                "native graph-backed session materialization only supports `copy`; requested `{}`",
                strategy
            ));
        }
    }

    let snap = crate::backend::open_snapshot_daemon_first_read_only(layout)
        .await
        .map_err(|e| anyhow::anyhow!("failed to open graph store: {}", e))?;
    let graph = snap.graph();
    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' is missing from the local graph",
            branch_name
        )
    })?;
    let genesis = kin_core::build_genesis_change();
    let tree = kin_core::build_file_tree(graph.as_ref(), &genesis.id, &branch.head)?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    Ok(MaterializedWorkspace::create_from_blob_tree(
        &blob_store,
        &tree,
        session_dir,
        scope,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::RepoMode;

    #[test]
    fn native_mode_rejects_non_copy_strategies_before_file_authority_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        kin_core::write_repo_mode(&layout, RepoMode::Native).unwrap();

        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(create_session_workspace(
                &layout,
                &dir.path().join("runs/session-1"),
                Some(MaterializeStrategy::Hardlink),
                None,
            ))
            .unwrap_err()
            .to_string();

        assert!(err.contains("only supports `copy`"));
    }
}
