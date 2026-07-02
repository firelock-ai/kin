// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_runtime::workspace::{
    MaterializationSource, MaterializationSourceKind, MaterializeStrategy, MaterializedWorkspace,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceRequest {
    pub session_dir: String,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceResponse {
    pub root: String,
    pub strategy: String,
    pub source_kind: String,
}

pub(crate) async fn create_session_workspace(
    layout: &kin_core::KinLayout,
    session_dir: &std::path::Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    let base_url = match std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(base_url) => base_url,
        None => crate::daemon_client::resolve_daemon_url(layout)
            .await?
            .ok_or_else(|| anyhow::anyhow!("kin daemon is required"))?,
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    let response = client
        .session_workspace(&SessionWorkspaceRequest {
            session_dir: session_dir.display().to_string(),
            strategy: strategy.map(|value| value.to_string()),
            scope: scope.map(str::to_string),
        })
        .await?;
    let strategy = response
        .strategy
        .parse::<MaterializeStrategy>()
        .map_err(|error| anyhow::anyhow!("{}", error))?;
    let source_kind = match response.source_kind.as_str() {
        "blob-tree" => MaterializationSourceKind::BlobTree,
        "filesystem" => MaterializationSourceKind::Filesystem,
        other => anyhow::bail!("daemon returned unknown materialization source: {other}"),
    };

    Ok(MaterializedWorkspace::from_existing(
        std::path::PathBuf::from(response.root),
        strategy,
        source_kind,
    ))
}

pub fn create_session_workspace_from_graph(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &std::path::Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    if let Some(strategy) = strategy {
        if strategy != MaterializeStrategy::Copy {
            return Err(anyhow::anyhow!(
                "native graph-backed session materialization only supports `copy`; requested `{}`",
                strategy
            ));
        }
    }

    validate_session_dir(layout, session_dir)?;

    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' is missing from the daemon graph",
            branch_name
        )
    })?;
    let genesis = kin_core::build_genesis_change();
    let tree = kin_core::build_file_tree(graph, &genesis.id, &branch.head)?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let workspace = MaterializedWorkspace::create_from_source(
        MaterializationSource::BlobTree {
            blob_store: &blob_store,
            tree: &tree,
        },
        session_dir,
        scope,
    )?;

    // Record the workspace's base version so a later reconcile replays only the
    // workspace's own change-set instead of force-syncing whole-tree state.
    // Immediately after materialization the workspace mirrors the projected
    // graph head, so hashing it captures the correct base.
    super::session_base::record_materialized_base(session_dir, Some(branch.head.to_string()))?;

    Ok(workspace)
}

pub fn materialize_session_workspace(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &SessionWorkspaceRequest,
) -> Result<SessionWorkspaceResponse> {
    let strategy = request
        .strategy
        .as_deref()
        .map(str::parse::<MaterializeStrategy>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("{}", error))?;
    let session_dir = std::path::PathBuf::from(&request.session_dir);
    // `entity:`/`artifact:` scopes resolve against graph truth here, so every
    // session surface (shell, exec, open) shares one scope vocabulary and an
    // unresolvable scope fails loud instead of silently widening.
    let scope = super::exec::resolve_materialization_scope(graph, request.scope.clone())?;
    let workspace = create_session_workspace_from_graph(
        layout,
        graph,
        &session_dir,
        strategy,
        scope.as_deref(),
    )?;

    Ok(SessionWorkspaceResponse {
        root: workspace.root.display().to_string(),
        strategy: workspace.strategy.to_string(),
        source_kind: match workspace.source_kind() {
            MaterializationSourceKind::BlobTree => "blob-tree".to_string(),
            MaterializationSourceKind::Filesystem => "filesystem".to_string(),
        },
    })
}

fn validate_session_dir(layout: &kin_core::KinLayout, session_dir: &std::path::Path) -> Result<()> {
    let runs_dir = layout.root().join("runs");
    if !session_dir.is_absolute() || !session_dir.starts_with(&runs_dir) {
        anyhow::bail!(
            "session workspace must be an absolute path under {}",
            runs_dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::init as init_repo;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, ChangeStore, FilePathId, Hash256,
        SemanticChange, SemanticChangeId,
    };
    use std::fs;

    fn commit_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn write_native_graph_file(
        layout: &kin_core::KinLayout,
        rel_path: &str,
        content: &[u8],
    ) -> anyhow::Result<()> {
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())?;
        let blob_hash = blob_store.write(content)?;
        let snap = crate::backend::open_kindb_snapshot(layout)?;
        let graph = snap.graph();
        let branch_name = BranchName::new("main");
        let branch = graph.get_branch(&branch_name)?.expect("main branch");
        let change = SemanticChange {
            id: commit_id(9),
            parents: vec![branch.head],
            timestamp: kin_model::Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add artifact".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId::new(rel_path),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(blob_hash),
            }],
            projected_files: vec![FilePathId::new(rel_path)],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        graph.create_change(&change)?;
        graph.update_branch_head(&branch_name, &change.id)?;
        snap.save()?;
        Ok(())
    }

    #[test]
    fn native_mode_rejects_non_copy_strategies_before_file_authority_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let graph = kin_db::InMemoryGraph::new();
        let err = create_session_workspace_from_graph(
            &layout,
            &graph,
            &dir.path().join("runs/session-1"),
            Some(MaterializeStrategy::Hardlink),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("only supports `copy`"));
    }

    #[test]
    #[serial_test::serial]
    fn native_mode_materializes_graph_truth_through_runtime_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let init = init_repo(dir.path()).unwrap();
        let layout = init.layout;
        // No mode to set — there's one mode: Kin.
        fs::create_dir_all(kin_core::source_dir(&layout).join("src")).unwrap();
        fs::write(
            kin_core::source_dir(&layout).join("src/lib.rs"),
            "source drift\n",
        )
        .unwrap();
        write_native_graph_file(&layout, "src/lib.rs", b"graph truth\n").unwrap();

        let session_dir = layout.root().join("runs/session-native");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let workspace =
            create_session_workspace_from_graph(&layout, graph.as_ref(), &session_dir, None, None)
                .unwrap();

        assert_eq!(workspace.source_kind(), MaterializationSourceKind::BlobTree);
        assert_eq!(
            fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            "graph truth\n"
        );

        let artifact_dir = std::path::Path::new("/tmp/workstreamC-materialization-dispatch-proof");
        fs::create_dir_all(artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("native.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "source_kind": format!("{:?}", workspace.source_kind()),
                "materialized_content": fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn default_session_workspace_materializes_graph_snapshot_even_when_source_tree_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/lib.rs"), "compat source\n").unwrap();
        let init = init_repo(dir.path()).unwrap();
        let layout = init.layout;
        write_native_graph_file(&layout, "src/lib.rs", b"compat source\n").unwrap();

        let session_dir = layout.root().join("runs/session-compat");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let workspace =
            create_session_workspace_from_graph(&layout, graph.as_ref(), &session_dir, None, None)
                .unwrap();

        assert_eq!(workspace.source_kind(), MaterializationSourceKind::BlobTree);
        assert_eq!(
            fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            "compat source\n"
        );

        let artifact_dir = std::path::Path::new("/tmp/workstreamC-materialization-dispatch-proof");
        fs::create_dir_all(artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("compat.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "source_kind": format!("{:?}", workspace.source_kind()),
                "materialized_content": fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            artifact_dir.join("summary.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "native_source_kind": "BlobTree",
                "native_materialized_content": "graph truth\\n",
                "compat_source_kind": "BlobTree",
                "compat_materialized_content": "compat source\\n",
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
