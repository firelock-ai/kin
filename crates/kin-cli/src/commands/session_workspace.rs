// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_runtime::workspace::{MaterializationSource, MaterializeStrategy, MaterializedWorkspace};

pub(crate) async fn create_session_workspace(
    layout: &kin_core::KinLayout,
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

    Ok(MaterializedWorkspace::create_from_source(
        MaterializationSource::BlobTree {
            blob_store: &blob_store,
            tree: &tree,
        },
        session_dir,
        scope,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::init as init_repo;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, ChangeStore, FilePathId, Hash256,
        SemanticChange, SemanticChangeId,
    };
    use kin_runtime::workspace::MaterializationSourceKind;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    async fn spawn_bootstrap_server(
        snapshot: kin_db::GraphSnapshot,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let payload = std::sync::Arc::new(snapshot.to_bytes().unwrap());
        let payload_for_task = std::sync::Arc::clone(&payload);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let payload = std::sync::Arc::clone(&payload_for_task);
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let _ = stream.write_all(payload.as_slice()).await;
                });
            }
        });

        (format!("http://{}", address), task)
    }

    fn graph_snapshot(layout: &kin_core::KinLayout) -> kin_db::GraphSnapshot {
        crate::backend::open_kindb_snapshot(layout)
            .unwrap()
            .graph()
            .to_snapshot()
    }

    #[test]
    fn native_mode_rejects_non_copy_strategies_before_file_authority_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

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
        let snapshot = graph_snapshot(&layout);
        let workspace = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (daemon_url, daemon_task) = spawn_bootstrap_server(snapshot).await;
            let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", &daemon_url);
            let workspace = create_session_workspace(&layout, &session_dir, None, None)
                .await
                .unwrap();
            daemon_task.abort();
            workspace
        });

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
        let snapshot = graph_snapshot(&layout);
        let workspace = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (daemon_url, daemon_task) = spawn_bootstrap_server(snapshot).await;
            let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", &daemon_url);
            let workspace = create_session_workspace(&layout, &session_dir, None, None)
                .await
                .unwrap();
            daemon_task.abort();
            workspace
        });

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
