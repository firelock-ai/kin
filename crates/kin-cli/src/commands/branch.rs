// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Branch, BranchName, ChangeStore, Hash256, SemanticChangeId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BranchRequest {
    List,
    Create { name: String },
    Delete { name: String },
    Switch { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
}

pub async fn list() -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::List).await?)
}

pub async fn create(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Create { name }).await?)
}

pub async fn delete(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Delete { name }).await?)
}

pub async fn switch(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Switch { name }).await?)
}

fn discover_layout() -> Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))
}

async fn run_daemon_branch(
    layout: &kin_core::KinLayout,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for branch commands but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.branch(request).await.context("daemon branch failed")
}

fn print_branch_response(response: BranchResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn execute_branch_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    match request {
        BranchRequest::List => branch_list(layout, graph),
        BranchRequest::Create { name } => branch_create(layout, graph, name),
        BranchRequest::Delete { name } => branch_delete(graph, name),
        BranchRequest::Switch { name } => branch_switch(layout, graph, name),
    }
}

fn branch_list(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<BranchResponse> {
    let branches = graph.list_branches()?;
    let current = kin_core::read_current_branch(layout)?;

    let lines = if branches.is_empty() {
        vec!["No branches".to_string()]
    } else {
        branches
            .iter()
            .map(|branch| {
                let marker = if branch.name == current { "* " } else { "  " };
                format!("{}{} -> {}", marker, branch.name, branch.head)
            })
            .collect()
    };

    Ok(BranchResponse {
        lines,
        mutated: false,
    })
}

fn branch_create(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<BranchResponse> {
    let current = kin_core::read_current_branch(layout)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;
    let branch = Branch {
        name: BranchName::new(name),
        head: current_branch.head,
    };
    graph.create_branch(&branch)?;
    Ok(BranchResponse {
        lines: vec![format!(
            "Created branch '{}' at {}",
            name, current_branch.head
        )],
        mutated: true,
    })
}

fn branch_delete(graph: &kin_db::InMemoryGraph, name: &str) -> Result<BranchResponse> {
    graph.delete_branch(&BranchName::new(name))?;
    Ok(BranchResponse {
        lines: vec![format!("Deleted branch '{}'", name)],
        mutated: true,
    })
}

fn branch_switch(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<BranchResponse> {
    branch_switch_with_pre_mutation_hook(layout, graph, name, || {})
}

fn branch_switch_with_pre_mutation_hook(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
    after_read_only_preflight: impl FnOnce(),
) -> Result<BranchResponse> {
    branch_switch_with_hooks(
        layout,
        graph,
        name,
        after_read_only_preflight,
        |_layout, _branch| Ok(()),
    )
}

fn branch_switch_with_hooks(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
    after_read_only_preflight: impl FnOnce(),
    before_head_commit: impl FnOnce(&kin_core::KinLayout, &BranchName) -> Result<()>,
) -> Result<BranchResponse> {
    let previous_name = kin_core::read_current_branch(layout)?;
    let previous_branch = graph
        .get_branch(&previous_name)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", previous_name))?;
    let branch = graph.get_branch(&BranchName::new(name))?;
    let Some(branch) = branch else {
        anyhow::bail!("branch '{}' not found", name);
    };

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
    let files_written = kin_core::tree::checkout_branch_between_heads_transactional_with_hooks(
        graph,
        &blob_store,
        layout,
        &previous_name.to_string(),
        &previous_branch.head,
        &branch.name.to_string(),
        &branch.head,
        after_read_only_preflight,
        || {
            let current_target = graph
                .get_branch(&branch.name)
                .map_err(|error| kin_core::KinError::Graph(error.to_string()))?
                .ok_or_else(|| {
                    kin_core::KinError::Graph(format!(
                        "branch '{}' disappeared during switch",
                        branch.name
                    ))
                })?;
            if current_target.head != branch.head {
                return Err(kin_core::KinError::Graph(format!(
                    "branch '{}' advanced from {} to {} during switch; current branch marker was not changed",
                    branch.name, branch.head, current_target.head
                )));
            }
            before_head_commit(layout, &branch.name).map_err(|error| {
                kin_core::KinError::Other(format!(
                    "validate branch authority before HEAD publication: {error:#}"
                ))
            })
        },
    )?;
    let mut lines = vec![format!(
        "Switched to branch '{}' at {}",
        branch.name, branch.head
    )];
    if files_written > 0 {
        lines.push(format!("  {} file(s) updated", files_written));
    }
    Ok(BranchResponse {
        lines,
        mutated: false,
    })
}

#[allow(dead_code)]
fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(s)
        .map_err(|_| anyhow::anyhow!("invalid change ID (expected 64 hex chars): {}", s))?;
    Ok(SemanticChangeId::from_hash(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactDelta, ArtifactDeltaKind, AuthorId, SemanticChange, Timestamp};

    fn source_change(
        id_byte: u8,
        parent: SemanticChangeId,
        artifact_deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("branch-switch-test"),
            message: format!("branch switch fixture {id_byte}"),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_removes_only_old_tracked_paths() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let shared_blob = blob_store.write(b"shared on main\n").unwrap();
        let shared_hash = Hash256::from_bytes(shared_blob.0);
        let main_change = source_change(
            0x61,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(shared_hash),
            }],
        );
        graph.create_change(&main_change).unwrap();

        let stale_blob = blob_store.write(b"feature only\n").unwrap();
        let stale_hash = Hash256::from_bytes(stale_blob.0);
        let feature_change = source_change(
            0x62,
            main_change.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/feature_only.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(stale_hash),
            }],
        );
        graph.create_change(&feature_change).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main_change.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature_change.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("feature")).unwrap();

        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(layout.root().join("preserve-control"), b"preserve kin\n").unwrap();
        std::fs::write(repo.path().join("src/shared.rs"), b"shared on main\n").unwrap();
        std::fs::write(repo.path().join("src/feature_only.rs"), b"feature only\n").unwrap();
        std::fs::write(repo.path().join("notes.txt"), b"untracked user bytes\n").unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::write(repo.path().join(".git/config"), b"preserve git\n").unwrap();
        std::fs::create_dir_all(repo.path().join(".kin-session")).unwrap();
        std::fs::write(
            repo.path().join(".kin-session/base.json"),
            b"preserve session\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo.path().join("target/debug")).unwrap();
        std::fs::write(repo.path().join("target/debug/cache"), b"preserve build\n").unwrap();

        branch_switch(&layout, &graph, "main").unwrap();

        assert_eq!(
            std::fs::read(repo.path().join("src/shared.rs")).unwrap(),
            b"shared on main\n"
        );
        assert!(!repo.path().join("src/feature_only.rs").exists());
        assert_eq!(
            std::fs::read(repo.path().join("notes.txt")).unwrap(),
            b"untracked user bytes\n"
        );
        assert!(layout.root().join("preserve-control").exists());
        assert!(repo.path().join(".git/config").exists());
        assert!(repo.path().join(".kin-session/base.json").exists());
        assert!(repo.path().join("target/debug/cache").exists());
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("main")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_refuses_modified_tracked_overwrite_without_partial_mutation() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let main_blob = blob_store.write(b"shared on main\n").unwrap();
        let main_hash = Hash256::from_bytes(main_blob.0);
        let main_change = source_change(
            0x63,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(main_hash),
            }],
        );
        graph.create_change(&main_change).unwrap();

        let feature_blob = blob_store.write(b"shared on feature\n").unwrap();
        let feature_hash = Hash256::from_bytes(feature_blob.0);
        let stale_blob = blob_store.write(b"feature only\n").unwrap();
        let stale_hash = Hash256::from_bytes(stale_blob.0);
        let feature_change = source_change(
            0x64,
            main_change.id,
            vec![
                ArtifactDelta {
                    file_id: kin_model::FilePathId::new("src/shared.rs"),
                    kind: ArtifactDeltaKind::ModifiedRegularFile,
                    old_hash: Some(main_hash),
                    new_hash: Some(feature_hash),
                },
                ArtifactDelta {
                    file_id: kin_model::FilePathId::new("src/feature_only.rs"),
                    kind: ArtifactDeltaKind::AddedRegularFile,
                    old_hash: None,
                    new_hash: Some(stale_hash),
                },
            ],
        );
        graph.create_change(&feature_change).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main_change.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature_change.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("feature")).unwrap();

        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/shared.rs"), b"user-edited feature\n").unwrap();
        std::fs::write(repo.path().join("src/feature_only.rs"), b"feature only\n").unwrap();

        let error = branch_switch(&layout, &graph, "main").unwrap_err();

        assert!(error
            .to_string()
            .contains("differs from current branch source"));
        assert_eq!(
            std::fs::read(repo.path().join("src/shared.rs")).unwrap(),
            b"user-edited feature\n"
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/feature_only.rs")).unwrap(),
            b"feature only\n"
        );
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("feature")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_refuses_modified_tracked_removal_without_partial_mutation() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let main_blob = blob_store.write(b"shared on main\n").unwrap();
        let main_hash = Hash256::from_bytes(main_blob.0);
        let main_change = source_change(
            0x65,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(main_hash),
            }],
        );
        graph.create_change(&main_change).unwrap();

        let feature_shared_blob = blob_store.write(b"shared on feature\n").unwrap();
        let feature_shared_hash = Hash256::from_bytes(feature_shared_blob.0);
        let removed_blob = blob_store.write(b"feature removable\n").unwrap();
        let removed_hash = Hash256::from_bytes(removed_blob.0);
        let feature_change = source_change(
            0x66,
            main_change.id,
            vec![
                ArtifactDelta {
                    file_id: kin_model::FilePathId::new("src/shared.rs"),
                    kind: ArtifactDeltaKind::ModifiedRegularFile,
                    old_hash: Some(main_hash),
                    new_hash: Some(feature_shared_hash),
                },
                ArtifactDelta {
                    file_id: kin_model::FilePathId::new("src/remove_on_main.rs"),
                    kind: ArtifactDeltaKind::AddedRegularFile,
                    old_hash: None,
                    new_hash: Some(removed_hash),
                },
            ],
        );
        graph.create_change(&feature_change).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main_change.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature_change.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("feature")).unwrap();

        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/shared.rs"), b"shared on feature\n").unwrap();
        std::fs::write(
            repo.path().join("src/remove_on_main.rs"),
            b"user-edited removable\n",
        )
        .unwrap();

        let error = branch_switch(&layout, &graph, "main").unwrap_err();

        assert!(error
            .to_string()
            .contains("differs from current branch source"));
        assert_eq!(
            std::fs::read(repo.path().join("src/shared.rs")).unwrap(),
            b"shared on feature\n"
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/remove_on_main.rs")).unwrap(),
            b"user-edited removable\n"
        );
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("feature")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_revalidates_post_preflight_editor_replacement_before_head() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let main_hash = Hash256::from_bytes(blob_store.write(b"main bytes\n").unwrap().0);
        let main = source_change(
            0x67,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(main_hash),
            }],
        );
        graph.create_change(&main).unwrap();
        let feature_hash = Hash256::from_bytes(blob_store.write(b"feature bytes\n").unwrap().0);
        let feature = source_change(
            0x68,
            main.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::ModifiedRegularFile,
                old_hash: Some(main_hash),
                new_hash: Some(feature_hash),
            }],
        );
        graph.create_change(&feature).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("feature")).unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        let path = repo.path().join("src/shared.rs");
        std::fs::write(&path, b"feature bytes\n").unwrap();

        let error = branch_switch_with_pre_mutation_hook(&layout, &graph, "main", || {
            let replacement = repo.path().join("src/editor.tmp");
            std::fs::write(&replacement, b"editor bytes\n").unwrap();
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(replacement, &path).unwrap();
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("differs from current branch source"));
        assert_eq!(std::fs::read(&path).unwrap(), b"editor bytes\n");
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("feature")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_revalidates_target_head_before_writing_current_branch() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let main_hash = Hash256::from_bytes(blob_store.write(b"main bytes\n").unwrap().0);
        let main = source_change(
            0x69,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(main_hash),
            }],
        );
        graph.create_change(&main).unwrap();
        let feature_hash = Hash256::from_bytes(blob_store.write(b"feature bytes\n").unwrap().0);
        let feature = source_change(
            0x6a,
            main.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::ModifiedRegularFile,
                old_hash: Some(main_hash),
                new_hash: Some(feature_hash),
            }],
        );
        graph.create_change(&feature).unwrap();
        let advanced_hash = Hash256::from_bytes(blob_store.write(b"advanced bytes\n").unwrap().0);
        let advanced = source_change(
            0x6b,
            feature.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::ModifiedRegularFile,
                old_hash: Some(feature_hash),
                new_hash: Some(advanced_hash),
            }],
        );
        graph.create_change(&advanced).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("main")).unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/shared.rs"), b"main bytes\n").unwrap();

        let error = branch_switch_with_pre_mutation_hook(&layout, &graph, "feature", || {
            graph
                .update_branch_head(&BranchName::new("feature"), &advanced.id)
                .unwrap();
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("advanced"));
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("main")
        );
        assert_eq!(
            graph
                .get_branch(&BranchName::new("feature"))
                .unwrap()
                .unwrap()
                .head,
            advanced.id
        );
        assert_eq!(
            graph
                .get_branch(&BranchName::new("main"))
                .unwrap()
                .unwrap()
                .head,
            main.id
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/shared.rs")).unwrap(),
            b"main bytes\n"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn branch_switch_head_write_failure_restores_prior_tree_head_and_graph() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();

        let main_hash = Hash256::from_bytes(blob_store.write(b"main bytes\n").unwrap().0);
        let main = source_change(
            0x6c,
            genesis.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(main_hash),
            }],
        );
        graph.create_change(&main).unwrap();
        let feature_hash = Hash256::from_bytes(blob_store.write(b"feature bytes\n").unwrap().0);
        let feature = source_change(
            0x6d,
            main.id,
            vec![ArtifactDelta {
                file_id: kin_model::FilePathId::new("src/shared.rs"),
                kind: ArtifactDeltaKind::ModifiedRegularFile,
                old_hash: Some(main_hash),
                new_hash: Some(feature_hash),
            }],
        );
        graph.create_change(&feature).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: main.id,
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("feature"),
                head: feature.id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("main")).unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/shared.rs"), b"main bytes\n").unwrap();

        let error = branch_switch_with_hooks(
            &layout,
            &graph,
            "feature",
            || {},
            |_layout, _branch| anyhow::bail!("injected HEAD write failure"),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected HEAD write failure"));
        assert_eq!(
            kin_core::read_current_branch(&layout).unwrap(),
            BranchName::new("main")
        );
        assert_eq!(
            std::fs::read(repo.path().join("src/shared.rs")).unwrap(),
            b"main bytes\n"
        );
        assert_eq!(
            graph
                .get_branch(&BranchName::new("main"))
                .unwrap()
                .unwrap()
                .head,
            main.id
        );
        assert_eq!(
            graph
                .get_branch(&BranchName::new("feature"))
                .unwrap()
                .unwrap()
                .head,
            feature.id
        );
    }
}
