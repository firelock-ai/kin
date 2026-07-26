// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{
    ChangeStore, EntityStore, Hash256, RepoPath, ResolvedArtifact, ResolvedTree, SemanticChangeId,
    TransactionDelta, TreeDelta,
};
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
    /// True only after both filesystem projection and exact graph admission
    /// succeeded.
    #[serde(default)]
    pub mutated: bool,
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
    let blobs =
        kin_blobs::BlobStore::new(layout.objects_dir()).context("open checkout object store")?;
    let target_head = resolve_target_head(layout, graph, request.change_id.as_deref())?;
    let target_at_change = graph
        .resolve_tree_at(&target_head)
        .context("resolve exact checkout target")?;
    let previous = graph.resolved_tree();
    let normalized = normalize_checkout_path(&request.path);
    let (desired, label, verification_tree) = if is_full_checkout(normalized) {
        (
            target_at_change,
            "all repository artifacts".to_string(),
            None,
        )
    } else {
        let path = RepoPath::from_utf8(normalized.to_string())
            .with_context(|| format!("invalid repository path '{normalized}'"))?;
        let desired = desired_single_path_tree(&previous, &target_at_change, &path, &target_head)?;
        let verification =
            ResolvedTree::from_artifacts(desired.artifact_at_path(&path).cloned().into_iter())
                .context("build single-artifact verification tree")?;
        (desired, normalized.to_string(), Some(verification))
    };

    let deltas = exact_tree_transition(&previous, &desired)?;
    if deltas.is_empty() {
        kin_projection::verify_resolved_tree_materialization(
            layout.working_dir(),
            verification_tree.as_ref().unwrap_or(&desired),
            &blobs,
        )
        .context("verify existing checkout projection")?;
        return Ok(CheckoutResponse {
            lines: vec![format!(
                "Checkout already matches {label} at change {target_head}"
            )],
            mutated: false,
        });
    }

    let report =
        kin_projection::transition_resolved_tree(layout.working_dir(), &previous, &desired, &blobs)
            .context("stage and publish exact checkout projection")?;

    if let Err(graph_error) = graph.apply_transaction_delta(&TransactionDelta {
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: deltas,
    }) {
        let rollback = kin_projection::transition_resolved_tree(
            layout.working_dir(),
            &desired,
            &previous,
            &blobs,
        );
        return match rollback {
            Ok(_) => Err(anyhow::anyhow!(
                "exact checkout graph admission failed after projection; filesystem rollback succeeded: {graph_error}"
            )),
            Err(rollback_error) => Err(anyhow::anyhow!(
                "exact checkout graph admission failed after projection: {graph_error}; \
                 filesystem rollback also failed: {rollback_error}"
            )),
        };
    }

    Ok(CheckoutResponse {
        lines: vec![format!(
            "Checked out {label} from change {target_head} \
             ({} materialized, {} displaced, {} unchanged)",
            report.materialized, report.removed, report.unchanged
        )],
        mutated: true,
    })
}

fn resolve_target_head(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    requested: Option<&str>,
) -> Result<SemanticChangeId> {
    if let Some(id) = requested {
        let hash = Hash256::from_hex(id).map_err(|_| {
            anyhow::anyhow!(
                "invalid change id '{id}': expected a 64-character lowercase hex string"
            )
        })?;
        return Ok(SemanticChangeId::from_hash(hash));
    }

    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' not found in graph; run `kin init` first",
            branch_name
        )
    })?;
    Ok(branch.head)
}

fn desired_single_path_tree(
    previous: &ResolvedTree,
    target: &ResolvedTree,
    path: &RepoPath,
    target_head: &SemanticChangeId,
) -> Result<ResolvedTree> {
    let selected = target.artifact_at_path(path).cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "artifact '{}' not found in the exact tree at change {}",
            path,
            target_head
        )
    })?;

    ResolvedTree::from_artifacts(
        previous
            .artifacts()
            .filter(|artifact| artifact.artifact_id != selected.artifact_id)
            .filter(|artifact| artifact.path != *path)
            .cloned()
            .chain(std::iter::once(ResolvedArtifact::new(
                selected.artifact_id,
                path.clone(),
                selected.entry,
            ))),
    )
    .context("construct exact single-path checkout target")
}

fn exact_tree_transition(previous: &ResolvedTree, target: &ResolvedTree) -> Result<Vec<TreeDelta>> {
    kin_core::exact_tree_correction(previous, target)
        .context("validate exact checkout tree transaction")
}

fn is_full_checkout(path: &str) -> bool {
    matches!(path, "" | "." | "*")
}

fn normalize_checkout_path(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, AuthorId, Branch, BranchName, LocatedEntry, SemanticChange, Timestamp,
        TreeEntry,
    };

    fn resolved(artifacts: Vec<(ArtifactId, &str, TreeEntry)>) -> ResolvedTree {
        ResolvedTree::from_artifacts(artifacts.into_iter().map(|(artifact_id, path, entry)| {
            ResolvedArtifact::new(artifact_id, RepoPath::from_utf8(path).unwrap(), entry)
        }))
        .unwrap()
    }

    fn install_change(
        graph: &kin_db::InMemoryGraph,
        parent: SemanticChangeId,
        id_byte: u8,
        deltas: Vec<TreeDelta>,
    ) -> SemanticChangeId {
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("checkout-test"),
            message: "checkout fixture".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };
        graph.create_change(&change).unwrap();
        change.id
    }

    fn setup_previous(
        layout: kin_core::KinLayout,
        artifacts: Vec<(ArtifactId, &str, TreeEntry)>,
    ) -> (
        kin_core::KinLayout,
        kin_db::InMemoryGraph,
        ResolvedTree,
        SemanticChangeId,
    ) {
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let previous = resolved(artifacts);
        let deltas = exact_tree_transition(&ResolvedTree::default(), &previous).unwrap();
        let head = install_change(&graph, genesis.id, 0x71, deltas.clone());
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &BranchName::new("main")).unwrap();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: deltas,
            })
            .unwrap();
        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        kin_projection::transition_resolved_tree(
            layout.working_dir(),
            &ResolvedTree::default(),
            &previous,
            &blobs,
        )
        .unwrap();
        (layout, graph, previous, head)
    }

    #[test]
    fn exact_transition_supports_swaps_and_path_reuse() {
        let left = ArtifactId::new();
        let right = ArtifactId::new();
        let replacement = ArtifactId::new();
        let x = TreeEntry::blob(Hash256::from_bytes([1; 32]), false);
        let y = TreeEntry::blob(Hash256::from_bytes([2; 32]), false);
        let z = TreeEntry::blob(Hash256::from_bytes([3; 32]), true);
        let previous = resolved(vec![(left, "left", x), (right, "right", y)]);
        let target = resolved(vec![
            (left, "right", x),
            (right, "left", y),
            (replacement, "compose.yaml", z),
        ]);

        let deltas = exact_tree_transition(&previous, &target).unwrap();
        assert_eq!(previous.apply(&deltas).unwrap(), target);
    }

    #[test]
    fn checkout_preflights_every_target_blob_before_mutating_graph_or_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let init = kin_core::init(temp.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.objects_dir()).unwrap();
        let old_hash = Hash256::from_bytes(blobs.write(b"old\n").unwrap().0);
        let old_id = ArtifactId::new();
        let (layout, graph, previous, head) = setup_previous(
            init.layout,
            vec![(old_id, "compose.yaml", TreeEntry::blob(old_hash, false))],
        );
        let missing = TreeEntry::blob(Hash256::from_bytes([0xf1; 32]), false);
        let target = resolved(vec![(old_id, "compose.yaml", missing)]);
        let target_id = install_change(
            &graph,
            head,
            0x72,
            exact_tree_transition(&previous, &target).unwrap(),
        );

        let error = execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: ".".to_string(),
                change_id: Some(target_id.to_string()),
            },
        )
        .expect_err("missing target blob must fail during staging");

        assert!(error.to_string().contains("stage and publish"));
        assert_eq!(graph.resolved_tree(), previous);
        assert_eq!(
            std::fs::read(layout.working_dir().join("compose.yaml")).unwrap(),
            b"old\n"
        );
    }

    #[test]
    fn checkout_publishes_projection_and_graph_as_one_command_invariant() {
        let temp = tempfile::tempdir().unwrap();
        let init = kin_core::init(temp.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.objects_dir()).unwrap();
        let old_hash = Hash256::from_bytes(blobs.write(b"old compose\n").unwrap().0);
        let new_hash = Hash256::from_bytes(blobs.write(b"new compose\n").unwrap().0);
        let script_hash = Hash256::from_bytes(blobs.write(b"#!/bin/sh\n").unwrap().0);
        let compose_id = ArtifactId::new();
        let script_id = ArtifactId::new();
        let (layout, graph, previous, head) = setup_previous(
            init.layout,
            vec![(compose_id, "compose.yaml", TreeEntry::blob(old_hash, false))],
        );
        let target = resolved(vec![
            (
                compose_id,
                "deploy/compose.yaml",
                TreeEntry::blob(new_hash, false),
            ),
            (script_id, "bin/run", TreeEntry::blob(script_hash, true)),
        ]);
        let target_id = install_change(
            &graph,
            head,
            0x73,
            exact_tree_transition(&previous, &target).unwrap(),
        );

        let response = execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: ".".to_string(),
                change_id: Some(target_id.to_string()),
            },
        )
        .unwrap();

        assert!(response.mutated);
        assert_eq!(graph.resolved_tree(), target);
        assert!(!layout.working_dir().join("compose.yaml").exists());
        assert_eq!(
            std::fs::read(layout.working_dir().join("deploy/compose.yaml")).unwrap(),
            b"new compose\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                std::fs::metadata(layout.working_dir().join("bin/run"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[test]
    fn single_path_checkout_restores_historic_artifact_identity() {
        let temp = tempfile::tempdir().unwrap();
        let init = kin_core::init(temp.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.objects_dir()).unwrap();
        let old_hash = Hash256::from_bytes(blobs.write(b"historic\n").unwrap().0);
        let replacement_hash = Hash256::from_bytes(blobs.write(b"replacement\n").unwrap().0);
        let historic_id = ArtifactId::new();
        let replacement_id = ArtifactId::new();
        let (layout, graph, previous, historic_head) = setup_previous(
            init.layout,
            vec![(
                historic_id,
                "compose.yaml",
                TreeEntry::blob(old_hash, false),
            )],
        );
        let current = resolved(vec![(
            replacement_id,
            "compose.yaml",
            TreeEntry::blob(replacement_hash, false),
        )]);
        let current_deltas = exact_tree_transition(&previous, &current).unwrap();
        install_change(&graph, historic_head, 0x74, current_deltas.clone());
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: current_deltas,
            })
            .unwrap();
        kin_projection::transition_resolved_tree(layout.working_dir(), &previous, &current, &blobs)
            .unwrap();

        execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: "compose.yaml".to_string(),
                change_id: Some(historic_head.to_string()),
            },
        )
        .unwrap();

        let active = graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("compose.yaml").unwrap())
            .unwrap();
        assert_eq!(active.artifact_id, historic_id);
        assert_eq!(
            std::fs::read(layout.working_dir().join("compose.yaml")).unwrap(),
            b"historic\n"
        );
    }

    #[test]
    fn gitlink_checkout_fails_before_graph_or_projection_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let init = kin_core::init(temp.path()).unwrap();
        let (layout, graph, previous, head) = setup_previous(init.layout, vec![]);
        let target = resolved(vec![(
            ArtifactId::new(),
            "vendor/submodule",
            kin_model::TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x44; 20])),
        )]);
        let target_id = install_change(
            &graph,
            head,
            0x75,
            exact_tree_transition(&previous, &target).unwrap(),
        );

        let error = execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: ".".to_string(),
                change_id: Some(target_id.to_string()),
            },
        )
        .expect_err("Gitlink projection requires explicit submodule state");

        assert!(error.to_string().contains("gitlink"));
        assert_eq!(graph.resolved_tree(), previous);
    }

    #[test]
    fn normalizes_relative_path_prefix_and_rejects_traversal() {
        assert_eq!(normalize_checkout_path("./src/main.rs"), "src/main.rs");
        assert_eq!(normalize_checkout_path("src/lib.rs"), "src/lib.rs");
        assert!(RepoPath::from_utf8(normalize_checkout_path("../outside")).is_err());
    }
}
