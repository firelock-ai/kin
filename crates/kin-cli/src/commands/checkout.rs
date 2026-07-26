// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact selected-path checkout over repository-v6 authority.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use kin_model::{
    compute_resolved_tree_hash, ArtifactId, AuthorId, Hash256, OperationId, RepoPath,
    RepositoryTransaction, ResolvedArtifact, ResolvedTree, SemanticChangeId, WorkspaceExpectation,
    WorkspaceMutation, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::repository_authority::ActiveRepositoryAuthority;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_hex: Option<String>,
    #[serde(default)]
    pub change_id: Option<String>,
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckoutReport {
    pub authority: String,
    pub operation_id: OperationId,
    pub selected: RepoPath,
    pub target_change_id: SemanticChangeId,
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub projected_entries: usize,
    pub projection_only: bool,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<CheckoutReport>,
}

pub fn parse_checkout_path(path: Option<&str>, path_hex: Option<&str>) -> Result<RepoPath> {
    let selected = match (path, path_hex) {
        (Some(path), None) => RepoPath::from_utf8(path)
            .map_err(|error| anyhow::anyhow!("invalid checkout path: {error}"))?,
        (None, Some(encoded)) => {
            let bytes = hex::decode(encoded)
                .with_context(|| format!("invalid repository path hex '{encoded}'"))?;
            if hex::encode(&bytes) != encoded {
                bail!("repository path hex must use canonical lowercase hexadecimal encoding");
            }
            RepoPath::from_bytes(bytes)
                .map_err(|error| anyhow::anyhow!("invalid byte-exact checkout path: {error}"))?
        }
        (Some(_), Some(_)) => bail!("provide either a UTF-8 path or --path-hex, not both"),
        (None, None) => bail!("provide a UTF-8 path or --path-hex"),
    };
    let first = selected
        .as_bytes()
        .split(|byte| *byte == b'/')
        .next()
        .expect("validated repository paths have one component");
    if matches!(first, b".kin" | b".kin-session" | b".git") {
        bail!(
            "checkout path {} names reserved repository control state",
            selected
        );
    }
    Ok(selected)
}

pub fn execute_checkout_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    execute_checkout_request_with_hooks(layout, graph, request, || {}, || {}, || {})
}

/// Test seam for selected-path namespace races and authority rollback.
#[doc(hidden)]
pub fn execute_checkout_request_with_hooks(
    layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    request: &CheckoutRequest,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    after_projection_mutation: impl FnOnce(),
) -> Result<CheckoutResponse> {
    let selected = parse_checkout_path(request.path.as_deref(), request.path_hex.as_deref())?;
    let authority = ActiveRepositoryAuthority::open(layout)?;
    let lease = authority.manager().read_authority();
    let roots = lease.roots().clone();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let target_change_id = match request.change_id.as_deref() {
        Some(value) => {
            let hash = Hash256::from_hex(value).map_err(|_| {
                anyhow::anyhow!(
                    "invalid change id '{value}': expected a canonical 64-character hash"
                )
            })?;
            if hash.to_string() != value {
                bail!("change id must use canonical lowercase hexadecimal encoding");
            }
            SemanticChangeId::from_hash(hash)
        }
        None => {
            let base = workspace.base_target.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "workspace {} is unborn and has no base tree to restore",
                    workspace.workspace_id
                )
            })?;
            lease
                .resolve_target_change_id(base)
                .context("resolve current symbolic or detached workspace base")?
        }
    };
    let actor = checkout_actor(
        &authority.repository_id,
        authority.workspace_id,
        request.operation_id,
        &selected,
        &target_change_id,
    );
    let existing_receipt = lease
        .metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == request.operation_id)
        .cloned();
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare immutable checkout target graph")?;
    let target_tree = kin_core::tree::resolve_change_tree(&graph, &target_change_id)
        .with_context(|| format!("resolve exact checkout tree at {target_change_id}"))?;

    if let Some(receipt) = existing_receipt {
        if receipt.operation.actor != actor {
            bail!(
                "checkout operation {} was already committed for a different path or target",
                request.operation_id
            );
        }
        kin_core::tree::recover_repository_workspace_projection(layout.working_dir())
            .context("recover committed exact checkout projection")?;
        let lease = authority.manager().read_authority();
        let current = lease
            .metadata()
            .workspaces
            .iter()
            .find(|candidate| candidate.workspace_id == workspace.workspace_id)
            .ok_or_else(|| anyhow::anyhow!("checkout workspace disappeared after recovery"))?;
        let projected_entries = selected_materialized_count(&target_tree, &selected)?;
        let report = CheckoutReport {
            authority: "repository-v6".to_string(),
            operation_id: request.operation_id,
            selected,
            target_change_id,
            authority_generation: lease.roots().generation,
            workspace_generation: current.generation,
            projected_entries,
            projection_only: false,
            idempotent: true,
        };
        return Ok(response(report, false));
    }

    let existing_projection_receipt = kin_core::tree::recover_checkout_projection_receipt(
        layout.working_dir(),
        request.operation_id,
    )
    .context("recover prior selected checkout projection")?;
    validate_checkout_selection(&workspace.tree, &target_tree, &selected)?;
    let next_tree = splice_checkout_tree(&workspace.tree, &target_tree, &selected)?;
    let next_tree_hash =
        compute_resolved_tree_hash(&next_tree).context("hash selected checkout workspace tree")?;

    if next_tree == workspace.tree {
        let projection_receipt = kin_core::tree::CheckoutProjectionReceipt::new(
            authority.repository_id.clone(),
            workspace.workspace_id,
            request.operation_id,
            roots.clone(),
            workspace.generation,
            workspace.tree_hash,
            selected.clone(),
        )?;
        if let Some(existing) = existing_projection_receipt {
            if existing != projection_receipt {
                bail!(
                    "checkout operation {} was already completed for a different projection request",
                    request.operation_id
                );
            }
            let report = CheckoutReport {
                authority: "repository-v6".to_string(),
                operation_id: request.operation_id,
                selected,
                target_change_id,
                authority_generation: roots.generation,
                workspace_generation: workspace.generation,
                projected_entries: 0,
                projection_only: true,
                idempotent: true,
            };
            return Ok(response(report, false));
        }
        let (projected_entries, _) =
            kin_core::tree::repair_repository_workspace_subtree_projection_with_hooks(
                layout.working_dir(),
                &workspace.tree,
                authority.manager(),
                projection_receipt,
                after_read_only_preflight,
                after_identity_revalidation,
                after_projection_mutation,
            )
            .context("repair exact selected checkout projection")?;
        let report = CheckoutReport {
            authority: "repository-v6".to_string(),
            operation_id: request.operation_id,
            selected,
            target_change_id,
            authority_generation: roots.generation,
            workspace_generation: workspace.generation,
            projected_entries,
            projection_only: true,
            idempotent: false,
        };
        return Ok(response(report, true));
    }
    if existing_projection_receipt.is_some() {
        bail!(
            "checkout operation {} was already completed as a projection-only request",
            request.operation_id
        );
    }

    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &next_tree)
        .context("plan selected exact checkout tree splice")?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor,
        reason: "checkout exact repository workspace path".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("workspace generation overflow"))?,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas,
            new_tree_hash: next_tree_hash,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
    };
    let (projected_entries, receipt) =
        kin_core::tree::checkout_repository_workspace_subtree_and_commit_with_hooks(
            layout.working_dir(),
            &selected,
            &workspace.tree,
            &next_tree,
            authority.manager(),
            transaction,
            after_read_only_preflight,
            after_identity_revalidation,
            after_projection_mutation,
        )
        .context("commit selected exact checkout workspace transition")?;
    let report = CheckoutReport {
        authority: "repository-v6".to_string(),
        operation_id: request.operation_id,
        selected,
        target_change_id,
        authority_generation: receipt.generation,
        workspace_generation: workspace.generation + 1,
        projected_entries,
        projection_only: false,
        idempotent: matches!(
            receipt.outcome,
            kin_model::RepositoryCommitOutcome::IdempotentReplay
        ),
    };
    Ok(response(report, true))
}

fn response(report: CheckoutReport, mutated: bool) -> CheckoutResponse {
    CheckoutResponse {
        lines: vec![format!(
            "Checked out {} from change {} ({} projected entries, authority generation {})",
            report.selected,
            report.target_change_id,
            report.projected_entries,
            report.authority_generation
        )],
        mutated,
        report: Some(report),
    }
}

fn checkout_actor(
    repository_id: &kin_model::RepositoryId,
    workspace_id: kin_model::WorkspaceId,
    operation_id: OperationId,
    selected: &RepoPath,
    target: &SemanticChangeId,
) -> AuthorId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.checkout-request.v1\0");
    hasher.update(repository_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(workspace_id.0.as_bytes());
    hasher.update(operation_id.as_uuid().as_bytes());
    hasher.update(selected.as_bytes());
    hasher.update(target.0.as_bytes());
    AuthorId::new(format!(
        "kin-checkout-command:{}",
        hex::encode(hasher.finalize())
    ))
}

fn validate_checkout_selection(
    current: &ResolvedTree,
    target: &ResolvedTree,
    selected: &RepoPath,
) -> Result<()> {
    let current_matches = current
        .artifacts_by_path()
        .filter(|artifact| path_is_selected(&artifact.path, selected))
        .count();
    let target_matches = target
        .artifacts_by_path()
        .filter(|artifact| path_is_selected(&artifact.path, selected))
        .count();
    if current_matches == 0 && target_matches == 0 {
        bail!(
            "checkout path {} does not name an artifact or component subtree in the current or target tree",
            selected
        );
    }
    for (label, tree) in [("current", current), ("target", target)] {
        let exact = tree.artifact_at_path(selected).is_some();
        let descendant = tree.artifacts_by_path().any(|artifact| {
            artifact.path != *selected && path_is_selected(&artifact.path, selected)
        });
        if exact && descendant {
            bail!(
                "{label} tree contains both exact path {} and descendants; checkout prefix is ambiguous",
                selected
            );
        }
    }
    Ok(())
}

fn splice_checkout_tree(
    current: &ResolvedTree,
    target: &ResolvedTree,
    selected: &RepoPath,
) -> Result<ResolvedTree> {
    let mut artifacts = current
        .artifacts()
        .filter(|artifact| !path_is_selected(&artifact.path, selected))
        .cloned()
        .collect::<Vec<_>>();
    let mut occupied_ids = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id)
        .collect::<HashSet<_>>();
    for target_artifact in target
        .artifacts_by_path()
        .filter(|artifact| path_is_selected(&artifact.path, selected))
    {
        if artifacts
            .iter()
            .any(|retained| paths_are_related(&retained.path, &target_artifact.path))
        {
            bail!(
                "checkout target {} conflicts with an unselected repository ancestor; select the common ancestor explicitly",
                target_artifact.path
            );
        }
        let mut artifact = target_artifact.clone();
        if occupied_ids.contains(&artifact.artifact_id) {
            artifact.artifact_id = collision_copy_artifact_id(target_artifact, &occupied_ids);
        }
        occupied_ids.insert(artifact.artifact_id);
        artifacts.push(artifact);
    }
    ResolvedTree::from_artifacts(artifacts)
        .map_err(|error| anyhow::anyhow!("splice selected checkout subtree: {error}"))
}

/// Allocate the stable identity of an exceptional checkout copy.
///
/// The target artifact ID cannot be reused when that identity remains outside
/// the selected subtree. Binding the copy to its source identity and selected
/// target location avoids operation-by-operation graph churn without turning
/// ordinary imported paths into identity seeds.
fn collision_copy_artifact_id(
    artifact: &ResolvedArtifact,
    occupied: &HashSet<ArtifactId>,
) -> ArtifactId {
    for counter in 0_u64.. {
        let mut hasher = Sha256::new();
        hasher.update(b"kin.checkout-collision-copy-artifact.v1\0");
        hasher.update(artifact.artifact_id.0.as_bytes());
        hasher.update(artifact.path.as_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let candidate = ArtifactId(uuid::Uuid::from_bytes(bytes));
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("u64 artifact remap namespace exhausted")
}

fn selected_materialized_count(tree: &ResolvedTree, selected: &RepoPath) -> Result<usize> {
    tree.artifacts_by_path()
        .filter(|artifact| path_is_selected(&artifact.path, selected))
        .try_fold(0_usize, |count, artifact| {
            Ok(count
                + usize::from(
                    kin_core::tree::source_projection_disposition(&artifact.path, artifact.entry)?
                        == kin_core::tree::SourceProjectionDisposition::Materialized,
                ))
        })
}

fn path_is_selected(path: &RepoPath, selected: &RepoPath) -> bool {
    path == selected
        || path
            .as_bytes()
            .strip_prefix(selected.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn paths_are_related(left: &RepoPath, right: &RepoPath) -> bool {
    path_is_selected(left, right) || path_is_selected(right, left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::TreeEntry;

    #[test]
    fn cross_boundary_copy_keeps_its_graph_assigned_id_across_later_checkouts() {
        let original_id = ArtifactId::new();
        let outside = RepoPath::from_utf8("outside.txt").unwrap();
        let selected = RepoPath::from_utf8("selected.txt").unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false);
        let current =
            ResolvedTree::from_artifacts([ResolvedArtifact::new(original_id, outside, entry)])
                .unwrap();
        let target = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            original_id,
            selected.clone(),
            entry,
        )])
        .unwrap();

        let copied = splice_checkout_tree(&current, &target, &selected).unwrap();
        let copied_id = copied.artifact_at_path(&selected).unwrap().artifact_id;
        assert_ne!(copied_id, original_id);

        let repeated = splice_checkout_tree(&copied, &target, &selected).unwrap();
        assert_eq!(repeated, copied);
        assert_eq!(
            repeated.artifact_at_path(&selected).unwrap().artifact_id,
            copied_id
        );
    }
}
