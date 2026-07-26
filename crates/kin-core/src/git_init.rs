// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact, fail-closed Git repository admission.
//!
//! Git is consulted only at this explicit ingestion boundary. The resulting
//! history, refs, raw object closure, workspace tree, admission policy, and
//! local ignore overlay are committed together as graph-owned authority before
//! the staged `.kin` repository is atomically published.

use std::path::Path;

use kin_blobs::BlobStore;
use kin_git::{
    admit_semantic_git_import, build_git_external_authority, capture_lossless_git_repository,
    plan_semantic_git_import, preflight_git_migration, GitLocalIgnoreSourceKind,
    GitMigrationPreflightProof, LosslessGitRepository,
};
use kin_model::{
    compute_resolved_tree_hash, AdmissionScanToken, AuthorId, EffectiveAdmissionPolicyStamp,
    FrozenLocalOverlay, FrozenLocalOverlayDelta, GitExternalAuthorityDelta, Hash256,
    LocalAdmissionRuleSource, LocalAdmissionRuleSourceKind, LocatedEntry, OperationId,
    RepositoryId, RepositoryTransaction, ResolvedTree, TreeDelta, WorkspaceExpectation,
    WorkspaceMutation, ADMISSION_POLICY_SEMANTICS_VERSION,
};
use tracing::info;

use crate::config::KinConfig;
use crate::error::{KinError, Result};
use crate::init::{
    prepare_repository_layout_at, publish_repository_layout_after_check, InitResult,
};
use crate::manifest::KinManifest;

/// Admit one clean materialized Git worktree as a complete Kin repository.
///
/// The source Git repository is never mutated. Publication is all-or-nothing:
/// source drift, unsupported compatibility state, an existing destination, or
/// any graph/CAS validation error leaves `.kin` absent.
pub fn init_from_git(working_dir: &Path) -> Result<InitResult> {
    let source = canonical_new_repository_root(working_dir)?;
    require_git_boundary(&source)?;

    let manifest = KinManifest::new();
    let repository_id = RepositoryId::new(manifest.repo_id.clone())
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    let source_parent = source.parent().ok_or_else(|| {
        KinError::Other(format!(
            "repository root has no parent for isolated Git capture: {}",
            source.display()
        ))
    })?;
    let capture_dir = tempfile::Builder::new()
        .prefix(".kin-git-capture-")
        .tempdir_in(source_parent)
        .map_err(|error| KinError::io(source_parent, error))?;
    let capture_store = BlobStore::new(capture_dir.path().join("objects"))
        .map_err(|error| git_boundary_error("create capture CAS", error))?;

    let snapshot = capture_lossless_git_repository(&source, repository_id, &capture_store)
        .map_err(|error| git_boundary_error("capture exact Git repository", error))?;
    let semantic_plan = plan_semantic_git_import(&snapshot, &capture_store)
        .map_err(|error| git_boundary_error("derive exact semantic Git history", error))?;
    let admitted = admit_semantic_git_import(&semantic_plan, &capture_store)
        .map_err(|error| git_boundary_error("derive branch-versioned admission policy", error))?;
    let git_authority = build_git_external_authority(&snapshot, &capture_store)
        .map_err(|error| git_boundary_error("build exact Git authority", error))?;
    let source_proof = preflight_git_migration(&source, &snapshot, &semantic_plan, &capture_store)
        .map_err(|error| git_boundary_error("prove mutable Git workspace", error))?;
    reject_unmapped_remotes(&source_proof)?;

    let staging_dir = source_parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
    let config = config_for_source(&snapshot);
    let mut prepared = prepare_repository_layout_at(&staging_dir, config, manifest)?;
    copy_captured_authority(&prepared, &snapshot, &capture_store, &source_proof)?;

    let workspace_seed = admitted.workspace_seed.clone();
    let workspace_policy = admitted.workspace_policy().clone();
    let mut transaction = admitted
        .into_generation_zero_repository_transaction(
            &capture_store,
            OperationId::new(),
            prepared.initial_roots().clone(),
            AuthorId::new("kin-git-import"),
            "admit exact Git repository authority",
        )
        .map_err(|error| git_boundary_error("construct Git bootstrap transaction", error))?;
    bind_workspace_authority(
        &mut transaction,
        prepared.workspace_id(),
        workspace_seed,
        workspace_policy,
        &source_proof,
    )?;
    transaction.git_authority_delta = Some(GitExternalAuthorityDelta::initialize(git_authority));
    transaction
        .validate()
        .map_err(|error| KinError::Other(format!("invalid Git bootstrap transaction: {error}")))?;
    prepared.commit_repository_bootstrap(&transaction)?;

    let final_kin_dir = source.join(".kin");
    let result = publish_repository_layout_after_check(prepared, &final_kin_dir, || {
        let final_proof =
            preflight_git_migration(&source, &snapshot, &semantic_plan, &capture_store)
                .map_err(|error| git_boundary_error("repeat final Git source proof", error))?;
        if final_proof != source_proof {
            return Err(KinError::Other(
                "Git source proof changed before repository publication; retry from a fresh capture"
                    .to_string(),
            ));
        }
        Ok(())
    })?;

    info!(
        path = %source.display(),
        repository = %result.repository_id,
        workspace = %result.workspace_id,
        generation = result.authority.receipt.generation,
        "admitted exact Git repository as graph-owned Kin authority"
    );
    Ok(result)
}

fn canonical_new_repository_root(working_dir: &Path) -> Result<std::path::PathBuf> {
    let source = working_dir
        .canonicalize()
        .map_err(|error| KinError::io(working_dir, error))?;
    let kin_dir = source.join(".kin");
    match std::fs::symlink_metadata(&kin_dir) {
        Ok(_) => return Err(KinError::AlreadyInitialized(source.display().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(KinError::io(&kin_dir, error)),
    }
    Ok(source)
}

fn require_git_boundary(source: &Path) -> Result<()> {
    let marker = source.join(".git");
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(KinError::Other(format!(
            "Git repository marker must not be a symlink: {}",
            marker.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(KinError::Other(
            format!("no Git repository marker found at {}", marker.display()),
        )),
        Err(error) => Err(KinError::io(&marker, error)),
    }
}

fn config_for_source(snapshot: &LosslessGitRepository) -> KinConfig {
    let mut config = KinConfig::default();
    if let kin_model::WorkspaceHead::Symbolic { target } = &snapshot.head {
        if target.is_branch() {
            let short = &target.as_bytes()[b"refs/heads/".len()..];
            if let Ok(short) = std::str::from_utf8(short) {
                config.default_branch = short.to_string();
            }
        }
    }
    config
}

fn reject_unmapped_remotes(proof: &GitMigrationPreflightProof) -> Result<()> {
    if !proof.remote_mapping.mapper_required {
        return Ok(());
    }
    Err(KinError::Other(format!(
        "Git repository has {} remote configuration block(s) and {} branch-tracking block(s); exact Kin remote mapping is required before migration",
        proof.remote_mapping.remotes.len(),
        proof.remote_mapping.branch_tracking.len()
    )))
}

fn copy_captured_authority(
    prepared: &crate::init::PreparedRepositoryInit,
    snapshot: &LosslessGitRepository,
    capture_store: &BlobStore,
    proof: &GitMigrationPreflightProof,
) -> Result<()> {
    for record in &snapshot.objects {
        let capture_hash = kin_blobs::Hash256::from_bytes(*record.body_hash.as_bytes());
        let body = capture_store.read(&capture_hash).map_err(|error| {
            git_boundary_error(
                format!("read captured Git object {}", record.object.oid),
                error,
            )
        })?;
        prepared.save_source_blob(record.body_hash, &body)?;
    }
    for input in &proof.ignored_local.inputs {
        let observed_len = u64::try_from(input.body.len()).map_err(|_| {
            KinError::Other("local Git ignore input exceeds u64 byte length".to_string())
        })?;
        let observed_hash = Hash256::from_bytes(kin_blobs::digest_bytes(&input.body));
        if observed_len != input.body_len || observed_hash != input.body_hash {
            return Err(KinError::Other(
                "local Git ignore input no longer matches its preflight identity".to_string(),
            ));
        }
        prepared.save_source_blob(input.body_hash, &input.body)?;
    }
    Ok(())
}

fn bind_workspace_authority(
    transaction: &mut RepositoryTransaction,
    workspace_id: kin_model::WorkspaceId,
    workspace_seed: kin_git::GitWorkspaceSeed,
    workspace_policy: kin_model::SharedAdmissionPolicy,
    proof: &GitMigrationPreflightProof,
) -> Result<()> {
    if proof.head != workspace_seed.head
        || proof.base_target != workspace_seed.base_target
        || proof.base_commit_oid != workspace_seed.base_commit_oid
        || proof.base_tree_hash != workspace_seed.base_tree_hash
    {
        return Err(KinError::Other(
            "Git preflight is not bound to the admitted workspace seed".to_string(),
        ));
    }
    let tree_hash = compute_resolved_tree_hash(&workspace_seed.base_tree)
        .map_err(|error| KinError::Other(error.to_string()))?;
    if workspace_seed
        .base_tree_hash
        .is_some_and(|hash| hash != tree_hash)
        || workspace_seed.base_tree_hash.is_none() != workspace_seed.base_tree.is_empty()
    {
        return Err(KinError::Other(
            "admitted Git workspace tree does not match its canonical base identity".to_string(),
        ));
    }
    let empty_tree_hash = compute_resolved_tree_hash(&ResolvedTree::default())
        .map_err(|error| KinError::Other(error.to_string()))?;
    let tree_deltas = workspace_seed
        .base_tree
        .artifacts()
        .map(|artifact| TreeDelta::Added {
            artifact_id: artifact.artifact_id,
            new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
        })
        .collect::<Vec<_>>();
    let local_overlay = frozen_local_overlay(workspace_id, proof)?;
    let effective_policy = EffectiveAdmissionPolicyStamp {
        shared: workspace_policy.stamp(),
        local: local_overlay.stamp(),
    };
    transaction.workspace_mutation = Some(WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: workspace_seed.head.clone(),
        new_base_target: workspace_seed.base_target,
        new_base_tree_hash: workspace_seed.base_tree_hash,
        tree_deltas,
        new_tree_hash: tree_hash,
        new_shared_admission_policy: workspace_policy,
        new_admission_policy: effective_policy,
    });
    transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(local_overlay));
    transaction.admission_scan_token = Some(AdmissionScanToken {
        repository_id: transaction.repository_id.clone(),
        workspace_id,
        workspace_generation: 0,
        workspace_head: workspace_seed.head,
        baseline_tree_hash: empty_tree_hash,
        observed_tree_hash: tree_hash,
        matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
        shared_policy: effective_policy.shared,
        local_overlay: effective_policy.local,
    });
    Ok(())
}

fn frozen_local_overlay(
    workspace_id: kin_model::WorkspaceId,
    proof: &GitMigrationPreflightProof,
) -> Result<FrozenLocalOverlay> {
    let sources = proof
        .ignored_local
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.order != index {
                return Err(KinError::Other(
                    "local Git ignore precedence is not contiguous".to_string(),
                ));
            }
            let precedence = u32::try_from(index).map_err(|_| {
                KinError::Other("local Git ignore source count exceeds u32".to_string())
            })?;
            let kind = match input.source_kind {
                GitLocalIgnoreSourceKind::ResolvedGlobalExcludes => {
                    LocalAdmissionRuleSourceKind::GitGlobalExclude
                }
                GitLocalIgnoreSourceKind::RepositoryInfoExclude => {
                    LocalAdmissionRuleSourceKind::GitInfoExclude
                }
            };
            Ok(LocalAdmissionRuleSource {
                kind,
                body_hash: input.body_hash,
                body_len: input.body_len,
                precedence,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    FrozenLocalOverlay::new(workspace_id, 0, sources)
        .map_err(|error| KinError::Other(error.to_string()))
}

fn git_boundary_error(context: impl std::fmt::Display, error: impl std::fmt::Display) -> KinError {
    KinError::Other(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn unmapped_remote_configuration_fails_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(
            &source,
            ["remote", "add", "origin", "https://example.invalid/kin.git"],
        );

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(
            error.contains("exact Kin remote mapping is required"),
            "{error}"
        );
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn exact_git_init_admits_polyglot_non_code_and_opaque_history_atomically() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::Arc;

        use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
        use kin_model::{RepoPath, TreeEntry};

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::create_dir_all(source.join("service")).unwrap();
        std::fs::write(source.join(".gitignore"), b"*.tmp\n").unwrap();
        std::fs::write(
            source.join("compose.yaml"),
            b"services:\n  api:\n    build: .\n",
        )
        .unwrap();
        std::fs::write(source.join("Dockerfile"), b"FROM scratch\n").unwrap();
        std::fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
        std::fs::write(source.join("service/app.py"), b"print('kin')\n").unwrap();
        let payload = [0_u8, 255, 17, 0, 128, 42];
        std::fs::write(source.join("payload.bin"), payload).unwrap();
        let executable = source.join("tool");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        symlink("compose.yaml", source.join("compose-link")).unwrap();
        let raw_name = if cfg!(target_os = "linux") {
            let name = OsString::from_vec(vec![b'r', b'a', b'w', b'-', 0x80]);
            std::fs::write(source.join(&name), b"raw path\n").unwrap();
            Some(name)
        } else {
            // macOS rejects an invalid UTF-8 pathname at the filesystem API
            // boundary. The DB/raw-tree contract covers that case without
            // pretending the local checkout can materialize it.
            None
        };
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "mixed exact tree"]);

        std::fs::create_dir_all(source.join("containers")).unwrap();
        git(&source, ["mv", "Dockerfile", "containers/Dockerfile"]);
        std::fs::write(
            source.join("compose.yaml"),
            b"services:\n  api:\n    build:\n      context: .\n",
        )
        .unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "move build artifact"]);
        std::fs::write(source.join("scratch.tmp"), b"ignored local state\n").unwrap();

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.authority.receipt.generation, 1);
        assert!(!result.authority.workspace.is_dirty());
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());

        let backend = Arc::new(LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            RepositoryAuthorityManager::open(result.repository_id.clone(), backend).unwrap();
        let lease = authority.read_authority();
        let metadata = lease.metadata();
        let git_authority = metadata.git_external_authority.as_ref().unwrap();
        assert_eq!(git_authority.commit_projections.len(), 2);
        assert_eq!(metadata.aliases.len(), 2);
        assert_eq!(metadata.workspaces.len(), 1);
        let workspace = &metadata.workspaces[0];
        assert_eq!(
            workspace.tree.artifacts().len(),
            if raw_name.is_some() { 9 } else { 8 }
        );

        let compose_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let compose = workspace.tree.artifact_at_path(&compose_path).unwrap();
        let TreeEntry::Blob {
            hash: compose_hash,
            executable: false,
        } = compose.entry
        else {
            panic!("Compose file lost exact blob identity");
        };
        assert_eq!(
            authority.load_source_blob(compose_hash).unwrap().unwrap(),
            b"services:\n  api:\n    build:\n      context: .\n"
        );

        let payload_path = RepoPath::from_utf8("payload.bin").unwrap();
        let payload_artifact = workspace.tree.artifact_at_path(&payload_path).unwrap();
        let TreeEntry::Blob {
            hash: payload_hash,
            executable: false,
        } = payload_artifact.entry
        else {
            panic!("binary payload lost exact blob identity");
        };
        assert_eq!(
            authority.load_source_blob(payload_hash).unwrap().unwrap(),
            payload
        );

        if let Some(raw_name) = raw_name {
            let raw_path = RepoPath::from_bytes(raw_name.as_encoded_bytes()).unwrap();
            assert!(workspace.tree.artifact_at_path(&raw_path).is_some());
        }
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("compose-link").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Symlink { .. }
        ));
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("tool").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        assert!(workspace
            .tree
            .artifact_at_path(&RepoPath::from_utf8("containers/Dockerfile").unwrap())
            .is_some());
    }

    fn initialize_git(source: &Path) {
        git(source, ["init", "--initial-branch=main"]);
        git(source, ["config", "user.email", "kin@example.invalid"]);
        git(source, ["config", "user.name", "Kin Test"]);
    }

    fn assert_no_staging_directories(parent: &Path) {
        let leftovers = std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| {
                name.to_string_lossy().starts_with(".kin.init-")
                    || name.to_string_lossy().starts_with(".kin-git-capture-")
            })
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
    }

    fn git<const N: usize>(repository: &Path, args: [&str; N]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
