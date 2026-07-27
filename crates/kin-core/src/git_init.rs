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
    plan_semantic_git_import, preflight_git_migration, preflight_git_migration_after_publication,
    GitLocalIgnoreSourceKind, GitMigrationPreflightProof, LosslessGitRepository,
};
use kin_model::{
    compute_resolved_tree_hash, AdmissionCase, AuthorId, ChangeStore,
    EffectiveAdmissionPolicyStamp, ExternalObjectId, ExternalObjectKind, FrozenLocalOverlay,
    FrozenLocalOverlayDelta, GitExternalAuthorityDelta, GitMaterialHead, Hash256,
    LocalAdmissionRuleSource, LocalAdmissionRuleSourceKind, LocatedEntry, OperationId,
    RepositoryId, RepositoryTransaction, TreeDelta, WorkspaceExpectation, WorkspaceMutation,
    WorkspaceSemanticDelta,
};
use tracing::info;

use crate::config::{
    GitBranchTrackingConfig, GitCoexistenceConfig, GitPushDefault, GitRemoteTransportConfig,
    KinConfig,
};
use crate::error::{KinError, Result};
use crate::init::{prepare_repository_layout_at, publish_repository_layout_linearized, InitResult};
use crate::manifest::KinManifest;

/// Admit one clean materialized Git worktree as a complete Kin repository.
///
/// The source Git repository is never mutated. Publication is all-or-nothing:
/// source drift, unsupported compatibility state, an existing destination, or
/// any graph/CAS validation error leaves `.kin` absent.
pub fn init_from_git(working_dir: &Path) -> Result<InitResult> {
    init_from_git_with_hook(working_dir, || {})
}

fn init_from_git_with_hook(
    working_dir: &Path,
    before_final_source_proof: impl FnOnce(),
) -> Result<InitResult> {
    init_from_git_with_hooks(working_dir, before_final_source_proof, || {})
}

fn init_from_git_with_hooks(
    working_dir: &Path,
    before_final_source_proof: impl FnOnce(),
    after_repository_publication: impl FnOnce(),
) -> Result<InitResult> {
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
    let git_authority = build_git_external_authority(&snapshot, &capture_store)
        .map_err(|error| git_boundary_error("build exact Git authority", error))?;
    let semantic_plan = plan_semantic_git_import(&snapshot, &capture_store)
        .map_err(|error| git_boundary_error("derive exact semantic Git history", error))?;
    verify_material_workspace_seed(&semantic_plan.workspace_seed, &git_authority.material_head)?;
    let admitted = admit_semantic_git_import(&semantic_plan, &capture_store)
        .map_err(|error| git_boundary_error("derive branch-versioned admission policy", error))?;
    let source_proof = preflight_git_migration(&source, &snapshot, &semantic_plan, &capture_store)
        .map_err(|error| git_boundary_error("prove mutable Git workspace", error))?;

    let final_kin_dir = source.join(".kin");
    let staging_dir = source_parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
    let config = config_for_source(&snapshot, &source_proof.remote_mapping)?;
    let mut prepared =
        prepare_repository_layout_at(&staging_dir, &final_kin_dir, config, manifest)?;
    copy_captured_authority(&prepared, &snapshot, &capture_store, &source_proof)?;

    let workspace_seed = admitted.workspace_seed.clone();
    let workspace_policy = admitted.workspace_policy().clone();
    let workspace_base_change_id = admitted.workspace_base_change_id();
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

    let mut result = publish_repository_layout_linearized(prepared, |publication| {
        before_final_source_proof();
        let final_proof =
            preflight_git_migration(&source, &snapshot, &semantic_plan, &capture_store)
                .map_err(|error| git_boundary_error("repeat final Git source proof", error))?;
        if final_proof != source_proof {
            return Err(KinError::Other(
                "Git source proof changed before repository publication; retry from a fresh capture"
                    .to_string(),
            ));
        }
        let published = publication.publish()?;
        after_repository_publication();
        let published_proof = preflight_git_migration_after_publication(
            &source,
            published.path(),
            &snapshot,
            &semantic_plan,
            &capture_store,
        )
        .map_err(|error| git_boundary_error("prove Git source after publication", error))?;
        if published_proof != source_proof {
            return Err(KinError::Other(
                "Git source proof changed across repository publication; published authority is \
                 not safe to use without recovery"
                    .to_string(),
            ));
        }
        Ok(())
    })?;
    // Exact Git refs intentionally retain external-object targets, so the
    // generic bootstrap helper cannot infer the semantic identity of a peeled
    // HEAD from `WorkspaceMutation::new_base_target`. The admitted plan already
    // proved that alias while validating the complete history; preserve it in
    // the initialization receipt instead of reporting an absent initial change.
    result.authority.initial_change_id = workspace_base_change_id;

    info!(
        path = %source.display(),
        repository = %result.repository_id,
        workspace = %result.workspace_id,
        generation = result.authority.receipt.generation,
        "admitted exact Git repository as graph-owned Kin authority"
    );
    Ok(result)
}

fn verify_material_workspace_seed(
    seed: &kin_git::GitWorkspaceSeed,
    material_head: &GitMaterialHead,
) -> Result<()> {
    match material_head {
        GitMaterialHead::Unborn { .. } => {
            let exact_unborn = matches!(&seed.head, kin_model::WorkspaceHead::Symbolic { .. })
                && seed.base_target.is_none()
                && seed.base_commit_oid.is_none()
                && seed.base_tree_hash.is_none()
                && seed.base_tree.is_empty();
            if !exact_unborn {
                return Err(KinError::Other(
                    "semantic workspace seed disagrees with verified unborn Git HEAD".to_string(),
                ));
            }
        }
        GitMaterialHead::Commit { commit_oid, .. } => {
            let material_target = kin_model::RefTarget::external_object(ExternalObjectId::new(
                ExternalObjectKind::Commit,
                *commit_oid,
            ));
            let exact_head = match &seed.head {
                kin_model::WorkspaceHead::Symbolic { .. } => true,
                kin_model::WorkspaceHead::Detached { target } => target == &material_target,
            };
            if !exact_head
                || seed.base_target.as_ref() != Some(&material_target)
                || seed.base_commit_oid != Some(*commit_oid)
                || seed.base_tree_hash.is_none()
            {
                return Err(KinError::Other(
                    "semantic workspace seed disagrees with verified material Git HEAD".to_string(),
                ));
            }
        }
        GitMaterialHead::NonMaterializable { .. } => {
            return Err(KinError::Other(
                "verified Git HEAD cannot seed a material Kin workspace".to_string(),
            ));
        }
    }
    Ok(())
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

fn config_for_source(
    snapshot: &LosslessGitRepository,
    remote_mapping: &kin_git::GitRemoteMappingFacts,
) -> Result<KinConfig> {
    let mut config = KinConfig::default();
    if let kin_model::WorkspaceHead::Symbolic { target } = &snapshot.head {
        if target.is_branch() {
            let short = &target.as_bytes()[b"refs/heads/".len()..];
            if let Ok(short) = std::str::from_utf8(short) {
                config.default_branch = short.to_string();
            }
        }
    }
    config.git = map_git_coexistence_config(remote_mapping)?;
    config.validate()?;
    Ok(config)
}

fn map_git_coexistence_config(
    facts: &kin_git::GitRemoteMappingFacts,
) -> Result<GitCoexistenceConfig> {
    let remotes = facts
        .remotes
        .iter()
        .map(|remote| {
            Ok(GitRemoteTransportConfig {
                name: exact_utf8(&remote.name, "Git remote name")?,
                fetch_urls: exact_utf8_values(&remote.fetch_urls, "Git fetch URL")?,
                push_urls: exact_utf8_values(&remote.push_urls, "Git push URL")?,
                fetch_refspecs: exact_utf8_values(&remote.fetch_refspecs, "Git fetch refspec")?,
                push_refspecs: exact_utf8_values(&remote.push_refspecs, "Git push refspec")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let branches = facts
        .branch_tracking
        .iter()
        .map(|branch| {
            Ok(GitBranchTrackingConfig {
                branch: exact_utf8(&branch.branch, "Git branch name")?,
                remote: branch
                    .remote
                    .as_deref()
                    .map(|value| exact_utf8(value, "Git branch remote"))
                    .transpose()?,
                merge_refs: exact_utf8_values(&branch.merge_refs, "Git branch merge ref")?,
                push_remote: branch
                    .push_remote
                    .as_deref()
                    .map(|value| exact_utf8(value, "Git branch pushRemote"))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let remote_push_default = facts
        .remote_push_default
        .as_deref()
        .map(|value| exact_utf8(value, "Git remote.pushDefault"))
        .transpose()?;
    let push_default = facts
        .push_default
        .as_deref()
        .map(|value| {
            let value = exact_utf8(value, "Git push.default")?;
            GitPushDefault::from_exact_git_value(&value).ok_or_else(|| {
                KinError::Other(
                    "Git push.default escaped preflight without an exact typed mapping".to_string(),
                )
            })
        })
        .transpose()?;
    Ok(GitCoexistenceConfig {
        remotes,
        branches,
        remote_push_default,
        push_default,
    })
}

fn exact_utf8(value: &[u8], label: &str) -> Result<String> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| KinError::Other(format!("{label} escaped preflight with non-UTF-8 bytes")))
}

fn exact_utf8_values(values: &[Vec<u8>], label: &str) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| exact_utf8(value, label))
        .collect()
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
    let valid_tree_identity = match workspace_seed.base_tree_hash {
        Some(expected) => expected == tree_hash,
        None => {
            workspace_seed.base_target.is_none()
                && workspace_seed.base_commit_oid.is_none()
                && workspace_seed.base_tree.is_empty()
        }
    };
    if !valid_tree_identity {
        return Err(KinError::Other(
            "admitted Git workspace tree does not match its canonical base identity".to_string(),
        ));
    }
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
    let semantic_delta = imported_workspace_semantic_delta(transaction, &workspace_seed)?;
    transaction.workspace_mutation = Some(WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: workspace_seed.head.clone(),
        new_base_target: workspace_seed.base_target,
        new_base_tree_hash: workspace_seed.base_tree_hash,
        tree_deltas,
        new_tree_hash: tree_hash,
        semantic_delta,
        new_shared_admission_policy: workspace_policy,
        new_admission_policy: effective_policy,
    });
    transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(local_overlay));
    Ok(())
}

fn imported_workspace_semantic_delta(
    transaction: &RepositoryTransaction,
    workspace_seed: &kin_git::GitWorkspaceSeed,
) -> Result<WorkspaceSemanticDelta> {
    let Some(base_target) = &workspace_seed.base_target else {
        return Ok(WorkspaceSemanticDelta::default());
    };
    let change_id = match base_target {
        kin_model::RefTarget::Change { change_id } => *change_id,
        kin_model::RefTarget::ExternalObject { object } => transaction
            .aliases
            .iter()
            .find(|alias| alias.oid == object.oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                KinError::Other(format!(
                    "Git workspace base {} has no semantic change alias in its bootstrap transaction",
                    object.oid
                ))
            })?,
        kin_model::RefTarget::Symbolic { .. } => {
            return Err(KinError::Other(
                "Git workspace bootstrap base must be resolved before semantic admission"
                    .to_string(),
            ))
        }
    };

    let graph = kin_db::InMemoryGraph::new();
    for change in &transaction.changes {
        graph.create_change(change).map_err(|error| {
            KinError::Other(format!("stage imported semantic history: {error}"))
        })?;
    }
    let target = graph.resolve_graph_at(&change_id).map_err(|error| {
        KinError::Other(format!("resolve imported workspace semantics: {error}"))
    })?;
    crate::diff_workspace_semantics(
        &Default::default(),
        &Default::default(),
        &target.entities,
        &target.relations,
    )
    .map_err(|error| KinError::Other(format!("derive imported workspace semantics: {error}")))
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
    let case = if proof.ignored_local.ignore_case {
        AdmissionCase::FoldAscii
    } else {
        AdmissionCase::Sensitive
    };
    FrozenLocalOverlay::new(workspace_id, 0, case, sources)
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
    fn exact_remote_configuration_is_sealed_in_local_kin_config() {
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
        git(
            &source,
            [
                "remote",
                "set-url",
                "--add",
                "origin",
                "https://mirror.example.invalid/kin.git",
            ],
        );
        git(
            &source,
            [
                "remote",
                "set-url",
                "--push",
                "origin",
                "ssh://example.invalid/kin.git",
            ],
        );
        git(
            &source,
            [
                "config",
                "--add",
                "remote.origin.push",
                "refs/heads/main:refs/heads/main",
            ],
        );
        git(&source, ["config", "branch.main.remote", "origin"]);
        git(&source, ["config", "branch.main.merge", "refs/heads/main"]);
        git(&source, ["config", "remote.pushDefault", "origin"]);
        git(&source, ["config", "push.default", "simple"]);

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.config.git.remotes.len(), 1);
        assert_eq!(
            result.config.git.remotes[0].fetch_urls,
            vec![
                "https://example.invalid/kin.git",
                "https://mirror.example.invalid/kin.git",
            ]
        );
        assert_eq!(
            result.config.git.remotes[0].push_urls,
            vec!["ssh://example.invalid/kin.git"]
        );
        assert_eq!(
            result.config.git.remotes[0].fetch_refspecs,
            vec!["+refs/heads/*:refs/remotes/origin/*"]
        );
        assert_eq!(
            result.config.git.remotes[0].push_refspecs,
            vec!["refs/heads/main:refs/heads/main"]
        );
        assert_eq!(result.config.git.branches.len(), 1);
        assert_eq!(
            result.config.git.branches[0].remote.as_deref(),
            Some("origin")
        );
        assert_eq!(
            result.config.git.remote_push_default.as_deref(),
            Some("origin")
        );
        assert_eq!(result.config.git.push_default, Some(GitPushDefault::Simple));
        let reopened = KinConfig::load(&result.layout.config_path()).unwrap();
        assert_eq!(reopened.git, result.config.git);
        assert!(!format!("{reopened:?}").contains("example.invalid"));
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn unsafe_remote_configuration_fails_before_staging_without_disclosure() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);
        git(
            &source,
            [
                "remote",
                "add",
                "origin",
                "https://super-secret@example.invalid/private/repo.git",
            ],
        );

        let error = init_from_git(&source).unwrap_err().to_string();

        assert!(error.contains("safe exact subset"), "{error}");
        assert!(!error.contains("super-secret"), "{error}");
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn same_count_remote_url_drift_at_final_proof_blocks_publication() {
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

        let source_for_hook = source.clone();
        let error = init_from_git_with_hook(&source, move || {
            git(
                &source_for_hook,
                [
                    "remote",
                    "set-url",
                    "origin",
                    "https://changed.example.invalid/kin.git",
                ],
            );
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("source proof changed"), "{error}");
        assert!(!error.contains("changed.example.invalid"), "{error}");
        assert!(!source.join(".kin").exists());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn source_drift_immediately_after_publication_is_detected_fail_loud() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"exact source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "initial"]);

        let source_for_hook = source.clone();
        let error = init_from_git_with_hooks(
            &source,
            || {},
            move || {
                std::fs::write(source_for_hook.join("README.md"), b"raced source\n").unwrap();
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(error.to_string().contains("after publication"));
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn pristine_unborn_repository_without_an_index_initializes_atomically() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        assert!(!source.join(".git/index").exists());

        let result = init_from_git(&source).unwrap();

        assert_eq!(result.authority.receipt.generation, 1);
        assert!(result.authority.workspace.base_target.is_none());
        assert!(result.authority.workspace.base_tree_hash.is_none());
        assert!(source.join(".kin").is_dir());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn born_empty_commit_keeps_a_present_empty_tree_identity() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        git(
            &source,
            [
                "commit",
                "--allow-empty",
                "--no-gpg-sign",
                "-m",
                "born empty",
            ],
        );

        let result = init_from_git(&source).unwrap();

        assert!(result.authority.workspace.base_target.is_some());
        assert!(result.authority.workspace.base_tree_hash.is_some());
        assert_eq!(
            result.authority.workspace.base_tree_hash,
            Some(result.authority.workspace.workspace_tree_hash)
        );
        assert!(!result.authority.workspace.is_dirty());
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn detached_annotated_tag_keeps_raw_tag_authority_and_seeds_the_peeled_commit() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_annotated_tag_source(&source);
        let tag_oid = git_stdout(&source, ["rev-parse", "refs/tags/release"]);
        std::fs::write(source.join(".git/HEAD"), format!("{}\n", tag_oid.trim())).unwrap();

        let result = init_from_git(&source).unwrap();
        let backend = std::sync::Arc::new(kin_db::LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            kin_db::RepositoryAuthorityManager::open(result.repository_id.clone(), backend)
                .unwrap();
        let lease = authority.read_authority();
        let git_authority = lease.metadata().git_external_authority.as_ref().unwrap();
        let (direct_target, commit_oid) = match &git_authority.material_head {
            GitMaterialHead::Commit {
                direct_target,
                tag_chain,
                commit_oid,
                ..
            } => {
                assert_eq!(direct_target.kind, ExternalObjectKind::Tag);
                assert_eq!(tag_chain.as_slice(), [*direct_target]);
                (*direct_target, *commit_oid)
            }
            other => panic!("expected material annotated-tag commit, got {other:?}"),
        };
        assert!(matches!(
            git_authority.raw_head,
            kin_model::GitRawTarget::Direct { object } if object == direct_target
        ));
        let material_target = kin_model::RefTarget::external_object(ExternalObjectId::new(
            ExternalObjectKind::Commit,
            commit_oid,
        ));
        assert_eq!(
            result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Detached {
                target: material_target.clone()
            }
        );
        assert_eq!(
            result.head,
            kin_model::WorkspaceHead::Detached {
                target: material_target.clone()
            }
        );
        assert_eq!(
            result.authority.workspace.base_target,
            Some(material_target)
        );
        assert_no_staging_directories(root.path());
    }

    #[test]
    fn symbolic_annotated_tag_keeps_raw_ref_authority_and_seeds_the_peeled_commit() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_annotated_tag_source(&source);
        git(&source, ["symbolic-ref", "HEAD", "refs/tags/release"]);

        let result = init_from_git(&source).unwrap();
        let backend = std::sync::Arc::new(kin_db::LocalFileBackend::new(result.layout.kindb_dir()));
        let authority =
            kin_db::RepositoryAuthorityManager::open(result.repository_id.clone(), backend)
                .unwrap();
        let lease = authority.read_authority();
        let git_authority = lease.metadata().git_external_authority.as_ref().unwrap();
        let (direct_target, commit_oid) = match &git_authority.material_head {
            GitMaterialHead::Commit {
                direct_target,
                tag_chain,
                commit_oid,
                ..
            } => {
                assert_eq!(direct_target.kind, ExternalObjectKind::Tag);
                assert_eq!(tag_chain.as_slice(), [*direct_target]);
                (*direct_target, *commit_oid)
            }
            other => panic!("expected material annotated-tag commit, got {other:?}"),
        };
        let tag_ref = kin_model::RefName::tag(b"release").unwrap();
        assert_eq!(
            git_authority.raw_head,
            kin_model::GitRawTarget::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert!(git_authority.raw_refs.iter().any(|raw_ref| {
            raw_ref.name == tag_ref
                && matches!(
                    raw_ref.target,
                    kin_model::GitRawTarget::Direct { object } if object == direct_target
                )
        }));
        assert_eq!(
            result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert_eq!(
            result.head,
            kin_model::WorkspaceHead::Symbolic {
                target: tag_ref.clone()
            }
        );
        assert_eq!(
            result.authority.workspace.base_target,
            Some(kin_model::RefTarget::external_object(
                ExternalObjectId::new(ExternalObjectKind::Commit, commit_oid)
            ))
        );
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn byte_symbolic_git_head_is_reported_exactly_without_inventing_main() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        initialize_git(&source);
        let raw_branch_leaf = b"raw-\xff".to_vec();
        let mut raw_head = b"ref: refs/heads/".to_vec();
        raw_head.extend_from_slice(&raw_branch_leaf);
        raw_head.push(b'\n');
        std::fs::write(source.join(".git/HEAD"), raw_head).unwrap();

        let result = init_from_git(&source).unwrap();

        let mut expected = b"refs/heads/".to_vec();
        expected.extend_from_slice(&raw_branch_leaf);
        assert!(matches!(
            &result.head,
            kin_model::WorkspaceHead::Symbolic { target } if target.as_bytes() == expected
        ));
        assert!(matches!(
            &result.authority.workspace.workspace_head,
            kin_model::WorkspaceHead::Symbolic { target } if target.as_bytes() == expected
        ));
        assert_ne!(
            match &result.head {
                kin_model::WorkspaceHead::Symbolic { target } => target.as_bytes(),
                kin_model::WorkspaceHead::Detached { .. } => unreachable!(),
            },
            b"refs/heads/main"
        );
        assert_no_staging_directories(root.path());
    }

    #[cfg(unix)]
    #[test]
    fn private_git_repository_keeps_staged_and_published_authority_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        initialize_git(&source);
        std::fs::write(source.join("README.md"), b"private source\n").unwrap();
        git(&source, ["add", "--all"]);
        git(&source, ["commit", "-m", "private history"]);

        let staging_parent = root.path().to_path_buf();
        let result = init_from_git_with_hook(&source, move || {
            let staging = std::fs::read_dir(&staging_parent)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.is_dir()
                        && path
                            .file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".kin.init-"))
                })
                .expect("complete unpublished staging directory");
            assert_eq!(
                std::fs::symlink_metadata(&staging)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert!(staging.join("config.toml").is_file());
        })
        .unwrap();

        assert_eq!(
            std::fs::symlink_metadata(result.layout.root())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
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
        assert!(result.authority.initial_change_id.is_some());
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

    fn initialize_annotated_tag_source(source: &Path) {
        initialize_git(source);
        std::fs::write(source.join("README.md"), b"annotated tag source\n").unwrap();
        git(source, ["add", "--all"]);
        git(source, ["commit", "-m", "tagged commit"]);
        git(source, ["tag", "--annotate", "release", "-m", "release"]);
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
            .env(
                "GIT_CONFIG_GLOBAL",
                repository.join(".kin-test-global-gitconfig"),
            )
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

    fn git_stdout<const N: usize>(repository: &Path, args: [&str; N]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                repository.join(".kin-test-global-gitconfig"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}
