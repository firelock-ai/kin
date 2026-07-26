// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_model::{
    compute_resolved_tree_hash, AdmissionPolicyDelta, AdmissionScanToken, AuthorId,
    DefaultRefExpectation, DefaultRefMutation, EffectiveAdmissionPolicyStamp, FrozenLocalOverlay,
    FrozenLocalOverlayDelta, OperationId, RefExpectation, RefMutation, RefName, RefTarget,
    RefUpdatePolicy, RepositoryAuthorityStore, RepositoryCommitReceipt, RepositoryId,
    RepositoryTransaction, SemanticChange, SemanticChangeId, SharedAdmissionPolicy, WorkspaceHead,
    WorkspaceId, WorkspaceMutation, WorkspaceSnapshotBinding, ADMISSION_POLICY_SEMANTICS_VERSION,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use tracing::info;

use crate::config::KinConfig;
use crate::error::{KinError, Result};
use crate::layout::{KinLayout, KIN_LAYOUT_VERSION};
use crate::manifest::KinManifest;

/// Result of creating a repository authority envelope.
#[derive(Debug)]
pub struct RepositoryBootstrap {
    pub receipt: RepositoryCommitReceipt,
    pub workspace: WorkspaceSnapshotBinding,
    /// Present only when initialization admitted real history.
    pub initial_change_id: Option<SemanticChangeId>,
}

/// Result of `kin init`.
#[derive(Debug)]
pub struct InitResult {
    pub layout: KinLayout,
    pub config: KinConfig,
    pub manifest: KinManifest,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub default_ref: RefName,
    pub authority: RepositoryBootstrap,
}

/// Initialize a new, empty Kin repository at `working_dir`.
///
/// Empty initialization creates an unborn symbolic default ref and an exact
/// empty workspace in one repository-authority transaction. It deliberately
/// does not invent a synthetic commit: the first real commit is the root of
/// history, matching Git's unborn-branch semantics.
///
/// # Errors
///
/// Returns `KinError::AlreadyInitialized` if `.kin/` already exists.
pub fn init(working_dir: &Path) -> Result<InitResult> {
    let kin_dir = working_dir.join(".kin");

    if kin_dir.exists() {
        return Err(KinError::AlreadyInitialized(
            working_dir.display().to_string(),
        ));
    }

    std::fs::create_dir_all(&kin_dir).map_err(|error| KinError::io(&kin_dir, error))?;
    let layout = KinLayout::new(kin_dir);
    for directory in layout.all_dirs() {
        std::fs::create_dir_all(&directory).map_err(|error| KinError::io(&directory, error))?;
    }
    std::fs::write(layout.version_path(), KIN_LAYOUT_VERSION.to_string())
        .map_err(|error| KinError::io(layout.version_path(), error))?;

    let config = KinConfig::default();
    config.save(&layout.config_path())?;

    let manifest = KinManifest::new();
    manifest.save(&layout.manifest_path())?;
    let repository_id = RepositoryId::new(manifest.repo_id.clone())
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id)
        .map_err(|error| KinError::Other(format!("invalid workspace identity: {error}")))?;
    let workspace_id = WorkspaceId::from_uuid(workspace_uuid);
    let default_ref = RefName::branch(config.default_branch.as_bytes())
        .map_err(|error| KinError::Other(format!("invalid default ref: {error}")))?;

    let backend = Arc::new(LocalFileBackend::new(layout.kindb_dir()));
    let authority =
        RepositoryAuthorityManager::open(repository_id.clone(), backend).map_err(graph_error)?;
    let bootstrap = initialize_repository_authority(
        &authority,
        repository_id.clone(),
        workspace_id,
        default_ref.clone(),
        SharedAdmissionPolicy::empty(0),
        None,
    )?;

    info!(
        path = %working_dir.display(),
        repository = %repository_id,
        workspace = %workspace_id,
        default_ref = %default_ref,
        "initialized unborn kin repository authority"
    );

    Ok(InitResult {
        layout,
        config,
        manifest,
        repository_id,
        workspace_id,
        default_ref,
        authority: bootstrap,
    })
}

/// Commit the first complete repository-authority state.
///
/// `initial_change` is optional by design. `None` creates an unborn default
/// ref. `Some(change)` is reserved for initialization that is admitting real
/// history (for example, a snapshot import); it creates the default ref at that
/// exact change and requires the change to initialize the supplied shared
/// admission policy.
pub fn initialize_repository_authority<B>(
    authority: &RepositoryAuthorityManager<B>,
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
    default_ref: RefName,
    shared_policy: SharedAdmissionPolicy,
    initial_change: Option<SemanticChange>,
) -> Result<RepositoryBootstrap>
where
    B: StorageBackend + 'static,
{
    shared_policy
        .validate()
        .map_err(|error| KinError::Other(error.to_string()))?;
    let initial_change_id = initial_change.as_ref().map(|change| change.id);
    if let Some(change) = &initial_change {
        if !change.parents.is_empty() {
            return Err(KinError::Other(
                "initial repository change must have no parents".to_string(),
            ));
        }
        let expected_policy = AdmissionPolicyDelta::initialize(shared_policy.clone());
        if change.admission_policy_delta.as_ref() != Some(&expected_policy) {
            return Err(KinError::Other(
                "initial repository change must initialize the exact shared admission policy"
                    .to_string(),
            ));
        }
        kin_model::validate_semantic_change_id(change)
            .map_err(|error| KinError::Other(error.to_string()))?;
    }

    let tree_deltas = initial_change
        .as_ref()
        .map(|change| change.tree_deltas.clone())
        .unwrap_or_default();
    let tree = kin_model::ResolvedTree::default()
        .apply(&tree_deltas)
        .map_err(|error| KinError::Other(error.to_string()))?;
    let empty_tree_hash = compute_resolved_tree_hash(&kin_model::ResolvedTree::default())
        .map_err(|error| KinError::Other(error.to_string()))?;
    let tree_hash =
        compute_resolved_tree_hash(&tree).map_err(|error| KinError::Other(error.to_string()))?;
    let base_target = initial_change_id.map(RefTarget::change);
    let base_tree_hash = initial_change_id.map(|_| tree_hash);
    let workspace_head = WorkspaceHead::Symbolic {
        target: default_ref.clone(),
    };
    let local_overlay = FrozenLocalOverlay::new(workspace_id, 0, Vec::new())
        .map_err(|error| KinError::Other(error.to_string()))?;
    let admission_policy = EffectiveAdmissionPolicyStamp {
        shared: shared_policy.stamp(),
        local: local_overlay.stamp(),
    };
    let workspace_mutation = WorkspaceMutation {
        workspace_id,
        expected: kin_model::WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: workspace_head.clone(),
        new_base_target: base_target.clone(),
        new_base_tree_hash: base_tree_hash,
        tree_deltas,
        new_tree_hash: tree_hash,
        new_shared_admission_policy: shared_policy,
        new_admission_policy: admission_policy,
    };

    let lease = authority.read_authority();
    let mut transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: repository_id.clone(),
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("kin"),
        reason: if initial_change.is_some() {
            "initialize repository with admitted history".to_string()
        } else {
            "initialize unborn repository workspace".to_string()
        },
        external_objects: Vec::new(),
        changes: initial_change.into_iter().collect(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(default_ref.clone()),
        }),
        workspace_mutation: Some(workspace_mutation),
        local_overlay_delta: Some(FrozenLocalOverlayDelta::initialize(local_overlay)),
        admission_scan_token: Some(AdmissionScanToken {
            repository_id: repository_id.clone(),
            workspace_id,
            workspace_generation: 0,
            workspace_head,
            baseline_tree_hash: empty_tree_hash,
            observed_tree_hash: tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: admission_policy.shared,
            local_overlay: admission_policy.local,
        }),
    };
    drop(lease);

    if let Some(change_id) = initial_change_id {
        transaction.ref_mutations.push(RefMutation {
            name: default_ref,
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::change(change_id)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
    }

    let receipt = authority
        .commit_repository_transaction(transaction)
        .map_err(graph_error)?;
    let workspace = authority
        .workspace_snapshot_binding(&repository_id, &workspace_id)
        .map_err(graph_error)?
        .ok_or_else(|| {
            KinError::Graph(format!(
                "repository authority committed without workspace {workspace_id}"
            ))
        })?;
    Ok(RepositoryBootstrap {
        receipt,
        workspace,
        initial_change_id,
    })
}

fn graph_error(error: impl std::fmt::Display) -> KinError {
    KinError::Graph(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        compute_semantic_change_id, ChangeOrigin, Hash256, RefTarget, Timestamp, WorkspaceHead,
    };

    #[test]
    fn init_creates_unborn_repository_authority() {
        let directory = tempfile::tempdir().unwrap();
        let result = init(directory.path()).unwrap();

        assert!(result.layout.root().exists());
        assert!(result.layout.config_path().exists());
        assert!(result.layout.manifest_path().exists());
        assert!(result.layout.kindb_dir().exists());
        assert!(result.layout.stashes_dir().exists());
        assert!(result.layout.projections_dir().exists());
        assert!(result.layout.docs_dir().exists());
        assert!(result.layout.bench_dir().exists());
        assert!(result.layout.runs_dir().exists());
        assert!(result.layout.logs_dir().exists());
        assert!(result.layout.adapters_dir().exists());

        assert_eq!(result.default_ref, RefName::branch(b"main").unwrap());
        assert_eq!(result.authority.initial_change_id, None);
        assert_eq!(
            result.authority.workspace.workspace_head,
            WorkspaceHead::Symbolic {
                target: result.default_ref.clone()
            }
        );
        assert_eq!(result.authority.workspace.base_target, None);
        assert_eq!(result.authority.workspace.base_tree_hash, None);
        assert!(!result.authority.workspace.is_dirty());
        assert!(!result.layout.root().join("HEAD").exists());
    }

    #[test]
    fn init_persists_distinct_repository_and_workspace_identities() {
        let directory = tempfile::tempdir().unwrap();
        let result = init(directory.path()).unwrap();
        let loaded = KinManifest::load(&result.layout.manifest_path()).unwrap();

        assert_eq!(result.repository_id.as_str(), loaded.repo_id);
        assert_eq!(result.workspace_id.to_string(), loaded.workspace_id);
        assert_ne!(loaded.repo_id, loaded.workspace_id);
    }

    #[test]
    fn init_writes_valid_config() {
        let directory = tempfile::tempdir().unwrap();
        let result = init(directory.path()).unwrap();
        let loaded = KinConfig::load(&result.layout.config_path()).unwrap();
        assert_eq!(loaded.default_branch, "main");
    }

    #[test]
    fn init_rejects_already_initialized() {
        let directory = tempfile::tempdir().unwrap();
        init(directory.path()).unwrap();
        let error = init(directory.path()).unwrap_err();
        assert!(matches!(error, KinError::AlreadyInitialized(_)));
    }

    #[test]
    fn unborn_workspace_does_not_publish_a_fake_ref_target() {
        let directory = tempfile::tempdir().unwrap();
        let result = init(directory.path()).unwrap();
        assert!(!matches!(
            result.authority.workspace.base_target,
            Some(RefTarget::Change { .. })
        ));
    }

    #[test]
    fn admitted_root_initializes_ref_workspace_and_policy_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let repository_id = RepositoryId::new("born-repository").unwrap();
        let workspace_id = WorkspaceId::new();
        let default_ref = RefName::branch(b"main").unwrap();
        let shared_policy = SharedAdmissionPolicy::empty(0);
        let mut initial_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("importer"),
            message: "admit exact imported root".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: ChangeOrigin::Native,
            admission_policy_delta: Some(AdmissionPolicyDelta::initialize(shared_policy.clone())),
        };
        initial_change.id = compute_semantic_change_id(&initial_change).unwrap();

        let backend = Arc::new(LocalFileBackend::new(directory.path().join("kindb")));
        let authority = RepositoryAuthorityManager::open(repository_id.clone(), backend).unwrap();
        let bootstrap = initialize_repository_authority(
            &authority,
            repository_id.clone(),
            workspace_id,
            default_ref.clone(),
            shared_policy.clone(),
            Some(initial_change.clone()),
        )
        .unwrap();

        let expected_target = RefTarget::change(initial_change.id);
        assert_eq!(bootstrap.initial_change_id, Some(initial_change.id));
        assert_eq!(
            bootstrap.workspace.base_target,
            Some(expected_target.clone())
        );
        assert_eq!(
            bootstrap.workspace.base_tree_hash,
            Some(bootstrap.workspace.workspace_tree_hash)
        );
        assert_eq!(
            bootstrap.workspace.admission_policy.shared,
            shared_policy.stamp()
        );
        assert!(!bootstrap.workspace.is_dirty());

        let repository_ref = authority
            .get_repository_ref(&repository_id, &default_ref)
            .unwrap()
            .expect("born default ref is committed");
        assert_eq!(repository_ref.target, expected_target);
        let workspace = authority
            .get_workspace_state(&repository_id, &workspace_id)
            .unwrap()
            .expect("workspace state is committed");
        assert_eq!(workspace.base_target, Some(repository_ref.target));
        assert_eq!(workspace.tree_hash, bootstrap.workspace.workspace_tree_hash);
        assert_eq!(workspace.shared_admission_policy, shared_policy);
    }
}
