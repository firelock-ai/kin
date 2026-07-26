// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 native commit publication.
//!
//! Filesystem observation belongs to the serialized reconcile/admission
//! boundary. This module consumes only the admitted live graph, immutable blob
//! CAS, and one persisted repository-authority lease. History, exact tree,
//! workspace base, and the named ref advance in one storage compare-and-swap.

use std::collections::BTreeSet;
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AuthorId, ChangeOrigin,
    EffectiveAdmissionPolicyStamp, Hash256, ModelError, OperationId, RefExpectation, RefMutation,
    RefName, RefTarget, RefUpdatePolicy, RepositoryCommitReceipt, RepositoryId,
    RepositoryTransaction, SemanticChange, SemanticChangeId, SharedAdmissionPolicy, Timestamp,
    WorkspaceExpectation, WorkspaceHead, WorkspaceId, WorkspaceMutation,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::commit_deltas::compute_deltas_vs_repository_authority;
use crate::error::{DaemonError, Result};

/// Complete immutable plan for one native repository transaction.
///
/// `source_hashes` name bodies already present in the daemon's admitted blob
/// CAS. They are copied into repository-owned CAS immediately before the
/// authority compare-and-swap; raw checkout bytes are never consulted.
pub struct NativeCommitPlan {
    pub change: SemanticChange,
    pub transaction: RepositoryTransaction,
    pub branch: RefName,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
    previous_tree: kin_model::ResolvedTree,
    target_tree: kin_model::ResolvedTree,
    source_hashes: Vec<Hash256>,
}

#[derive(Debug)]
pub struct NativeCommitResult {
    pub change: SemanticChange,
    pub receipt: RepositoryCommitReceipt,
    pub branch: RefName,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
}

/// Result of durably admitting one exact working-tree transition.
///
/// This advances workspace authority only. It does not manufacture a semantic
/// history node or move a named ref: dirty Compose/config/binary/unsupported
/// artifacts remain dirty workspace state until an explicit Kin commit.
#[derive(Debug)]
pub struct WorkspaceAdmissionResult {
    pub receipt: RepositoryCommitReceipt,
    pub workspace_id: WorkspaceId,
    pub tree_hash: Hash256,
    pub file_count: usize,
}

/// Atomically publish one exact graph-owned workspace tree.
///
/// The caller has already performed the explicit filesystem-ingestion scan.
/// This boundary consumes only its admitted exact tree plus bodies in the
/// non-authoritative ingestion CAS, copies newly referenced bodies into
/// repository CAS, and compare-and-swaps the workspace. It never creates a
/// history node or advances a ref.
pub fn publish_workspace_tree(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    desired_tree: &kin_model::ResolvedTree,
    operation_id: OperationId,
    actor: AuthorId,
) -> Result<Option<WorkspaceAdmissionResult>> {
    let (repository_id, workspace_id) = repository_identity(layout)?;
    let authority = open_authority(layout, repository_id.clone())?;
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }
    if workspace.tree == *desired_tree {
        return Ok(None);
    }

    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, desired_tree)?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, _) = SharedAdmissionPolicy::derive_from_tree(
        Some(&workspace.shared_admission_policy),
        desired_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            let body = blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "read admitted workspace policy source {hash}: {error}"
                    ))
                })?;
            let length = u64::try_from(body.len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "admitted workspace policy source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
    )?;
    let tree_hash = compute_resolved_tree_hash(desired_tree)?;
    let new_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor,
        reason: "admit exact graph-owned workspace tree".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation,
            new_head: workspace.head,
            new_base_target: workspace.base_target,
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: tree_deltas.clone(),
            new_tree_hash: tree_hash,
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));
    drop(lease);

    for hash in source_hashes {
        let body = blobs.read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))?;
        authority.save_source_blob(hash, &body)?;
    }
    let receipt = authority.commit_repository_transaction(transaction)?;
    receipt.validate()?;
    Ok(Some(WorkspaceAdmissionResult {
        receipt,
        workspace_id,
        tree_hash,
        file_count: tree_deltas.len(),
    }))
}

/// Construct one exact native transaction without mutating repository
/// authority.
#[allow(clippy::too_many_arguments)]
pub fn plan_native_commit(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
) -> Result<NativeCommitPlan> {
    if message.trim().is_empty() {
        return Err(invalid("native commit message must not be empty"));
    }
    let (repository_id, workspace_id) = repository_identity(layout)?;
    let authority = open_authority(layout, repository_id.clone())?;
    let lease = authority.read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }

    let (branch, current_ref_target, parent) =
        resolve_symbolic_commit_base(metadata, &workspace.head, workspace.base_target.as_ref())?;
    let parent_policy = match parent {
        Some(parent) => Some(
            metadata
                .admission_policies
                .iter()
                .find(|candidate| candidate.change_id == parent)
                .and_then(|candidate| candidate.policy.clone())
                .ok_or_else(|| {
                    invalid(format!(
                        "native commit parent {parent} has no resolved shared admission policy"
                    ))
                })?,
        ),
        None => None,
    };

    let deltas = compute_deltas_vs_repository_authority(graph, lease.snapshot(), parent.as_ref())?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, admission_policy_delta) = SharedAdmissionPolicy::derive_from_tree(
        parent_policy.as_ref(),
        &deltas.expected_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            let body = blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "read graph-owned admission source {hash}: {error}"
                    ))
                })?;
            let length = u64::try_from(body.len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "graph-owned admission source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
    )?;

    let entity_count = deltas.entity_deltas.len();
    let relation_count = deltas.relation_deltas.len();
    let file_count = deltas.tree_deltas.len();
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: parent.into_iter().collect(),
        timestamp,
        author: author.clone(),
        message,
        entity_deltas: deltas.entity_deltas,
        relation_deltas: deltas.relation_deltas,
        tree_deltas: deltas.tree_deltas,
        admission_policy_delta,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
    };
    change.id = compute_semantic_change_id(&change)?;

    let tree_hash = compute_resolved_tree_hash(&deltas.expected_tree)?;
    let workspace_tree_deltas =
        kin_core::exact_tree_correction(&workspace.tree, &deltas.expected_tree)?;
    let workspace_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let new_target = RefTarget::change(change.id);
    let workspace_mutation = WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: workspace.generation,
            head: workspace.head.clone(),
            base_target: workspace.base_target.clone(),
            base_tree_hash: workspace.base_tree_hash,
            tree_hash: workspace.tree_hash,
            admission_policy: workspace.admission_policy,
        },
        new_generation: workspace_generation,
        new_head: workspace.head.clone(),
        new_base_target: Some(new_target.clone()),
        new_base_tree_hash: Some(tree_hash),
        tree_deltas: workspace_tree_deltas,
        new_tree_hash: tree_hash,
        new_shared_admission_policy: shared_policy.clone(),
        new_admission_policy: EffectiveAdmissionPolicyStamp {
            shared: shared_policy.stamp(),
            local: workspace.admission_policy.local,
        },
    };
    let ref_mutation = RefMutation {
        name: branch.clone(),
        expected: current_ref_target
            .map(|target| RefExpectation::MustEqual { target })
            .unwrap_or(RefExpectation::MustNotExist),
        new_target: Some(new_target),
        policy: RefUpdatePolicy::FastForwardOnly,
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor: author,
        reason: "publish admitted native semantic change".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change.clone()],
        aliases: Vec::new(),
        ref_mutations: vec![ref_mutation],
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation),
        local_overlay_delta: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &change.tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));

    Ok(NativeCommitPlan {
        change,
        transaction,
        branch,
        entity_count,
        relation_count,
        file_count,
        previous_tree: workspace.tree,
        target_tree: deltas.expected_tree,
        source_hashes: source_hashes.into_iter().collect(),
    })
}

/// Persist immutable bodies, then atomically publish the complete repository
/// transaction.
pub fn commit_native_plan(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    let (repository_id, _) = repository_identity(layout)?;
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = open_authority(layout, repository_id)?;
    for hash in &plan.source_hashes {
        let body = blobs.read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))?;
        authority.save_source_blob(*hash, &body)?;
    }
    let receipt = authority.commit_repository_transaction(plan.transaction)?;
    receipt.validate()?;
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        branch: plan.branch,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

/// Atomically project and publish one native repository transaction.
///
/// Source bodies are copied into repository CAS first, then the exact prior
/// and target trees are loaded back through that immutable authority. The
/// projection recovery journal linearizes the working-tree transition with
/// the repository transaction: a pre-commit failure restores the prior tree,
/// while recovery after a durable authority commit finalizes the target tree.
/// No graph-commit-then-best-effort-projection state is observable.
pub fn commit_native_plan_with_projection(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    let (repository_id, _) = repository_identity(layout)?;
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = open_authority(layout, repository_id)?;
    for hash in &plan.source_hashes {
        let body = blobs.read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))?;
        authority.save_source_blob(*hash, &body)?;
    }

    let previous_entries = load_projection_entries(&authority, &plan.previous_tree)?;
    let target_entries = load_projection_entries(&authority, &plan.target_tree)?;
    let (projected, receipt) = kin_core::reconcile_source_tree_and_commit_repository_transaction(
        layout.working_dir(),
        &plan.previous_tree,
        &plan.target_tree,
        previous_entries
            .iter()
            .map(|(path, entry, body)| (path, *entry, body.as_slice())),
        target_entries
            .iter()
            .map(|(path, entry, body)| (path, *entry, body.as_slice())),
        &authority,
        plan.transaction,
    )?;
    if projected != plan.target_tree.len() {
        return Err(invalid(format!(
            "exact projection installed {projected} artifacts but target authority contains {}",
            plan.target_tree.len()
        )));
    }
    receipt.validate()?;
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        branch: plan.branch,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

fn load_projection_entries(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    tree: &kin_model::ResolvedTree,
) -> Result<Vec<(kin_model::RepoPath, kin_model::TreeEntry, Vec<u8>)>> {
    let mut entries = Vec::with_capacity(tree.len());
    for artifact in tree.artifacts_by_path() {
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            invalid(format!(
                "exact native projection cannot materialize gitlink {}",
                artifact.path
            ))
        })?;
        let body = authority.load_source_blob(hash)?.ok_or_else(|| {
            invalid(format!(
                "repository source CAS is missing {} for {}",
                hash, artifact.path
            ))
        })?;
        entries.push((artifact.path.clone(), artifact.entry, body));
    }
    Ok(entries)
}

fn repository_identity(layout: &kin_core::KinLayout) -> Result<(RepositoryId, WorkspaceId)> {
    let manifest = kin_core::manifest::KinManifest::load(&layout.manifest_path())?;
    let repository_id = RepositoryId::new(manifest.repo_id)
        .map_err(|error| invalid(format!("invalid repository identity: {error}")))?;
    let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id)
        .map_err(|error| invalid(format!("invalid workspace identity: {error}")))?;
    Ok((repository_id, WorkspaceId::from_uuid(workspace_uuid)))
}

fn open_authority(
    layout: &kin_core::KinLayout,
    repository_id: RepositoryId,
) -> Result<RepositoryAuthorityManager<LocalFileBackend>> {
    RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .map_err(DaemonError::Graph)
}

fn resolve_symbolic_commit_base(
    metadata: &kin_db::PersistedRepositoryAuthority,
    head: &WorkspaceHead,
    workspace_base: Option<&RefTarget>,
) -> Result<(RefName, Option<RefTarget>, Option<SemanticChangeId>)> {
    let WorkspaceHead::Symbolic { target: branch } = head else {
        return Err(invalid(
            "native repository commit requires a symbolic workspace HEAD",
        ));
    };
    let current = metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == *branch)
        .map(|repository_ref| repository_ref.target.clone());
    if current.as_ref() != workspace_base {
        return Err(invalid(format!(
            "workspace base does not match current symbolic ref {branch}; refresh or rebase before commit"
        )));
    }
    let parent = match current.as_ref() {
        None => None,
        Some(RefTarget::Change { change_id }) => Some(*change_id),
        Some(RefTarget::ExternalObject { object }) => Some(
            metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == object.oid)
                .map(|alias| alias.change_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "workspace base external commit {} has no semantic alias",
                        object.oid
                    ))
                })?,
        ),
        Some(RefTarget::Symbolic { target }) => {
            return Err(invalid(format!(
                "native commit does not yet mutate symbolic ref chain {branch} -> {target}"
            )));
        }
    };
    Ok((branch.clone(), current, parent))
}

fn invalid(message: impl Into<String>) -> DaemonError {
    ModelError::InvalidOperation(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, EntityStore, LocatedEntry, RepoPath, RepositoryAuthorityStore,
        ResolvedArtifact, ResolvedTree, TransactionDelta, TreeDelta, TreeEntry,
    };

    fn add_artifact(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &[u8],
        bytes: &[u8],
        entry: impl FnOnce(Hash256) -> TreeEntry,
    ) -> ResolvedArtifact {
        let digest = blobs.write(bytes).unwrap();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry(Hash256::from_bytes(digest.0)),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
                }],
                admission_policy_delta: None,
            })
            .unwrap();
        artifact
    }

    fn fixed_timestamp() -> Timestamp {
        Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn reopen(init: &kin_core::InitResult) -> RepositoryAuthorityManager<LocalFileBackend> {
        RepositoryAuthorityManager::open(
            init.repository_id.clone(),
            Arc::new(LocalFileBackend::new(init.layout.kindb_dir())),
        )
        .unwrap()
    }

    #[test]
    fn workspace_admission_persists_dirty_exact_tree_without_history_or_ref_move() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );
        let desired = ResolvedTree::from_artifacts([compose, opaque, symlink]).unwrap();

        let initial_authority = reopen(&init);
        let initial_lease = initial_authority.read_authority();
        let initial_workspace = initial_lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        let initial_refs = initial_lease.metadata().ref_state.clone();
        drop(initial_lease);

        let result = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .expect("dirty exact tree must advance workspace authority");
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(result.workspace_id, init.workspace_id);
        assert_eq!(result.file_count, 3);
        assert_eq!(
            result.tree_hash,
            compute_resolved_tree_hash(&desired).unwrap()
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        assert_eq!(workspace.head, initial_workspace.head);
        assert_eq!(workspace.base_target, initial_workspace.base_target);
        assert_eq!(workspace.base_tree_hash, initial_workspace.base_tree_hash);
        assert!(workspace.is_dirty());
        assert_eq!(lease.metadata().ref_state, initial_refs);
        assert!(lease.snapshot().changes.is_empty());
        for artifact in desired.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert_eq!(
                    authority.load_source_blob(hash).unwrap().as_deref(),
                    Some(blobs.read(&hash).unwrap().as_slice())
                );
            }
        }
        drop(lease);

        assert!(publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .is_none());
        assert_eq!(reopen(&init).read_authority().roots().generation, 2);
    }

    #[test]
    fn workspace_admission_cannot_invent_unverified_gitlink_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("vendor/semantic-engine").unwrap(),
            TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x73; 20])),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected external-authority rejection: {error}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn workspace_admission_missing_body_cannot_advance_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing admitted body must surface the typed blob absence, got {error:?}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn native_commit_atomically_projects_exact_non_code_tree_and_ref() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let dockerfile = add_artifact(&graph, &blobs, b"Dockerfile", b"FROM scratch\n", |hash| {
            TreeEntry::blob(hash, true)
        });
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "commit exact repository artifacts".to_string(),
        )
        .unwrap();
        assert_eq!(plan.file_count, 4);
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  app:\n    image: kin:test\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("Dockerfile")).unwrap(),
            b"FROM scratch\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("assets/model.bin")).unwrap(),
            [0, 0xff, 0x41, 0x00]
        );
        assert_eq!(
            std::fs::read_link(root.path().join("current-compose")).unwrap(),
            std::path::PathBuf::from("compose.yaml")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                std::fs::metadata(root.path().join("Dockerfile"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        let expected =
            ResolvedTree::from_artifacts([compose, dockerfile, opaque, symlink]).unwrap();
        assert_eq!(workspace.tree, expected);
        assert_eq!(
            workspace.base_target,
            Some(RefTarget::change(result.change.id))
        );
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, &result.branch)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id)
        );
        for artifact in expected.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert!(authority.load_source_blob(hash).unwrap().is_some());
            }
        }
    }

    #[test]
    fn stale_plan_cannot_split_change_workspace_and_ref_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b"compose.yaml", b"services: {}\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let winner = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("winner"),
            "winner".to_string(),
        )
        .unwrap();
        let winner_id = winner.change.id;
        let stale = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("stale"),
            "stale".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, winner).unwrap();
        let error = commit_native_plan(&init.layout, &blobs, stale).unwrap_err();
        assert!(error.to_string().contains("authority moved"));

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        let default_ref = lease.metadata().ref_state.default_ref.as_ref().unwrap();
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, default_ref)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(winner_id)
        );
        assert_eq!(lease.snapshot().changes.len(), 1);
    }

    #[test]
    fn ignored_new_artifact_is_rejected_without_partial_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b".gitignore", b"secret.txt\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        add_artifact(&graph, &blobs, b"secret.txt", b"not admitted\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "must fail admission".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(error
            .to_string()
            .contains("excluded by the exact graph-owned admission policy"));

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease.snapshot().changes.is_empty());
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert!(workspace.tree.is_empty());
        assert!(lease.metadata().ref_state.refs.is_empty());
    }

    #[test]
    fn missing_graph_blob_fails_before_repository_authority_moves() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path, artifact.entry),
                }],
                admission_policy_delta: None,
            })
            .unwrap();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "missing body".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing graph body must surface the typed blob absence, got {error:?}"
        );
        assert_eq!(reopen(&init).read_authority().roots().generation, 1);
    }
}
