// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
#[cfg(any(unix, windows))]
use std::collections::HashSet;
#[cfg(any(unix, windows))]
use std::ffi::OsString;
#[cfg(any(unix, windows))]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Arc;

use kin_db::{
    LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager,
    RepositoryAuthorityState,
};
use kin_model::{
    compute_resolved_tree_hash, GraphStore, Hash256, OperationId, RepoPath,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId, RepositoryTransaction,
    ResolvedTree, RootBundle, SemanticChangeId, TreeEntry, WorkspaceExpectation, WorkspaceId,
};

use crate::{KinError, Result};

#[cfg(any(unix, windows))]
use fs2::FileExt as _;

#[cfg(any(unix, windows))]
const RECONCILIATION_CONTROL_DIRECTORY: &str = "reconciliation";
#[cfg(any(unix, windows))]
const RECONCILIATION_AUTHORITY_FILE: &str = "authority.key";
#[cfg(any(unix, windows))]
const RECONCILIATION_MANIFEST_FILE: &str = "manifest.json";
#[cfg(any(unix, windows))]
const RECONCILIATION_PROJECTION_LOCK_FILE: &str = "projection.lock";
#[cfg(any(unix, windows))]
const SESSION_PROJECTION_CONTROL_DIRECTORY: &str = ".kin-session";
#[cfg(any(unix, windows))]
const SESSION_PROJECTION_BASE_FILE: &str = "base.json";
#[cfg(any(unix, windows))]
const SESSION_RUNS_DIRECTORY: &str = "runs";
#[cfg(any(unix, windows))]
const SESSION_STAGING_DIRECTORY_PREFIX: &str = ".session-stage-";
#[cfg(unix)]
const EXACT_EJECT_JOURNAL_FILE: &str = "exact-eject-journal.json";
#[cfg(unix)]
const EXACT_EJECT_JOURNAL_SCHEMA: u32 = 1;
#[cfg(unix)]
const MAX_EXACT_EJECT_JOURNAL_BYTES: u64 = 256 * 1024;

/// How long a caller waits for a live exact-source projection to finish before
/// failing loud. Bounded so an undiscovered lock-order cycle degrades to a
/// slow, named failure instead of a hang.
const PROJECTION_LOCK_WAIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(any(unix, windows))]
const RECONCILIATION_MANIFEST_SCHEMA: u32 = 3;
#[cfg(any(unix, windows))]
const RECONCILIATION_ACTION_FILE_PREFIX: &str = "action-";
#[cfg(any(unix, windows))]
const MAX_RECONCILIATION_ACTIONS: usize = 100_000;
#[cfg(any(unix, windows))]
const MAX_RECONCILIATION_ACTION_RECORD_BYTES: u64 = 256 * 1024;
#[cfg(any(unix, windows))]
const MAX_RECONCILIATION_ACTION_LOG_BYTES: u64 = 64 * 1024 * 1024;
const CHECKOUT_PROJECTION_RECEIPT_SCHEMA: u32 = 1;
#[cfg(any(unix, windows))]
const CHECKOUT_PROJECTION_RECEIPT_PREFIX: &str = "checkout-receipt-";
#[cfg(any(unix, windows))]
const MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES: u64 = 256 * 1024;

/// Resolve the exact repository tree at one semantic change.
pub fn resolve_change_tree<G: GraphStore>(
    graph: &G,
    change_id: &SemanticChangeId,
) -> Result<ResolvedTree> {
    graph
        .resolve_tree_at(change_id)
        .map_err(|error| KinError::Graph(error.to_string()))
}

/// Local, authenticated identity of one projection-only checkout repair.
///
/// This receipt is deliberately not repository-replicated truth. It records
/// that the derived filesystem projection was restored while the named
/// repository roots and workspace generation/tree were frozen.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutProjectionReceipt {
    pub schema: u32,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub operation_id: OperationId,
    pub authority_roots: RootBundle,
    pub workspace_generation: u64,
    pub workspace_tree_hash: Hash256,
    pub selected: RepoPath,
    pub projection_digest: Hash256,
    pub completed: bool,
}

impl CheckoutProjectionReceipt {
    /// Construct the caller-stable identity before any namespace mutation.
    pub fn new(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        operation_id: OperationId,
        authority_roots: RootBundle,
        workspace_generation: u64,
        workspace_tree_hash: Hash256,
        selected: RepoPath,
    ) -> Result<Self> {
        let projection_digest = checkout_projection_digest(
            &repository_id,
            workspace_id,
            operation_id,
            &authority_roots,
            workspace_generation,
            workspace_tree_hash,
            &selected,
        )?;
        Ok(Self {
            schema: CHECKOUT_PROJECTION_RECEIPT_SCHEMA,
            repository_id,
            workspace_id,
            operation_id,
            authority_roots,
            workspace_generation,
            workspace_tree_hash,
            selected,
            projection_digest,
            completed: true,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.schema != CHECKOUT_PROJECTION_RECEIPT_SCHEMA || !self.completed {
            return Err(KinError::Other(
                "checkout projection receipt is incomplete or has an unsupported schema"
                    .to_string(),
            ));
        }
        let expected = checkout_projection_digest(
            &self.repository_id,
            self.workspace_id,
            self.operation_id,
            &self.authority_roots,
            self.workspace_generation,
            self.workspace_tree_hash,
            &self.selected,
        )?;
        if self.projection_digest != expected {
            return Err(KinError::Other(
                "checkout projection receipt digest does not match its bound request".to_string(),
            ));
        }
        Ok(())
    }
}

fn checkout_projection_digest(
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
    operation_id: OperationId,
    authority_roots: &RootBundle,
    workspace_generation: u64,
    workspace_tree_hash: Hash256,
    selected: &RepoPath,
) -> Result<Hash256> {
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        schema: &'static str,
        repository_id: &'a RepositoryId,
        workspace_id: WorkspaceId,
        operation_id: OperationId,
        authority_roots: &'a RootBundle,
        workspace_generation: u64,
        workspace_tree_hash: Hash256,
        selected: &'a RepoPath,
    }
    let encoded = serde_json::to_vec(&Identity {
        schema: "kin.checkout-projection-receipt.v1",
        repository_id,
        workspace_id,
        operation_id,
        authority_roots,
        workspace_generation,
        workspace_tree_hash,
        selected,
    })
    .map_err(|error| KinError::Other(format!("encode checkout projection identity: {error}")))?;
    Ok(Hash256::from_bytes(kin_blobs::digest_bytes(&encoded)))
}

fn validate_checkout_projection_workspace(
    authority: &RepositoryAuthorityState,
    receipt: &CheckoutProjectionReceipt,
) -> Result<()> {
    receipt.validate()?;
    if authority.roots() != &receipt.authority_roots
        || authority.metadata().repository_id != receipt.repository_id
    {
        return Err(KinError::Other(format!(
            "checkout projection authority moved from repository {} generation {}",
            receipt.repository_id, receipt.authority_roots.generation
        )));
    }
    let workspace = authority
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == receipt.workspace_id)
        .ok_or_else(|| {
            KinError::Other(format!(
                "checkout projection workspace {} is absent",
                receipt.workspace_id
            ))
        })?;
    if workspace.generation != receipt.workspace_generation
        || workspace.tree_hash != receipt.workspace_tree_hash
    {
        return Err(KinError::Other(format!(
            "checkout projection workspace {} moved from generation/tree {}:{}",
            receipt.workspace_id, receipt.workspace_generation, receipt.workspace_tree_hash
        )));
    }
    Ok(())
}

fn repository_authority_state_contains_commit(
    authority: &RepositoryAuthorityState,
    marker: &ReconciliationAuthorityCommit,
) -> Result<bool> {
    if authority.metadata().repository_id != marker.repository_id {
        return Err(KinError::Other(format!(
            "projection recovery marker names repository {}, but frozen authority names {}",
            marker.repository_id,
            authority.metadata().repository_id
        )));
    }
    let Some(operation) = authority
        .metadata()
        .operation_log
        .iter()
        .find(|operation| operation.operation_id == marker.operation_id)
    else {
        return Ok(false);
    };
    if operation.transaction_hash != marker.transaction_hash {
        return Err(KinError::Other(format!(
            "repository operation {} exists with a different transaction identity during \
             exact-source projection recovery",
            marker.operation_id
        )));
    }
    Ok(true)
}

/// Preserve control-plane and generated dependency/build directories during
/// exact tree cleanup. This policy is shared by full projection and workspace
/// transitions so neither path treats generated state as graph-owned source.
pub fn should_preserve_checkout_path(relative: &Path) -> bool {
    const PRESERVED_COMPONENTS: &[&str] = &[
        ".kin",
        ".kin-session",
        ".git",
        "node_modules",
        "target",
        "__pycache__",
        ".next",
        "dist",
        "build",
        "vendor",
    ];

    relative.components().any(|component| {
        if let std::path::Component::Normal(name) = component {
            name.to_str().is_some_and(|name| {
                PRESERVED_COMPONENTS
                    .iter()
                    .any(|preserved| name.eq_ignore_ascii_case(preserved))
            })
        } else {
            false
        }
    })
}

/// Materialize one graph-owned exact source entry beneath `root`.
///
/// Paths and link targets are validated before mutation. Supported-platform
/// writes are anchored to directory capabilities and use no-follow traversal
/// plus atomic replacement, so neither a pre-existing link nor a concurrent
/// rename can redirect bytes outside the projection root.
///
/// This is a physical export/recovery primitive, not a repository-authority
/// workspace transition. V2 workspace switching is served through VFS.
pub fn materialize_source_entry(
    root: &Path,
    file_id: &RepoPath,
    kind: TreeEntry,
    content: &[u8],
) -> Result<()> {
    materialize_source_tree(root, [(file_id, kind, content)]).map(|_| ())
}

/// Materialize a complete graph-owned source tree under one retained root
/// capability.
///
/// Validation finishes before the root is opened, and every preparation and
/// replacement operation after that is relative to the same directory handle.
/// A concurrent rename or symlink swap therefore cannot redirect a later
/// entry to a different ambient path.
pub fn materialize_source_tree<'a>(
    root: &Path,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<usize> {
    let entries = validated_source_entries(entries)?;
    project_validated_source_tree(root, &entries, None, || {})
}

/// Materialize one exact repository tree as a disposable session projection.
///
/// Session metadata is installed under `.kin-session/base.json`, while the
/// projection recovery journal lives under `.kin-session/reconciliation`.
/// Keeping this control plane separate from `.kin/` ensures repository
/// discovery from inside the session continues to bind the owning repository
/// rather than mistaking the derived workspace for an independent authority.
#[cfg(test)]
fn materialize_session_source_tree<'a>(
    root: &Path,
    base_metadata: &[u8],
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<usize> {
    let entries = validated_session_source_entries(base_metadata, entries)?;
    project_validated_session_source_tree(root, &entries, base_metadata)
}

/// Replace a working tree from exact graph-owned source under one retained
/// root capability, removing non-tree files except paths selected by
/// `should_preserve`.
///
/// Cleanup discovery is part of the read-only preflight. Cleanup, transition
/// preparation, materialization, and empty-directory removal then all use the
/// same retained capability rather than ambient pathnames.
pub fn replace_source_tree<'a>(
    root: &Path,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    should_preserve: impl Fn(&Path) -> bool,
) -> Result<usize> {
    let entries = validated_source_entries(entries)?;
    project_validated_source_tree(root, &entries, Some(&should_preserve), || {})
}

/// Reconcile one exact graph-owned tree to another without deleting unrelated
/// working-copy files.
///
/// Only paths tracked by `previous_entries` and absent from `entries` are
/// eligible for deletion. A prior tracked path that would be replaced or
/// removed must still match its exact prior-workspace kind and content; local
/// edits fail the whole read-only preflight. New target paths fail closed when
/// an unrelated working-copy object occupies the destination or blocks an
/// ancestor.
pub fn reconcile_source_tree<'a, 'b>(
    root: &Path,
    previous_entries: impl IntoIterator<Item = (&'b RepoPath, TreeEntry, &'b [u8])>,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    should_preserve: impl Fn(&Path) -> bool,
) -> Result<usize> {
    reconcile_source_tree_with_pre_mutation_hook(
        root,
        previous_entries,
        entries,
        should_preserve,
        || {},
    )
}

#[doc(hidden)]
pub fn reconcile_source_tree_with_pre_mutation_hook<'a, 'b>(
    root: &Path,
    previous_entries: impl IntoIterator<Item = (&'b RepoPath, TreeEntry, &'b [u8])>,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    should_preserve: impl Fn(&Path) -> bool,
    after_read_only_preflight: impl FnOnce(),
) -> Result<usize> {
    reconcile_source_tree_with_mutation_hooks(
        root,
        previous_entries,
        entries,
        should_preserve,
        after_read_only_preflight,
        || {},
    )
}

/// Test seam for a namespace replacement that lands after the second
/// byte/kind/identity validation but before any tracked object is displaced.
#[doc(hidden)]
pub fn reconcile_source_tree_with_mutation_hooks<'a, 'b>(
    root: &Path,
    previous_entries: impl IntoIterator<Item = (&'b RepoPath, TreeEntry, &'b [u8])>,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    should_preserve: impl Fn(&Path) -> bool,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
) -> Result<usize> {
    let entries = validated_source_entries(entries)?;
    let previous_entries = validated_source_entries(previous_entries)?;
    project_reconciled_source_tree(
        root,
        &previous_entries,
        &entries,
        &should_preserve,
        after_read_only_preflight,
        after_identity_revalidation,
    )
}

/// Reconcile a graph-derived working tree and linearize its repository-v6
/// workspace transaction at the projection transaction's commit boundary.
///
/// The projection WAL records the exact repository operation before any
/// namespace mutation. Recovery rolls the filesystem back when that operation
/// is absent and finalizes the target projection when the exact operation was
/// durably committed, closing the process-crash window between the two stores.
pub fn reconcile_source_tree_and_commit_repository_transaction<'a, 'b>(
    root: &Path,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    previous_entries: impl IntoIterator<Item = (&'b RepoPath, TreeEntry, &'b [u8])>,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(usize, RepositoryCommitReceipt)> {
    let entries = validated_source_entries(entries)?;
    let previous_entries = validated_source_entries(previous_entries)?;
    validate_repository_projection_transaction(
        previous_tree,
        target_tree,
        &previous_entries,
        &entries,
        &transaction,
        GraphOnlyTransitionPolicy::RequireUnchanged,
    )?;
    let materialized_count = entries.len();
    let marker = ReconciliationAuthorityCommit {
        repository_id: transaction.repository_id.clone(),
        operation_id: transaction.operation_id,
        transaction_hash: transaction
            .transaction_hash()
            .map_err(|error| KinError::Other(error.to_string()))?,
    };
    project_reconciled_source_tree_and_commit(
        root,
        &previous_entries,
        &entries,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingRepositoryFrozen(authority),
            ..ReconciledProjectionOptions::default()
        },
        || {},
        || {},
        || {},
        Some(marker),
        None,
        || commit_repository_transaction_exact(authority, transaction),
    )
    .map(|(_, receipt)| (materialized_count, receipt))
}

/// Transition one complete repository-v6 workspace tree, including exact
/// graph-only metadata, and publish its authority transaction at the
/// projection WAL's commit boundary.
///
/// Only host-materializable blobs and symbolic links receive source bodies or
/// filesystem writes. Gitlinks remain typed repository entries: an absent
/// Gitlink stays absent, while an existing no-follow real directory is
/// identity-bound and retained without inspecting independently owned
/// descendants. Host-unrepresentable paths likewise remain in
/// [`ResolvedTree`] without acquiring lossy local aliases.
///
/// Unlike ordinary source reconciliation, this is the dedicated graph-native
/// workspace transition allowed to add, remove, or retarget graph-only
/// entries. It requires an already initialized projection control plane and
/// retains the root, projection lock, repository roots, and recovery journal
/// through authority publication.
///
/// This API is deliberately ref-agnostic. Branch switch, detached checkout,
/// ref checkout, and future restore operations should all construct their
/// exact repository-v6 [`RepositoryTransaction`] and delegate the shared
/// filesystem/authority transition here.
pub fn transition_repository_workspace_tree_and_commit_repository_transaction(
    root: &Path,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(
    usize,
    RepositoryCommitReceipt,
    LocalRepositoryAuthorityFreeze,
)> {
    transition_repository_workspace_tree_and_commit_with_hooks(
        root,
        previous_tree,
        target_tree,
        authority,
        transaction,
        || {},
        || {},
        || {},
        None,
        commit_repository_transaction_exact_and_freeze,
    )
    .map(|(count, (receipt, freeze))| (count, receipt, freeze))
}

/// Verify that the complete current repository workspace still matches its
/// exact derived projection without publishing a repository transaction.
///
/// This is the no-op counterpart to a workspace transition. It is used when a
/// command such as switching to the already-active branch has no authority
/// delta to commit but still must not report success over dirty tracked bytes,
/// changed modes or symlink targets, or an invalid graph-only Gitlink
/// representation. The projection lock is acquired before the repository
/// freeze, preserving the global lock order, and the returned freeze proves
/// that the verified tree belonged to the retained repository authority.
pub fn verify_repository_workspace_projection(
    root: &Path,
    tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
) -> Result<(usize, LocalRepositoryAuthorityFreeze)> {
    #[cfg(any(unix, windows))]
    {
        let projection =
            ExactProjectionFreeze::acquire_existing_for_repository_transition(root, authority)?;
        let expected_roots = authority.read_authority().roots().clone();
        let owned = load_repository_projection_entries(authority, tree, "current workspace")?;
        let entries = validated_source_entries(
            owned
                .iter()
                .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
        )?;
        validate_repository_projection_entries_match_tree("current workspace", tree, &entries)?;
        validate_projection_proof_paths(tree.artifacts_by_path().map(|artifact| &artifact.path))?;
        let authority_freeze = authority
            .freeze_current_authority(&expected_roots)
            .map_err(|error| {
                classify_repository_authority_freeze_error(
                    "freeze verified repository workspace authority",
                    error,
                )
            })?;

        let entry_refs = entries.iter().collect::<Vec<_>>();
        let materialized_identities = projection
            .projection
            .validate_frozen_entries_unchanged(&entry_refs)?;
        let mut graph_only_proofs = Vec::new();
        for artifact in tree.artifacts_by_path() {
            let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
            if disposition != SourceProjectionDisposition::Materialized {
                graph_only_proofs.push((
                    artifact.path.clone(),
                    disposition,
                    projection
                        .projection
                        .verify_frozen_graph_only(&artifact.path, disposition)?,
                ));
            }
        }
        projection
            .projection
            .revalidate_frozen_entries_unchanged(&entry_refs, &materialized_identities)?;
        for (path, disposition, proof) in &graph_only_proofs {
            projection
                .projection
                .revalidate_frozen_graph_only(path, *disposition, proof)?;
        }
        projection.revalidate_namespace()?;
        Ok((entries.len(), authority_freeze))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, tree, authority);
        Err(unsupported_safe_projection_error())
    }
}

/// One bounded read-only observation of the derived projection against the
/// exact workspace tree graph authority owns.
///
/// `compared_entries` counts the materializable tracked members actually read
/// back from the working copy, so a caller can report coverage instead of
/// implying that an empty `drift` list proves every tracked member was
/// comparable on this host.
/// `drifted_paths` names the same divergences as `drift`, positionally, as the
/// byte-exact repository paths that produced them. A caller that wants to act
/// on a divergence needs the path itself: parsing it back out of a human
/// message would make the repair depend on message wording, and a repair that
/// silently matched nothing would look exactly like a clean projection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceProjectionDrift {
    pub compared_entries: usize,
    pub drift: Vec<String>,
    pub drifted_paths: Vec<RepoPath>,
}

impl WorkspaceProjectionDrift {
    pub fn is_clean(&self) -> bool {
        self.drift.is_empty()
    }

    pub fn first(&self) -> Option<&String> {
        self.drift.first()
    }

    pub fn len(&self) -> usize {
        self.drift.len()
    }

    pub fn is_empty(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Report every tracked path whose working copy no longer matches the exact
/// workspace tree that graph authority owns.
///
/// This is the read-only half of a workspace transition. It compares each
/// tracked member of `tree` against the working copy using content loaded from
/// repository authority, mutates neither the filesystem nor authority, and
/// admits nothing. Working-copy paths the tree does not track are never read:
/// untracked host content is not graph-owned, so it cannot drift and must not
/// gate a transition. The returned messages describe the diverged tracked
/// paths in repository order and are empty when the derived view still matches
/// graph authority.
pub fn report_repository_workspace_projection_drift(
    root: &Path,
    tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
) -> Result<WorkspaceProjectionDrift> {
    #[cfg(any(unix, windows))]
    {
        let projection =
            ExactProjectionFreeze::acquire_existing_for_repository_transition(root, authority)?;
        let owned = load_repository_projection_entries(authority, tree, "current workspace")?;
        let entries = validated_source_entries(
            owned
                .iter()
                .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
        )?;
        validate_repository_projection_entries_match_tree("current workspace", tree, &entries)?;
        validate_projection_proof_paths(tree.artifacts_by_path().map(|artifact| &artifact.path))?;
        let mut drift = Vec::new();
        let mut drifted_paths = Vec::new();
        for entry in &entries {
            match projection.projection.validate_frozen_entry_unchanged(entry) {
                Ok(_) => {}
                Err(KinError::ProjectionConflict(detail)) => {
                    // The message alone, exactly as before. This collector is
                    // why the kind rides INSIDE the variant rather than in a new
                    // one: a second variant would have fallen through to the
                    // `Err(error)` arm below and turned every tracked drift into
                    // a hard failure instead of a collected one.
                    drift.push(detail.message);
                    drifted_paths.push(entry.file_id.clone());
                }
                Err(error) => return Err(error),
            }
        }
        Ok(WorkspaceProjectionDrift {
            compared_entries: entries.len(),
            drift,
            drifted_paths,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, tree, authority);
        Err(unsupported_safe_projection_error())
    }
}

/// Restore one exact repository path or component-aware subtree while
/// publishing only its repository-v6 workspace mutation.
///
/// This is deliberately narrower than a branch transition. Filesystem drift
/// at selected materialized members is overwritten transactionally, while
/// unselected paths are neither validated nor mutated. The complete workspace
/// tree still participates in the repository compare-and-swap, so selected
/// graph-only members (Gitlinks and host-unrepresentable paths) remain exact
/// authority even when this host cannot materialize them.
pub fn checkout_repository_workspace_subtree_and_commit_repository_transaction(
    root: &Path,
    selected: &RepoPath,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(
    usize,
    RepositoryCommitReceipt,
    LocalRepositoryAuthorityFreeze,
)> {
    checkout_repository_workspace_subtree_and_commit_with_hooks(
        root,
        selected,
        previous_tree,
        target_tree,
        authority,
        transaction,
        || {},
        || {},
        || {},
    )
}

/// Test seam for exact selected-path namespace and authority races.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn checkout_repository_workspace_subtree_and_commit_with_hooks(
    root: &Path,
    selected: &RepoPath,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    after_projection_mutation: impl FnOnce(),
) -> Result<(
    usize,
    RepositoryCommitReceipt,
    LocalRepositoryAuthorityFreeze,
)> {
    validate_checkout_repository_transaction(selected, previous_tree, target_tree, &transaction)?;
    transition_repository_workspace_tree_and_commit_with_hooks(
        root,
        previous_tree,
        target_tree,
        authority,
        transaction,
        after_read_only_preflight,
        after_identity_revalidation,
        after_projection_mutation,
        Some(selected),
        commit_repository_transaction_exact_and_freeze,
    )
    .map(|(count, (receipt, freeze))| (count, receipt, freeze))
}

/// Repair a selected derived projection when repository workspace authority
/// already names the exact desired tree.
///
/// The repository authority is frozen only after the retained projection lock
/// is held. A local authenticated receipt, not a fake repository mutation,
/// becomes the WAL commit marker. This keeps graph truth unchanged while
/// making crash recovery and caller-stable retries explicit.
pub fn repair_repository_workspace_subtree_projection(
    root: &Path,
    tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    receipt: CheckoutProjectionReceipt,
) -> Result<(
    usize,
    CheckoutProjectionReceipt,
    LocalRepositoryAuthorityFreeze,
)> {
    repair_repository_workspace_subtree_projection_with_hooks(
        root,
        tree,
        authority,
        receipt,
        || {},
        || {},
        || {},
    )
}

/// Test seam for projection-only checkout races and rollback.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn repair_repository_workspace_subtree_projection_with_hooks(
    root: &Path,
    tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    receipt: CheckoutProjectionReceipt,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    after_projection_mutation: impl FnOnce(),
) -> Result<(
    usize,
    CheckoutProjectionReceipt,
    LocalRepositoryAuthorityFreeze,
)> {
    receipt.validate()?;
    let tree_hash =
        compute_resolved_tree_hash(tree).map_err(|error| KinError::Other(error.to_string()))?;
    if tree_hash != receipt.workspace_tree_hash {
        return Err(KinError::Other(format!(
            "checkout projection receipt names tree {}, but repair received {}",
            receipt.workspace_tree_hash, tree_hash
        )));
    }
    let owned = load_repository_projection_entries(authority, tree, "checkout workspace")?;
    let entries = validated_source_entries(
        owned
            .iter()
            .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
    )?;
    validate_repository_projection_entries_match_tree("checkout", tree, &entries)?;
    let committed = receipt.clone();
    let mut authority_freeze = None;
    let (count, committed) = project_reconciled_source_tree_and_commit(
        root,
        &entries,
        &entries,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingRepositoryFrozen(authority),
            graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                previous_tree: tree,
                target_tree: tree,
                scope: Some(&receipt.selected),
            }),
            checkout_scope: Some(&receipt.selected),
            checkout_projection_authority: Some(CheckoutProjectionAuthority {
                authority,
                receipt: &receipt,
            }),
            checkout_projection_freeze: Some(&mut authority_freeze),
        },
        after_read_only_preflight,
        after_identity_revalidation,
        after_projection_mutation,
        None,
        Some(receipt.clone()),
        move || ProjectionAuthorityCommit::Committed(committed),
    )?;
    let authority_freeze = authority_freeze.ok_or_else(|| {
        KinError::Other(
            "checkout projection repair completed without retaining repository authority"
                .to_string(),
        )
    })?;
    Ok((count, committed, authority_freeze))
}

/// Recover any retained selected-checkout WAL and read its authenticated local
/// receipt. Merely opening this boundary never creates projection control
/// state.
pub fn recover_checkout_projection_receipt(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    operation_id: OperationId,
) -> Result<Option<CheckoutProjectionReceipt>> {
    #[cfg(any(unix, windows))]
    {
        let freeze =
            ExactProjectionFreeze::acquire_existing_for_repository_transition(root, authority)?;
        freeze
            .projection
            .load_checkout_projection_receipt(operation_id)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, authority, operation_id);
        Err(unsupported_safe_projection_error())
    }
}

/// Replay one already-committed repository transaction and recover its exact
/// workspace projection without inverting the authority lock order.
///
/// The projection freeze is acquired first. Only then is the transaction
/// replayed into an exact repository-authority freeze, and any authenticated
/// projection WAL is finalized while both freezes remain retained. The
/// returned repository freeze lets the daemon keep that same authority stable
/// through graph finalization.
pub fn replay_repository_workspace_transaction_and_recover_projection(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    replay_repository_workspace_transaction_and_recover_projection_with_hooks(
        root,
        authority,
        transaction,
        || {},
        || {},
    )
}

fn replay_repository_workspace_transaction_and_recover_projection_with_hooks(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
    after_projection_freeze: impl FnOnce(),
    after_authority_freeze: impl FnOnce(),
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    #[cfg(any(unix, windows))]
    {
        let projection_freeze = ExactProjectionFreeze::acquire_existing_for_replay_recovery(root)?;
        after_projection_freeze();

        let transaction_hash = transaction
            .transaction_hash()
            .map_err(|error| KinError::Other(error.to_string()))?;
        let installed =
            installed_repository_receipt(authority, transaction.operation_id, transaction_hash)
                .ok_or_else(|| {
                    KinError::Other(format!(
                "repository operation {} is not committed and cannot enter projection replay",
                transaction.operation_id
            ))
                })?;
        let (receipt, authority_freeze) =
            commit_repository_transaction_exact_and_freeze(authority, transaction).into_result()?;
        receipt
            .validate()
            .map_err(|error| KinError::Other(error.to_string()))?;
        if receipt.transaction_hash != installed.transaction_hash
            || receipt.roots_before != installed.roots_before
            || receipt.roots_after != installed.roots_after
            || receipt.generation != installed.generation
            || !matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay)
        {
            return Err(KinError::Other(format!(
                "repository operation {} did not replay its exact installed receipt",
                receipt.operation_id
            )));
        }
        if authority_freeze.roots() != &receipt.roots_after {
            return Err(KinError::Other(format!(
                "repository operation {} replay freeze does not name its committed roots",
                receipt.operation_id
            )));
        }
        after_authority_freeze();
        projection_freeze
            .projection
            .recover_reconciliation_transactions_with_authority(authority_freeze.authority())?;
        projection_freeze.revalidate_namespace()?;
        Ok((receipt, authority_freeze))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (
            root,
            authority,
            transaction,
            after_projection_freeze,
            after_authority_freeze,
        );
        Err(unsupported_safe_projection_error())
    }
}

#[allow(clippy::too_many_arguments)]
fn transition_repository_workspace_tree_and_commit_with_hooks<T>(
    root: &Path,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    after_projection_mutation: impl FnOnce(),
    checkout_scope: Option<&RepoPath>,
    commit: impl FnOnce(
        &RepositoryAuthorityManager<LocalFileBackend>,
        RepositoryTransaction,
    ) -> ProjectionAuthorityCommit<T>,
) -> Result<(usize, T)> {
    let previous_owned =
        load_repository_projection_entries(authority, previous_tree, "previous workspace")?;
    let target_owned =
        load_repository_projection_entries(authority, target_tree, "target workspace")?;
    let previous_entries = validated_source_entries(
        previous_owned
            .iter()
            .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
    )?;
    let entries = validated_source_entries(
        target_owned
            .iter()
            .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
    )?;
    validate_repository_projection_transaction(
        previous_tree,
        target_tree,
        &previous_entries,
        &entries,
        &transaction,
        GraphOnlyTransitionPolicy::AllowExactMetadataTransition,
    )?;
    let materialized_count = checkout_scope.map_or(entries.len(), |scope| {
        entries
            .iter()
            .filter(|entry| repository_path_is_same_or_descendant(entry.file_id, scope))
            .count()
    });
    let marker = ReconciliationAuthorityCommit {
        repository_id: transaction.repository_id.clone(),
        operation_id: transaction.operation_id,
        transaction_hash: transaction
            .transaction_hash()
            .map_err(|error| KinError::Other(error.to_string()))?,
    };
    project_reconciled_source_tree_and_commit(
        root,
        &previous_entries,
        &entries,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingRepositoryFrozen(authority),
            graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                previous_tree,
                target_tree,
                scope: checkout_scope,
            }),
            checkout_scope,
            checkout_projection_authority: None,
            checkout_projection_freeze: None,
        },
        after_read_only_preflight,
        after_identity_revalidation,
        after_projection_mutation,
        Some(marker),
        None,
        || commit(authority, transaction),
    )
    .map(|(_, committed)| (materialized_count, committed))
}

fn validate_checkout_repository_transaction(
    selected: &RepoPath,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    transaction: &RepositoryTransaction,
) -> Result<()> {
    if !transaction.external_objects.is_empty()
        || transaction.git_authority_delta.is_some()
        || !transaction.changes.is_empty()
        || !transaction.aliases.is_empty()
        || !transaction.ref_mutations.is_empty()
        || transaction.default_ref_mutation.is_some()
        || transaction.local_overlay_delta.is_some()
    {
        return Err(KinError::Other(
            "exact checkout transaction must mutate only one repository workspace".to_string(),
        ));
    }
    let mutation = transaction.workspace_mutation.as_ref().ok_or_else(|| {
        KinError::Other("exact checkout transaction requires one workspace mutation".to_string())
    })?;
    let WorkspaceExpectation::MustEqual {
        head,
        base_target,
        base_tree_hash,
        admission_policy,
        ..
    } = &mutation.expected
    else {
        return Err(KinError::Other(
            "exact checkout requires an existing workspace compare-and-swap".to_string(),
        ));
    };
    if mutation.new_head != *head
        || mutation.new_base_target != *base_target
        || mutation.new_base_tree_hash != *base_tree_hash
        || mutation.new_admission_policy != *admission_policy
    {
        return Err(KinError::Other(
            "exact checkout must leave workspace head, base, and admission policy unchanged"
                .to_string(),
        ));
    }

    for artifact in previous_tree.artifacts_by_path() {
        if !repository_path_is_same_or_descendant(&artifact.path, selected)
            && target_tree.get(&artifact.artifact_id) != Some(artifact)
        {
            return Err(KinError::Other(format!(
                "exact checkout changed unselected repository member {}",
                artifact.path
            )));
        }
    }
    for artifact in target_tree.artifacts_by_path() {
        if !repository_path_is_same_or_descendant(&artifact.path, selected)
            && previous_tree.get(&artifact.artifact_id) != Some(artifact)
        {
            return Err(KinError::Other(format!(
                "exact checkout added or moved unselected repository member {}",
                artifact.path
            )));
        }
    }
    Ok(())
}

struct OwnedProjectionSourceEntry {
    path: RepoPath,
    kind: TreeEntry,
    content: Vec<u8>,
}

fn load_repository_projection_entries(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    tree: &ResolvedTree,
    label: &str,
) -> Result<Vec<OwnedProjectionSourceEntry>> {
    let mut entries = Vec::new();
    for artifact in tree.artifacts_by_path() {
        let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
        let Some(expected) = artifact.entry.blob_identity() else {
            if disposition != SourceProjectionDisposition::GraphOnlyGitlink {
                return Err(KinError::Other(format!(
                    "{label} path {} has no source-CAS identity but is not a Gitlink",
                    artifact.path
                )));
            }
            continue;
        };
        let content = authority
            .load_source_blob(expected)
            .map_err(|error| {
                KinError::Other(format!(
                    "load {label} source-CAS object {expected} for {}: {error}",
                    artifact.path
                ))
            })?
            .ok_or_else(|| {
                KinError::Other(format!(
                    "{label} source-CAS object {expected} for {} is absent",
                    artifact.path
                ))
            })?;
        let actual = Hash256::from_bytes(kin_blobs::digest_bytes(&content));
        if actual != expected {
            return Err(KinError::Other(format!(
                "{label} source-CAS object for {} hashes to {actual}, expected {expected}",
                artifact.path
            )));
        }
        if disposition == SourceProjectionDisposition::Materialized {
            entries.push(OwnedProjectionSourceEntry {
                path: artifact.path.clone(),
                kind: artifact.entry,
                content,
            });
        }
    }
    Ok(entries)
}

/// Verify an already-current source projection and publish one repository
/// transaction while the retained projection capability remains frozen.
///
/// Explicit filesystem admission commonly advances the workspace tree before
/// an explicit commit records semantic deltas, the new base, and the named ref.
/// In that case there is no source namespace transition to journal. This seam
/// verifies every materializable repository member twice through no-follow
/// capabilities—including byte-exact Unix paths—then commits the repository
/// transaction while the same projection lock and root capability remain
/// held. Graph-only Gitlinks stay in the complete tree but never acquire fake
/// local blob bodies.
pub fn verify_unchanged_source_tree_and_commit_repository_transaction<'a>(
    root: &Path,
    tree: &ResolvedTree,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(usize, RepositoryCommitReceipt)> {
    let entries = validated_projection_proof_entries(entries)?;
    validate_repository_projection_transaction(
        tree,
        tree,
        &entries,
        &entries,
        &transaction,
        GraphOnlyTransitionPolicy::RequireUnchanged,
    )?;

    #[cfg(any(unix, windows))]
    {
        let freeze = ExactProjectionFreeze::acquire_existing(root)?;
        let entry_refs = entries.iter().collect::<Vec<_>>();
        let identities = freeze
            .projection
            .validate_frozen_entries_unchanged(&entry_refs)?;
        freeze
            .projection
            .revalidate_frozen_entries_unchanged(&entry_refs, &identities)?;
        freeze.revalidate_namespace()?;
        let receipt = commit_repository_transaction_exact(authority, transaction).into_result()?;
        Ok((entries.len(), receipt))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, authority, transaction);
        Err(unsupported_safe_projection_error())
    }
}

/// Verify that the working copy already holds one exact target tree, then
/// publish the transaction that moves the workspace onto it.
///
/// This is the boundary for a caller that derived `target_tree` from the
/// working copy itself. A complete filesystem scan produced the target, so the
/// bytes on disk are what proves it, and the same transaction can carry both
/// that tree transition and the caller's semantic change instead of paying for
/// two repository-authority successors moments apart.
///
/// It differs from [`verify_unchanged_source_tree_and_commit_repository_transaction`]
/// in exactly one way: the workspace mutation is allowed to move the tree. The
/// proof is taken against the target rather than the prior tree, because the
/// prior tree is by construction the one the working copy no longer holds. It
/// differs from [`reconcile_source_tree_and_commit_repository_transaction`] in
/// that nothing is written: there is no namespace transition to journal, no
/// rollback, and no window in which the working copy holds bytes that no tree
/// describes.
///
/// Crash consistency is therefore the same as the unchanged-verification seam
/// above. The only durable mutation is the repository transaction, which is
/// atomic and compare-and-swapped on the workspace generation the caller
/// planned against. A process that dies at any point before that CAS leaves
/// authority exactly where it was and leaves the working copy exactly as its
/// author wrote it, which is the state the next complete scan re-derives the
/// same target tree from.
///
/// Graph-only repository members must be identical in both trees, as they must
/// be for every exact-source projection: moving one is a dedicated graph-native
/// operation, not something a source commit may carry.
pub fn verify_observed_target_tree_and_commit_repository_transaction<'a, 'b>(
    root: &Path,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    previous_entries: impl IntoIterator<Item = (&'b RepoPath, TreeEntry, &'b [u8])>,
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(usize, RepositoryCommitReceipt)> {
    let entries = validated_projection_proof_entries(entries)?;
    let previous_entries = validated_projection_proof_entries(previous_entries)?;
    validate_repository_projection_transaction(
        previous_tree,
        target_tree,
        &previous_entries,
        &entries,
        &transaction,
        GraphOnlyTransitionPolicy::RequireUnchanged,
    )?;

    #[cfg(any(unix, windows))]
    {
        let freeze = ExactProjectionFreeze::acquire_existing(root)?;
        let entry_refs = entries.iter().collect::<Vec<_>>();
        let identities = freeze
            .projection
            .validate_frozen_entries_unchanged(&entry_refs)?;
        freeze
            .projection
            .revalidate_frozen_entries_unchanged(&entry_refs, &identities)?;
        freeze.revalidate_namespace()?;
        let receipt = commit_repository_transaction_exact(authority, transaction).into_result()?;
        Ok((entries.len(), receipt))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, authority, transaction);
        Err(unsupported_safe_projection_error())
    }
}

fn validate_repository_projection_transaction(
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    previous_entries: &[ValidatedSourceEntry<'_>],
    entries: &[ValidatedSourceEntry<'_>],
    transaction: &RepositoryTransaction,
    graph_only_policy: GraphOnlyTransitionPolicy,
) -> Result<()> {
    let mutation = transaction.workspace_mutation.as_ref().ok_or_else(|| {
        KinError::Other(
            "exact-source repository projection requires one workspace mutation".to_string(),
        )
    })?;
    let transitioned = previous_tree
        .apply(&mutation.tree_deltas)
        .map_err(|error| KinError::Other(format!("apply workspace projection deltas: {error}")))?;
    if transitioned != *target_tree {
        return Err(KinError::Other(
            "workspace mutation deltas do not produce the requested projection tree".to_string(),
        ));
    }
    let target_tree_hash = compute_resolved_tree_hash(target_tree)
        .map_err(|error| KinError::Other(error.to_string()))?;
    let previous_tree_hash = compute_resolved_tree_hash(previous_tree)
        .map_err(|error| KinError::Other(error.to_string()))?;
    match &mutation.expected {
        WorkspaceExpectation::MustEqual { tree_hash, .. } if *tree_hash == previous_tree_hash => {}
        WorkspaceExpectation::MustEqual { tree_hash, .. } => {
            return Err(KinError::Other(format!(
                "workspace mutation expects prior tree {tree_hash}, but caller supplied {previous_tree_hash}"
            )));
        }
        WorkspaceExpectation::MustNotExist => {
            return Err(KinError::Other(
                "exact repository workspace transition requires a MustEqual prior workspace"
                    .to_string(),
            ));
        }
    }
    if mutation.new_tree_hash != target_tree_hash {
        return Err(KinError::Other(format!(
            "workspace mutation tree hash {} does not match requested projection tree {}",
            mutation.new_tree_hash, target_tree_hash
        )));
    }
    if graph_only_policy == GraphOnlyTransitionPolicy::RequireUnchanged {
        validate_unchanged_graph_only_entries(previous_tree, target_tree)?;
    }
    validate_repository_projection_entries_match_tree("previous", previous_tree, previous_entries)?;
    validate_repository_projection_entries_match_tree("target", target_tree, entries)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphOnlyTransitionPolicy {
    RequireUnchanged,
    AllowExactMetadataTransition,
}

/// Require graph-only repository members to remain byte-for-byte repository
/// identity across a source-projection transaction.
///
/// Gitlinks and host-unrepresentable members are exact repository tree
/// entries, but they are not ordinary host projection objects. A Gitlink may
/// have an independently managed derived checkout at its path. Moving, adding,
/// removing, or retargeting graph-only state needs the dedicated workspace
/// transition above; ordinary source reconciliation must never infer such a
/// transition from ambient filesystem contents.
fn validate_unchanged_graph_only_entries(
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
) -> Result<()> {
    let graph_only = |tree: &ResolvedTree| -> Result<Vec<_>> {
        tree.artifacts_by_path()
            .filter_map(|artifact| {
                match source_projection_disposition(&artifact.path, artifact.entry) {
                    Ok(SourceProjectionDisposition::Materialized) => None,
                    Ok(_) => Some(Ok((
                        artifact.artifact_id,
                        artifact.path.clone(),
                        artifact.entry,
                    ))),
                    Err(error) => Some(Err(error)),
                }
            })
            .collect()
    };
    if graph_only(previous_tree)? != graph_only(target_tree)? {
        return Err(KinError::Other(
            "exact-source repository projection cannot mutate graph-only repository members; use \
             a dedicated graph-native operation"
                .to_string(),
        ));
    }
    Ok(())
}

/// Bind the materializable source bodies to the complete repository tree
/// without pretending graph-only entries have local blob bodies.
///
/// The caller separately proves how the complete previous tree transitions to
/// the complete target tree. This comparison therefore covers exactly the
/// materializable subset while excluding only entries classified by explicit
/// host policy as graph-only—never arbitrary unknown or unsupported content.
fn validate_repository_projection_entries_match_tree(
    label: &str,
    tree: &ResolvedTree,
    entries: &[ValidatedSourceEntry<'_>],
) -> Result<()> {
    let mut expected = Vec::new();
    for artifact in tree.artifacts() {
        if source_projection_disposition(&artifact.path, artifact.entry)?
            == SourceProjectionDisposition::Materialized
        {
            expected.push((&artifact.path, artifact.entry));
        }
    }
    expected.sort_by(|left, right| left.0.cmp(right.0));
    if expected.len() != entries.len()
        || expected
            .iter()
            .zip(entries)
            .any(|((path, kind), entry)| *path != entry.file_id || *kind != entry.kind)
    {
        return Err(KinError::Other(format!(
            "{label} exact-source bodies do not cover every materializable member of the complete graph tree"
        )));
    }
    for entry in entries {
        let expected_hash = entry.kind.blob_identity().ok_or_else(|| {
            KinError::Other(format!(
                "{label} exact-source body list contains a graph-only repository member {}",
                entry.file_id
            ))
        })?;
        let actual_hash = kin_blobs::digest(entry.content);
        if actual_hash != expected_hash {
            return Err(KinError::Other(format!(
                "{label} source body for {} hashes to {}, expected repository CAS object {}",
                entry.file_id, actual_hash, expected_hash
            )));
        }
    }
    Ok(())
}

/// How one exact repository entry maps onto the current host projection.
///
/// This is deliberately separate from repository membership. Every entry
/// remains in [`ResolvedTree`] regardless of whether this host can expose it
/// as a local source object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceProjectionDisposition {
    /// A repository-owned blob or symbolic link that this host can represent.
    Materialized,
    /// A Gitlink is exact repository history whose optional nested checkout is
    /// independently owned, never a blob in this repository's source CAS.
    GraphOnlyGitlink,
    /// The repository path or entry kind cannot be represented faithfully on
    /// this host (for example a non-UTF-8 Git path on macOS).
    GraphOnlyHostUnrepresentable,
}

/// Classify one repository member without consulting ambient filesystem state.
///
/// Invalid/reserved control-plane paths still fail loud. Host limitations only
/// affect projection; they never erase exact graph membership.
pub fn source_projection_disposition(
    path: &RepoPath,
    entry: TreeEntry,
) -> Result<SourceProjectionDisposition> {
    if matches!(entry, TreeEntry::Gitlink { .. }) {
        return Ok(SourceProjectionDisposition::GraphOnlyGitlink);
    }
    #[cfg(windows)]
    if matches!(entry, TreeEntry::Symlink { .. }) {
        return Ok(SourceProjectionDisposition::GraphOnlyHostUnrepresentable);
    }
    if let Some(path) = path.as_utf8() {
        validate_source_path(path)?;
        return Ok(SourceProjectionDisposition::Materialized);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        validate_projection_proof_path(path)?;
        Ok(SourceProjectionDisposition::Materialized)
    }
    #[cfg(any(target_os = "macos", windows, not(any(unix, windows))))]
    {
        Ok(SourceProjectionDisposition::GraphOnlyHostUnrepresentable)
    }
}

fn validate_projection_entries_match_tree(
    label: &str,
    tree: &ResolvedTree,
    entries: &[ValidatedSourceEntry<'_>],
) -> Result<()> {
    let mut expected = tree
        .artifacts()
        .map(|artifact| (&artifact.path, artifact.entry))
        .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.0.cmp(right.0));
    if expected.len() != entries.len()
        || expected
            .iter()
            .zip(entries)
            .any(|((path, kind), entry)| *path != entry.file_id || *kind != entry.kind)
    {
        return Err(KinError::Other(format!(
            "{label} exact-source bodies do not cover the complete graph tree"
        )));
    }
    for entry in entries {
        let expected_hash = entry.kind.blob_identity().ok_or_else(|| {
            KinError::Other(format!(
                "{label} graph tree contains unmaterializable gitlink {}",
                entry.file_id
            ))
        })?;
        let actual_hash = kin_blobs::digest(entry.content);
        if actual_hash != expected_hash {
            return Err(KinError::Other(format!(
                "{label} source body for {} hashes to {}, expected repository CAS object {}",
                entry.file_id, actual_hash, expected_hash
            )));
        }
    }
    Ok(())
}

fn load_projection_proof_blob(
    blobs: &kin_blobs::BlobStore,
    path: &RepoPath,
    entry: TreeEntry,
) -> Result<Vec<u8>> {
    let expected = entry.blob_identity().ok_or_else(|| {
        KinError::Other(format!(
            "graph tree contains unmaterializable gitlink {path}"
        ))
    })?;
    let blob_hash = kin_blobs::Hash256::from_bytes(*expected.as_bytes());
    let content = blobs.read(&blob_hash).map_err(|error| {
        KinError::Other(format!(
            "load exact projection body {expected} for {path}: {error}"
        ))
    })?;
    let actual = kin_blobs::digest(&content);
    if actual.as_bytes() != expected.as_bytes() {
        return Err(KinError::Other(format!(
            "exact projection body for {path} hashes to {actual}, expected repository CAS object {expected}"
        )));
    }
    Ok(content)
}

/// Initialize the reconciliation control state inside an existing `.kin`
/// directory.
///
/// Repository initialization calls this against its private staging
/// directory, before publishing that directory as `.kin`. Runtime exact-tree
/// guards deliberately use an existing-only open instead, so a missing lock or
/// authority key is never repaired while repository authority is being frozen.
pub(crate) fn initialize_projection_control_directory(kin_dir: &Path) -> Result<()> {
    #[cfg(any(unix, windows))]
    {
        let kin_control = open_projection_root_nofollow(kin_dir)?;
        let display_control = kin_dir.join(RECONCILIATION_CONTROL_DIRECTORY);
        let control = open_or_create_private_directory(
            &kin_control,
            std::ffi::OsStr::new(RECONCILIATION_CONTROL_DIRECTORY),
            &display_control,
        )?;
        let (_projection_lock, _projection_lock_identity) = acquire_reconciliation_projection_lock(
            &control,
            &display_control,
            PROJECTION_LOCK_WAIT_DEADLINE,
        )?;
        load_or_create_reconciliation_authority_key(&control, &display_control)?;
        sync_directory_capability(&control, &display_control)?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = kin_dir;
        Err(unsupported_safe_projection_error())
    }
}

/// Exclusive, non-creating capability over an existing exact-source projection.
///
/// The guard holds Kin's projection lock and no-follow capabilities for the
/// working root and `.kin/reconciliation` namespace. It does not open repository
/// authority, so callers that also freeze repository-v6 state must acquire this
/// guard first and retain it while they acquire authority.
pub struct ExactProjectionFreeze {
    #[cfg(any(unix, windows))]
    projection: ProjectionRoot,
    #[cfg(any(unix, windows))]
    root_identity: TrackedEntryIdentity,
}

/// Opaque authority-bearing handle for one exact session projection.
///
/// The handle can only be produced by materializing graph-owned source through
/// an [`ExactProjectionFreeze`]. It retains the repository projection lock,
/// the original `.kin/runs` directory, and the published session directory, so
/// downstream runtime code cannot relabel an arbitrary ambient path as exact.
pub struct ExactSessionProjection {
    repository_freeze: ExactProjectionFreeze,
    #[cfg(any(unix, windows))]
    projection: ProjectionRoot,
    #[cfg(any(unix, windows))]
    runs: cap_std::fs::Dir,
    #[cfg(any(unix, windows))]
    runs_identity: TrackedEntryIdentity,
    #[cfg(any(unix, windows))]
    session_name: OsString,
    #[cfg(any(unix, windows))]
    session_identity: TrackedEntryIdentity,
    display_root: std::path::PathBuf,
}

/// Identity-bound proof that one complete [`ResolvedTree`] matched every
/// host-materializable working-copy entry, while graph-only entries satisfied
/// their typed host representation policy, under an
/// [`ExactProjectionFreeze`].
pub struct ExactProjectionVerification {
    tree_hash: Hash256,
    #[cfg(any(unix, windows))]
    entries: Vec<ExactProjectionVerifiedEntry>,
}

#[cfg(any(unix, windows))]
struct ExactProjectionVerifiedEntry {
    path: RepoPath,
    kind: TreeEntry,
    proof: ExactProjectionEntryProof,
}

#[cfg(any(unix, windows))]
enum ExactProjectionEntryProof {
    Materialized {
        identity: TrackedEntryIdentity,
    },
    HostUnrepresentableAbsent,
    GitlinkAbsent,
    GitlinkDirectory {
        directory: cap_std::fs::Dir,
        identity: TrackedEntryIdentity,
    },
}

/// Retained, no-follow capability for an already-created eject archive.
///
/// Keeping this target alive prevents the final metadata move from reopening
/// an ambient destination path after verification.
pub struct ExactProjectionDetachTarget {
    #[cfg(any(unix, windows))]
    parent: cap_std::fs::Dir,
    #[cfg(any(unix, windows))]
    parent_identity: TrackedEntryIdentity,
    #[cfg(any(unix, windows))]
    directory: cap_std::fs::Dir,
    #[cfg(any(unix, windows))]
    name: OsString,
    #[cfg(any(unix, windows))]
    identity: TrackedEntryIdentity,
    parent_display_path: std::path::PathBuf,
    display_path: std::path::PathBuf,
}

/// Retained, no-follow capability for a fully prepared staged `.git` directory.
///
/// Callers must finish and durably sync the staged repository before opening
/// this capability. The consuming eject transaction moves this exact directory
/// into the frozen projection and restores it to its retained parent on error.
pub struct ExactProjectionGitStage {
    #[cfg(unix)]
    parent: cap_std::fs::Dir,
    #[cfg(unix)]
    parent_identity: TrackedEntryIdentity,
    #[cfg(unix)]
    directory: cap_std::fs::Dir,
    #[cfg(unix)]
    name: OsString,
    #[cfg(unix)]
    identity: TrackedEntryIdentity,
    #[cfg(unix)]
    seal: ExactGitDirectorySeal,
    #[cfg(unix)]
    proof: Option<kin_git::RepositoryGitExportProof>,
    #[cfg(unix)]
    expected_tree: Option<ResolvedTree>,
    #[cfg(unix)]
    parent_display_path: std::path::PathBuf,
    display_path: std::path::PathBuf,
}

/// Result of one capability-anchored exact projection eject transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactProjectionEjectOutcome {
    /// Whether an existing regular-file or directory `.git` entry was retained
    /// and archived before the staged repository was installed.
    pub had_previous_git: bool,
    /// Set when the eject completed but its journal could not be retired from
    /// the archived `.kin`, naming the file and what to do about it. `None` is
    /// the normal case: a finished transaction leaves no journal behind.
    pub retained_journal: Option<String>,
}

impl std::fmt::Debug for ExactProjectionFreeze {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactProjectionFreeze")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExactSessionProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactSessionProjection")
            .field("display_root", &self.display_root)
            .finish_non_exhaustive()
    }
}

impl ExactSessionProjection {
    /// Absolute display path of the capability-owned session directory.
    pub fn root(&self) -> &Path {
        &self.display_root
    }

    /// Revalidate the repository epoch, `.kin/runs`, published session name,
    /// retained session directory, and session projection lock.
    pub fn revalidate(&self) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            let runs_display = self
                .repository_freeze
                .projection
                .display_projection_control
                .join(SESSION_RUNS_DIRECTORY);
            self.repository_freeze.revalidate_session_runs(
                &self.runs,
                self.runs_identity,
                &runs_display,
            )?;
            validate_named_directory_identity(
                &self.runs,
                &self.session_name,
                &self.projection.root,
                self.session_identity,
                &self.display_root,
                "published session directory",
            )?;
            self.projection.revalidate_projection_lock()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported_safe_projection_error())
        }
    }

    /// Bind a child process to the retained session directory capability.
    ///
    /// On Unix the child performs `fchdir` against a cloned retained
    /// directory handle after `fork` and before `exec`. A concurrent rename or
    /// replacement of the ambient display path therefore cannot redirect the
    /// process into attacker-controlled content after revalidation.
    ///
    /// Platforms without a handle-relative child working-directory primitive
    /// fail before spawn instead of falling back to `Command::current_dir`.
    pub fn configure_command_current_dir(&self, command: &mut std::process::Command) -> Result<()> {
        self.revalidate()?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::process::CommandExt;

            let root = self
                .projection
                .root
                .try_clone()
                .map_err(|error| KinError::io(&self.display_root, error))?;
            let identity = tracked_open_directory_identity(&root)
                .map_err(|error| KinError::io(&self.display_root, error))?;
            if identity != self.session_identity {
                return Err(KinError::Other(format!(
                    "retained session execution root identity changed at {}",
                    self.display_root.display()
                )));
            }
            // SAFETY: `pre_exec` runs in the child after fork. The closure only
            // calls the async-signal-safe `fchdir(2)` on an already-open fd and
            // constructs an `io::Error` from errno on failure. Owning `root`
            // inside the closure keeps that exact directory alive until the
            // child has changed directory.
            unsafe {
                command.pre_exec(move || {
                    if libc::fchdir(root.as_raw_fd()) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = command;
            Err(KinError::Other(
                "capability-bound session execution is unsupported on this platform".to_string(),
            ))
        }
    }
}

impl std::fmt::Debug for ExactProjectionVerification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactProjectionVerification")
            .field("tree_hash", &self.tree_hash)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExactProjectionDetachTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactProjectionDetachTarget")
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExactProjectionGitStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactProjectionGitStage")
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

impl ExactProjectionDetachTarget {
    /// Retain an already-created real directory without following its leaf.
    pub fn open_existing(path: &Path) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            if !path.is_absolute() {
                return Err(KinError::Other(format!(
                    "projection detach target must be absolute: {}",
                    path.display()
                )));
            }
            let parent_path = path.parent().ok_or_else(|| {
                KinError::Other(format!(
                    "projection detach target has no parent: {}",
                    path.display()
                ))
            })?;
            let name = path.file_name().ok_or_else(|| {
                KinError::Other(format!(
                    "projection detach target has no file name: {}",
                    path.display()
                ))
            })?;
            let parent = open_projection_root_nofollow(parent_path)?;
            let parent_identity = tracked_open_directory_identity(&parent)
                .map_err(|error| KinError::io(parent_path, error))?;
            let directory = open_directory_nofollow_for_removal(&parent, name)
                .map_err(|error| KinError::io(path, error))?;
            let identity = tracked_open_directory_identity(&directory)
                .map_err(|error| KinError::io(path, error))?;
            // On Unix this durably binds the caller-created archive name before
            // it can become the sole namespace owner of `.git` or `.kin`.
            // Windows eject currently fails closed before mutation below.
            sync_directory_capability(&directory, path)?;
            sync_directory_capability(&parent, parent_path)?;
            Ok(Self {
                parent,
                parent_identity,
                directory,
                name: name.to_os_string(),
                identity,
                parent_display_path: parent_path.to_path_buf(),
                display_path: path.to_path_buf(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(unsupported_safe_projection_error())
        }
    }

    #[cfg(any(unix, windows))]
    fn revalidate(&self) -> Result<()> {
        let visible_parent = open_projection_root_nofollow(&self.parent_display_path)?;
        if tracked_open_directory_identity(&visible_parent)
            .map_err(|error| KinError::io(&self.parent_display_path, error))?
            != self.parent_identity
        {
            return Err(KinError::Other(format!(
                "projection detach target parent {} was replaced while retained",
                self.parent_display_path.display()
            )));
        }
        if tracked_open_directory_identity(&self.parent)
            .map_err(|error| KinError::io(&self.parent_display_path, error))?
            != self.parent_identity
        {
            return Err(KinError::Other(format!(
                "retained projection detach target parent {} changed identity",
                self.parent_display_path.display()
            )));
        }
        let named = open_directory_nofollow(&self.parent, &self.name)
            .map_err(|error| KinError::io(&self.display_path, error))?;
        if tracked_open_directory_identity(&named)
            .map_err(|error| KinError::io(&self.display_path, error))?
            != self.identity
        {
            return Err(KinError::Other(format!(
                "projection detach target {} was replaced while retained",
                self.display_path.display()
            )));
        }
        if tracked_open_directory_identity(&self.directory)
            .map_err(|error| KinError::io(&self.display_path, error))?
            != self.identity
        {
            return Err(KinError::Other(format!(
                "retained projection detach target {} changed identity",
                self.display_path.display()
            )));
        }
        Ok(())
    }
}

impl ExactProjectionGitStage {
    /// Prove and retain an already-created staged `.git` directory.
    ///
    /// The repository must still match the opaque proof returned by
    /// `kin_git::export_repository_to_git`, its checked-out HEAD tree must
    /// equal `expected_tree`, and every descendant byte, mode, kind, and object
    /// identity is sealed through no-follow capabilities before this returns.
    pub fn open_existing(
        path: &Path,
        proof: &kin_git::RepositoryGitExportProof,
        expected_tree: &ResolvedTree,
    ) -> Result<Self> {
        #[cfg(unix)]
        {
            let mut stage = Self::open_and_seal(path)?;
            kin_git::verify_repository_git_export(path, proof, expected_tree).map_err(|error| {
                KinError::Other(format!(
                    "verify staged Git repository against repository-v6 export proof: {error}"
                ))
            })?;
            stage.revalidate_named()?;
            stage.proof = Some(proof.clone());
            stage.expected_tree = Some(expected_tree.clone());
            Ok(stage)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, proof, expected_tree);
            Err(KinError::Other(
                "sealed exact Git staging is unsupported on this platform until durable no-replace directory namespace moves are available"
                    .to_string(),
            ))
        }
    }

    #[cfg(unix)]
    fn open_and_seal(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(KinError::Other(format!(
                "staged Git directory must be absolute: {}",
                path.display()
            )));
        }
        let parent_path = path.parent().ok_or_else(|| {
            KinError::Other(format!(
                "staged Git directory has no parent: {}",
                path.display()
            ))
        })?;
        let name = path.file_name().ok_or_else(|| {
            KinError::Other(format!(
                "staged Git directory has no file name: {}",
                path.display()
            ))
        })?;
        let parent = open_projection_root_nofollow(parent_path)?;
        let parent_identity = tracked_open_directory_identity(&parent)
            .map_err(|error| KinError::io(parent_path, error))?;
        let directory = open_directory_nofollow_for_removal(&parent, name)
            .map_err(|error| KinError::io(path, error))?;
        let identity = tracked_open_directory_identity(&directory)
            .map_err(|error| KinError::io(path, error))?;
        sync_directory_capability(&directory, path)?;
        sync_directory_capability(&parent, parent_path)?;
        let seal = seal_exact_git_directory(&directory, path)?;
        if seal.multiply_linked_files != 0 {
            return Err(KinError::Other(format!(
                "staged Git directory {} contains {} externally aliased hard-linked files",
                path.display(),
                seal.multiply_linked_files
            )));
        }
        let stage = Self {
            parent,
            parent_identity,
            directory,
            name: name.to_os_string(),
            identity,
            seal,
            proof: None,
            expected_tree: None,
            parent_display_path: parent_path.to_path_buf(),
            display_path: path.to_path_buf(),
        };
        stage.revalidate_named()?;
        Ok(stage)
    }

    #[cfg(all(test, unix))]
    fn open_existing_unverified_for_test(path: &Path) -> Result<Self> {
        Self::open_and_seal(path)
    }

    #[cfg(all(test, not(unix)))]
    fn open_existing_unverified_for_test(path: &Path) -> Result<Self> {
        Ok(Self {
            display_path: path.to_path_buf(),
        })
    }

    #[cfg(unix)]
    fn revalidate_parent(&self) -> Result<()> {
        let visible_parent = open_projection_root_nofollow(&self.parent_display_path)?;
        if tracked_open_directory_identity(&visible_parent)
            .map_err(|error| KinError::io(&self.parent_display_path, error))?
            != self.parent_identity
        {
            return Err(KinError::Other(format!(
                "staged Git parent {} was replaced while retained",
                self.parent_display_path.display()
            )));
        }
        if tracked_open_directory_identity(&self.parent)
            .map_err(|error| KinError::io(&self.parent_display_path, error))?
            != self.parent_identity
        {
            return Err(KinError::Other(format!(
                "retained staged Git parent {} changed identity",
                self.parent_display_path.display()
            )));
        }
        if tracked_open_directory_identity(&self.directory)
            .map_err(|error| KinError::io(&self.display_path, error))?
            != self.identity
        {
            return Err(KinError::Other(format!(
                "retained staged Git directory {} changed identity",
                self.display_path.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn revalidate_named(&self) -> Result<()> {
        self.revalidate_parent()?;
        let named = open_directory_nofollow(&self.parent, &self.name)
            .map_err(|error| KinError::io(&self.display_path, error))?;
        if tracked_open_directory_identity(&named)
            .map_err(|error| KinError::io(&self.display_path, error))?
            != self.identity
        {
            return Err(KinError::Other(format!(
                "staged Git directory {} was replaced while retained",
                self.display_path.display()
            )));
        }
        let seal = seal_exact_git_directory(&self.directory, &self.display_path)?;
        if seal != self.seal {
            return Err(KinError::Other(format!(
                "staged Git directory {} changed descendants after exact sealing",
                self.display_path.display()
            )));
        }
        Ok(())
    }
}

impl ExactProjectionFreeze {
    /// Acquire the existing projection lock without creating `.kin`, its
    /// reconciliation directory, lock file, or authority key.
    pub fn acquire_existing(root: &Path) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let projection =
                ProjectionRoot::open_existing_for_freeze(root, PROJECTION_LOCK_WAIT_DEADLINE)?;
            let root_identity = tracked_open_directory_identity(&projection.root)
                .map_err(|error| KinError::io(root, error))?;
            let freeze = Self {
                projection,
                root_identity,
            };
            freeze.revalidate_namespace()?;
            Ok(freeze)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = root;
            Err(unsupported_safe_projection_error())
        }
    }

    /// Acquire an existing projection for an authority-publishing workspace
    /// transition, recovering an earlier authenticated reconciliation WAL
    /// before admitting a new one.
    ///
    /// Unlike ordinary projection open, this never creates or repairs `.kin`
    /// control state. Unlike eject freeze, it may recover a prior repository
    /// transition because branch retry is itself the recovery boundary.
    #[cfg(test)]
    fn acquire_existing_for_transition(root: &Path) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let projection = ProjectionRoot::open_existing_for_reconciliation(
                root,
                PROJECTION_LOCK_WAIT_DEADLINE,
            )?;
            let root_identity = tracked_open_directory_identity(&projection.root)
                .map_err(|error| KinError::io(root, error))?;
            let freeze = Self {
                projection,
                root_identity,
            };
            freeze.revalidate_namespace()?;
            Ok(freeze)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = root;
            Err(unsupported_safe_projection_error())
        }
    }

    /// Acquire a repository workspace transition boundary and recover any
    /// authenticated WAL through the caller's retained storage capability.
    ///
    /// Lock order is projection then repository authority. The authority
    /// freeze revalidates KinDB's startup-pinned storage root before recovery
    /// can inspect or clean a WAL; an identically copied path replacement is
    /// therefore rejected instead of being treated as the original repo.
    fn acquire_existing_for_repository_transition(
        root: &Path,
        authority: &RepositoryAuthorityManager<LocalFileBackend>,
    ) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let projection = ProjectionRoot::open_existing_for_replay_recovery(
                root,
                PROJECTION_LOCK_WAIT_DEADLINE,
            )?;
            let root_identity = tracked_open_directory_identity(&projection.root)
                .map_err(|error| KinError::io(root, error))?;
            let freeze = Self {
                projection,
                root_identity,
            };
            freeze.revalidate_namespace()?;

            let expected_roots = authority.read_authority().roots().clone();
            let authority_freeze = authority
                .freeze_current_authority(&expected_roots)
                .map_err(|error| {
                    classify_repository_authority_freeze_error(
                        "freeze retained repository authority before projection recovery",
                        error,
                    )
                })?;
            freeze
                .projection
                .recover_reconciliation_transactions_with_authority(authority_freeze.authority())?;
            drop(authority_freeze);
            freeze.revalidate_namespace()?;
            Ok(freeze)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (root, authority);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Acquire the projection lock without recovering its repository WAL.
    ///
    /// Replay recovery must freeze repository authority only after this guard
    /// exists, then finalize the retained WAL while both guards are alive.
    fn acquire_existing_for_replay_recovery(root: &Path) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let projection = ProjectionRoot::open_existing_for_replay_recovery(
                root,
                PROJECTION_LOCK_WAIT_DEADLINE,
            )?;
            let root_identity = tracked_open_directory_identity(&projection.root)
                .map_err(|error| KinError::io(root, error))?;
            let freeze = Self {
                projection,
                root_identity,
            };
            freeze.revalidate_namespace()?;
            Ok(freeze)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = root;
            Err(unsupported_safe_projection_error())
        }
    }

    /// Materialize and atomically publish one exact session projection beneath
    /// the retained repository's `.kin/runs` directory, creating that
    /// directory through the retained `.kin` capability when absent.
    ///
    /// The final child is never opened or created through its ambient path.
    /// Kin materializes into an unguessable retained staging child, then moves
    /// that exact directory to `session_name` with no replacement while the
    /// repository projection lock remains held.
    pub fn materialize_session_source_tree<'a>(
        self,
        session_name: &str,
        base_metadata: &[u8],
        entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    ) -> Result<(ExactSessionProjection, usize)> {
        let entries = validated_session_source_entries(base_metadata, entries)?;
        #[cfg(any(unix, windows))]
        {
            self.materialize_validated_session_source_tree(
                session_name,
                base_metadata,
                &entries,
                || {},
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (self, session_name, base_metadata, entries);
            Err(unsupported_safe_projection_error())
        }
    }

    #[cfg(any(unix, windows))]
    fn materialize_validated_session_source_tree(
        self,
        session_name: &str,
        base_metadata: &[u8],
        entries: &[ValidatedSourceEntry<'_>],
        after_runs_open: impl FnOnce(),
    ) -> Result<(ExactSessionProjection, usize)> {
        validate_session_projection_name(session_name)?;
        self.revalidate_namespace()?;

        let runs_display = self
            .projection
            .display_projection_control
            .join(SESSION_RUNS_DIRECTORY);
        let runs = open_or_create_private_directory(
            &self.projection.kin_control,
            std::ffi::OsStr::new(SESSION_RUNS_DIRECTORY),
            &runs_display,
        )
        .map_err(|error| {
            KinError::Other(format!(
                "open or create retained repository session root {}: {error}",
                runs_display.display()
            ))
        })?;
        let runs_identity = tracked_open_directory_identity(&runs)
            .map_err(|error| KinError::io(&runs_display, error))?;

        after_runs_open();
        self.revalidate_session_runs(&runs, runs_identity, &runs_display)?;

        let final_name = OsString::from(session_name);
        let final_display = runs_display.join(&final_name);
        ensure_session_child_absent(&runs, &final_name, &final_display)?;

        let (stage_name, stage_display, stage_identity, stage_root) =
            create_retained_session_stage(&runs, &runs_display)?;
        let mut projection =
            ProjectionRoot::open_session_from_capability(stage_root, &stage_display).map_err(
                |error| {
                    KinError::Other(format!(
                        "initialize retained session staging directory {}: {error}",
                        stage_display.display()
                    ))
                },
            )?;
        let tracked = TrackedPathClassifier::new(entries.iter().map(|entry| entry.file_id))?;
        let plan = projection.plan_full_replacement(&tracked, None)?;
        projection.apply_full_replacement(entries, plan)?;
        projection.install_session_base_metadata(base_metadata)?;
        sync_directory_capability(&projection.root, &stage_display)?;

        self.revalidate_namespace()?;
        self.revalidate_session_runs(&runs, runs_identity, &runs_display)?;
        validate_named_directory_identity(
            &runs,
            &stage_name,
            &projection.root,
            stage_identity,
            &stage_display,
            "session staging directory",
        )?;
        ensure_session_child_absent(&runs, &final_name, &final_display)?;

        self.projection
            .move_open_directory_from_expected_source_exact(
                NamedEntryLocation {
                    parent: &runs,
                    name: &stage_name,
                },
                NamedEntryLocation {
                    parent: &runs,
                    name: &final_name,
                },
                &projection.root,
                stage_identity,
                &stage_display,
            )?;
        projection.retarget_display_root(final_display.clone());

        let post_publish = self
            .revalidate_namespace()
            .and_then(|()| self.revalidate_session_runs(&runs, runs_identity, &runs_display))
            .and_then(|()| {
                validate_named_directory_identity(
                    &runs,
                    &final_name,
                    &projection.root,
                    stage_identity,
                    &final_display,
                    "published session directory",
                )
            })
            .and_then(|()| projection.revalidate_projection_lock());
        if let Err(error) = post_publish {
            let rollback = self
                .projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &runs,
                        name: &final_name,
                    },
                    NamedEntryLocation {
                        parent: &runs,
                        name: &stage_name,
                    },
                    &projection.root,
                    stage_identity,
                    &final_display,
                );
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(KinError::Other(format!(
                    "{error}; retained session publication rollback also failed: {rollback_error}"
                ))),
            };
        }

        let count = entries.len();
        Ok((
            ExactSessionProjection {
                repository_freeze: self,
                projection,
                runs,
                runs_identity,
                session_name: final_name,
                session_identity: stage_identity,
                display_root: final_display,
            },
            count,
        ))
    }

    #[cfg(any(unix, windows))]
    fn revalidate_session_runs(
        &self,
        runs: &cap_std::fs::Dir,
        expected_identity: TrackedEntryIdentity,
        display: &Path,
    ) -> Result<()> {
        self.revalidate_namespace()?;
        validate_named_directory_identity(
            &self.projection.kin_control,
            std::ffi::OsStr::new(SESSION_RUNS_DIRECTORY),
            runs,
            expected_identity,
            display,
            "repository session root",
        )
    }

    /// Verify exact bytes, Git mode/kind, and symbolic-link targets for every
    /// artifact in `tree`, traversing every ancestor through no-follow handles.
    ///
    /// Extra untracked working-copy paths are deliberately outside this proof:
    /// they remain ordinary untracked files after eject rather than becoming
    /// repository authority.
    pub fn verify_resolved_tree<'a>(
        &self,
        tree: &ResolvedTree,
        entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    ) -> Result<ExactProjectionVerification> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_namespace()?;
            let entries = validated_projection_proof_entries(entries)?;
            validate_projection_entries_match_tree("frozen", tree, &entries)?;
            let entry_refs = entries.iter().collect::<Vec<_>>();
            let identities = self
                .projection
                .validate_frozen_entries_unchanged(&entry_refs)?;
            self.revalidate_namespace()?;
            let tree_hash = compute_resolved_tree_hash(tree)
                .map_err(|error| KinError::Other(error.to_string()))?;
            Ok(ExactProjectionVerification {
                tree_hash,
                entries: entries
                    .into_iter()
                    .zip(identities)
                    .map(|(entry, identity)| ExactProjectionVerifiedEntry {
                        path: entry.file_id.clone(),
                        kind: entry.kind,
                        proof: ExactProjectionEntryProof::Materialized { identity },
                    })
                    .collect(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (tree, entries);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Bounded-memory variant of [`Self::verify_resolved_tree`] that reads each
    /// host-materializable exact body from a content-addressed blob store.
    /// Gitlinks and paths the host cannot represent remain graph-only and are
    /// proved through their typed representation policy instead.
    pub fn verify_resolved_tree_from_blobs(
        &self,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
    ) -> Result<ExactProjectionVerification> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_namespace()?;
            validate_projection_proof_paths(
                tree.artifacts_by_path().map(|artifact| &artifact.path),
            )?;
            let mut verified = Vec::with_capacity(tree.len());
            for artifact in tree.artifacts_by_path() {
                let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
                let proof = match disposition {
                    SourceProjectionDisposition::GraphOnlyGitlink => self
                        .projection
                        .verify_frozen_graph_only(&artifact.path, disposition)?,
                    SourceProjectionDisposition::GraphOnlyHostUnrepresentable => self
                        .projection
                        .verify_frozen_graph_only(&artifact.path, disposition)?,
                    SourceProjectionDisposition::Materialized => {
                        let content =
                            load_projection_proof_blob(blobs, &artifact.path, artifact.entry)?;
                        let entry = ValidatedSourceEntry {
                            file_id: &artifact.path,
                            kind: artifact.entry,
                            content: &content,
                        };
                        let identity = self.projection.validate_frozen_entry_unchanged(&entry)?;
                        ExactProjectionEntryProof::Materialized { identity }
                    }
                };
                verified.push(ExactProjectionVerifiedEntry {
                    path: artifact.path.clone(),
                    kind: artifact.entry,
                    proof,
                });
            }
            self.revalidate_namespace()?;
            let tree_hash = compute_resolved_tree_hash(tree)
                .map_err(|error| KinError::Other(error.to_string()))?;
            Ok(ExactProjectionVerification {
                tree_hash,
                entries: verified,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (tree, blobs);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Revalidate a prior exact proof, including object identities, immediately
    /// before a namespace transition.
    pub fn revalidate_resolved_tree<'a>(
        &self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
    ) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_namespace()?;
            let tree_hash = compute_resolved_tree_hash(tree)
                .map_err(|error| KinError::Other(error.to_string()))?;
            if tree_hash != verification.tree_hash {
                return Err(KinError::Other(
                    "resolved projection tree changed after exact verification".to_string(),
                ));
            }
            let entries = validated_projection_proof_entries(entries)?;
            validate_projection_entries_match_tree("revalidated", tree, &entries)?;
            if entries.len() != verification.entries.len()
                || entries
                    .iter()
                    .zip(&verification.entries)
                    .any(|(entry, verified)| {
                        entry.file_id != &verified.path || entry.kind != verified.kind
                    })
            {
                return Err(KinError::Other(
                    "exact projection verification does not describe this resolved tree"
                        .to_string(),
                ));
            }
            let entry_refs = entries.iter().collect::<Vec<_>>();
            let expected_identities = verification
                .entries
                .iter()
                .map(|entry| match &entry.proof {
                    ExactProjectionEntryProof::Materialized { identity } => Ok(*identity),
                    ExactProjectionEntryProof::HostUnrepresentableAbsent
                    | ExactProjectionEntryProof::GitlinkAbsent
                    | ExactProjectionEntryProof::GitlinkDirectory { .. } => Err(KinError::Other(
                        "byte-slice projection revalidation cannot represent graph-only entry state; use the CAS-backed exact proof"
                            .to_string(),
                    )),
                })
                .collect::<Result<Vec<_>>>()?;
            self.projection
                .revalidate_frozen_entries_unchanged(&entry_refs, &expected_identities)?;
            self.revalidate_namespace()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (verification, tree, entries);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Bounded-memory variant of [`Self::revalidate_resolved_tree`].
    pub fn revalidate_resolved_tree_from_blobs(
        &self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
    ) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_namespace()?;
            let tree_hash = compute_resolved_tree_hash(tree)
                .map_err(|error| KinError::Other(error.to_string()))?;
            if tree_hash != verification.tree_hash {
                return Err(KinError::Other(
                    "resolved projection tree changed after exact verification".to_string(),
                ));
            }
            validate_projection_proof_paths(
                tree.artifacts_by_path().map(|artifact| &artifact.path),
            )?;
            if tree.len() != verification.entries.len() {
                return Err(KinError::Other(
                    "exact projection verification does not cover this resolved tree".to_string(),
                ));
            }
            for (artifact, verified) in tree.artifacts_by_path().zip(verification.entries.iter()) {
                if artifact.path != verified.path || artifact.entry != verified.kind {
                    return Err(KinError::Other(
                        "exact projection verification does not describe this resolved tree"
                            .to_string(),
                    ));
                }
                let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
                match disposition {
                    SourceProjectionDisposition::GraphOnlyGitlink
                    | SourceProjectionDisposition::GraphOnlyHostUnrepresentable => {
                        self.projection.revalidate_frozen_graph_only(
                            &artifact.path,
                            disposition,
                            &verified.proof,
                        )?
                    }
                    SourceProjectionDisposition::Materialized => {
                        let ExactProjectionEntryProof::Materialized {
                            identity: expected_identity,
                        } = &verified.proof
                        else {
                            return Err(KinError::Other(
                                "exact projection verification mixed materialized and graph-only entry proofs"
                                    .to_string(),
                            ));
                        };
                        let content =
                            load_projection_proof_blob(blobs, &artifact.path, artifact.entry)?;
                        let entry = ValidatedSourceEntry {
                            file_id: &artifact.path,
                            kind: artifact.entry,
                            content: &content,
                        };
                        let identity = self.projection.validate_frozen_entry_unchanged(&entry)?;
                        if identity != *expected_identity {
                            let path = validate_projection_proof_path(&artifact.path)?;
                            return Err(KinError::Other(format!(
                                "tracked working-copy path {} changed object identity after exact projection verification",
                                self.projection.display_root.join(&path.relative).display()
                            )));
                        }
                    }
                }
            }
            self.revalidate_namespace()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (verification, tree, blobs);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Revalidate the exact projection and atomically move the retained `.kin`
    /// directory into `target/destination_name` without replacement.
    ///
    /// This consumes the guard so its kernel lock remains held through the
    /// identity-checked move and is released only after `.kin` is detached.
    pub fn detach_verified_to<'a>(
        self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
        target: &ExactProjectionDetachTarget,
        destination_name: &std::ffi::OsStr,
    ) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_resolved_tree(verification, tree, entries)?;
            self.detach_after_revalidation(target, destination_name)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (verification, tree, entries, target, destination_name);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Bounded-memory variant of [`Self::detach_verified_to`].
    pub fn detach_verified_to_from_blobs(
        self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
        target: &ExactProjectionDetachTarget,
        destination_name: &std::ffi::OsStr,
    ) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.revalidate_resolved_tree_from_blobs(verification, tree, blobs)?;
            self.detach_after_revalidation(target, destination_name)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (verification, tree, blobs, target, destination_name);
            Err(unsupported_safe_projection_error())
        }
    }

    /// Replace the frozen projection's `.git` entry with one fully prepared
    /// staged Git directory, archive any prior regular-file or directory
    /// `.git`, and detach `.kin` as one retained-capability transaction.
    ///
    /// Every namespace move is no-replace, identity checked, and parent synced.
    /// Any failure after the first move rolls back in reverse order through the
    /// retained root, archive, and stage capabilities. The staged repository
    /// must be fully verified and durably synced before
    /// [`ExactProjectionGitStage::open_existing`] is called.
    ///
    /// Windows currently returns an unsupported error before the first
    /// mutation: `MoveFileExW(MOVEFILE_WRITE_THROUGH)` is path-authorized, while
    /// the retained-handle rename API does not expose an equivalent durable
    /// directory-namespace guarantee.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_git_and_detach_verified_to_from_blobs(
        self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
        staged_git: ExactProjectionGitStage,
        target: &ExactProjectionDetachTarget,
        archived_kin_name: &std::ffi::OsStr,
        archived_git_name: &std::ffi::OsStr,
    ) -> Result<ExactProjectionEjectOutcome> {
        #[cfg(unix)]
        {
            self.replace_git_and_detach_verified_to_from_blobs_with_hook(
                verification,
                tree,
                blobs,
                staged_git,
                target,
                archived_kin_name,
                archived_git_name,
                |_| {},
            )
        }
        #[cfg(windows)]
        {
            let _ = (
                self,
                verification,
                tree,
                blobs,
                staged_git,
                target,
                archived_kin_name,
                archived_git_name,
            );
            Err(KinError::Other(
                "capability-anchored exact Git replacement is unsupported on Windows until durable no-replace directory namespace moves are available"
                    .to_string(),
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (
                self,
                verification,
                tree,
                blobs,
                staged_git,
                target,
                archived_kin_name,
                archived_git_name,
            );
            Err(unsupported_safe_projection_error())
        }
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn replace_git_and_detach_verified_to_from_blobs_with_hook(
        self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
        staged_git: ExactProjectionGitStage,
        target: &ExactProjectionDetachTarget,
        archived_kin_name: &std::ffi::OsStr,
        archived_git_name: &std::ffi::OsStr,
        mut hook: impl FnMut(ExactProjectionEjectHookPoint),
    ) -> Result<ExactProjectionEjectOutcome> {
        validate_exact_namespace_component("archived Kin", archived_kin_name)?;
        validate_exact_namespace_component("archived Git", archived_git_name)?;
        if archived_kin_name == archived_git_name {
            return Err(KinError::Other(
                "archived Kin and Git destinations must be distinct".to_string(),
            ));
        }

        self.revalidate_resolved_tree_from_blobs(verification, tree, blobs)?;
        target.revalidate()?;
        staged_git.revalidate_named()?;
        self.validate_distinct_eject_capabilities(&staged_git, target)?;

        let previous_git = self.projection.open_optional_retained_git_entry(
            std::ffi::OsStr::new(".git"),
            &self.projection.display_root.join(".git"),
        )?;
        ensure_named_entry_absent(
            &target.directory,
            archived_kin_name,
            &target.display_path.join(archived_kin_name),
        )?;
        ensure_named_entry_absent(
            &target.directory,
            archived_git_name,
            &target.display_path.join(archived_git_name),
        )?;
        let mut eject_journal = self.prepare_exact_eject_journal(
            &staged_git,
            target,
            archived_kin_name,
            archived_git_name,
            previous_git.as_ref(),
        )?;
        self.projection
            .persist_exact_eject_journal(&eject_journal, true)?;

        let mut previous_git_archived = false;
        let mut staged_git_installed = false;
        let mut kin_detached = false;
        let transaction = (|| {
            hook(ExactProjectionEjectHookPoint::BeforeNamespaceMutation);
            self.revalidate_resolved_tree_from_blobs(verification, tree, blobs)?;
            target.revalidate()?;
            staged_git.revalidate_named()?;
            if let Some(previous) = previous_git.as_ref() {
                self.projection.validate_retained_git_entry_at(
                    previous,
                    &self.projection.root,
                    std::ffi::OsStr::new(".git"),
                    &self.projection.display_root.join(".git"),
                )?;
            } else {
                ensure_named_entry_absent(
                    &self.projection.root,
                    std::ffi::OsStr::new(".git"),
                    &self.projection.display_root.join(".git"),
                )?;
            }
            ensure_named_entry_absent(
                &target.directory,
                archived_kin_name,
                &target.display_path.join(archived_kin_name),
            )?;
            ensure_named_entry_absent(
                &target.directory,
                archived_git_name,
                &target.display_path.join(archived_git_name),
            )?;

            eject_journal.phase = ExactEjectJournalPhase::PreviousGitMovePending;
            self.projection
                .persist_exact_eject_journal(&eject_journal, false)?;
            if let Some(previous) = previous_git.as_ref() {
                // Record intent before entering a helper whose post-rename
                // validation can fail after an uncertain internal restore.
                // A conservative outer rollback may then retain the journal,
                // but it must never delete the only durable recovery proof.
                previous_git_archived = true;
                self.projection.move_retained_git_entry_exact(
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".git"),
                    },
                    NamedEntryLocation {
                        parent: &target.directory,
                        name: archived_git_name,
                    },
                    previous,
                    &self.projection.display_root.join(".git"),
                )?;
            }
            hook(ExactProjectionEjectHookPoint::AfterPreviousGitArchived);

            eject_journal.phase = ExactEjectJournalPhase::StageInstallPending;
            self.projection
                .persist_exact_eject_journal(&eject_journal, false)?;
            staged_git_installed = true;
            self.projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &staged_git.parent,
                        name: &staged_git.name,
                    },
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".git"),
                    },
                    &staged_git.directory,
                    staged_git.identity,
                    &staged_git.display_path,
                )?;
            hook(ExactProjectionEjectHookPoint::AfterStagedGitInstalled);

            // Moving `.git` is outside the repository tree proof, but the full
            // graph-owned tree and `.kin` lock namespace are rechecked after
            // that move and immediately before detachment.
            self.revalidate_resolved_tree_from_blobs(verification, tree, blobs)?;
            target.revalidate()?;
            staged_git.revalidate_parent()?;
            self.validate_installed_git(&staged_git)?;

            eject_journal.phase = ExactEjectJournalPhase::DetachPending;
            self.projection
                .persist_exact_eject_journal(&eject_journal, false)?;
            kin_detached = true;
            self.projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".kin"),
                    },
                    NamedEntryLocation {
                        parent: &target.directory,
                        name: archived_kin_name,
                    },
                    &self.projection.kin_control,
                    self.projection.kin_control_identity,
                    &self.projection.display_root.join(".kin"),
                )?;
            hook(ExactProjectionEjectHookPoint::AfterKinDetached);

            self.revalidate_resolved_tree_from_blobs_retained(verification, tree, blobs)?;
            self.revalidate_visible_root()?;
            target.revalidate()?;
            staged_git.revalidate_parent()?;
            self.validate_installed_git(&staged_git)?;
            self.validate_detached_kin(target, archived_kin_name)?;
            if let Some(previous) = previous_git.as_ref() {
                self.projection.validate_retained_git_entry_at(
                    previous,
                    &target.directory,
                    archived_git_name,
                    &target.display_path.join(archived_git_name),
                )?;
            }
            Ok(())
        })();

        if let Err(error) = transaction {
            let (mut error, rollback_complete) = self.rollback_exact_eject(
                error,
                &staged_git,
                target,
                archived_kin_name,
                archived_git_name,
                previous_git.as_ref(),
                kin_detached,
                staged_git_installed,
                previous_git_archived,
            );
            if rollback_complete {
                if let Err(cleanup) = self.projection.remove_exact_eject_journal(
                    &eject_journal,
                    &self
                        .projection
                        .reconciliation_control_path()
                        .join(EXACT_EJECT_JOURNAL_FILE),
                ) {
                    error = KinError::Other(format!(
                        "{error}; exact eject rollback completed but durable journal cleanup failed: {cleanup}"
                    ));
                }
            }
            return Err(error);
        }

        // The transaction is complete: the staged Git is installed at the root,
        // the previous Git is archived, and `.kin` is detached into the archive
        // with this handle still open on its reconciliation directory. The
        // journal exists to recover a transaction that dies part way, and a
        // finished one has nothing to recover, so it is retired here rather
        // than left in the archive. Left there it made the archive a trap: a
        // `.kin` copied back out of it carried a journal bound to inodes the
        // copy did not have, every projection open after that refused, and the
        // only exit a stranger found on 0.5.52 was deleting the store
        // (FIR-2664).
        let archived_journal = target
            .display_path
            .join(archived_kin_name)
            .join(RECONCILIATION_CONTROL_DIRECTORY)
            .join(EXACT_EJECT_JOURNAL_FILE);
        let retained_journal = self
            .projection
            .remove_exact_eject_journal(&eject_journal, &archived_journal)
            .err()
            .map(|error| {
                format!(
                    "the eject completed, but its journal could not be retired and remains at {}: \
                     {error}. Remove that file before reusing the archived kin/ directory",
                    archived_journal.display()
                )
            });

        Ok(ExactProjectionEjectOutcome {
            had_previous_git: previous_git.is_some(),
            retained_journal,
        })
    }

    #[cfg(unix)]
    fn validate_distinct_eject_capabilities(
        &self,
        staged_git: &ExactProjectionGitStage,
        target: &ExactProjectionDetachTarget,
    ) -> Result<()> {
        if staged_git.identity == self.root_identity
            || staged_git.identity == self.projection.kin_control_identity
            || staged_git.identity == target.identity
            || target.identity == self.root_identity
            || target.identity == self.projection.kin_control_identity
        {
            return Err(KinError::Other(
                "eject root, staged Git, archive, and Kin control directories must be distinct"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn prepare_exact_eject_journal(
        &self,
        staged_git: &ExactProjectionGitStage,
        target: &ExactProjectionDetachTarget,
        archived_kin_name: &std::ffi::OsStr,
        archived_git_name: &std::ffi::OsStr,
        previous_git: Option<&RetainedGitEntry>,
    ) -> Result<ExactEjectJournal> {
        use std::os::unix::ffi::OsStrExt as _;

        let (namespace_parent, actual_root_name) = self.projection.locate_open_directory(
            &self.projection.root,
            self.root_identity,
            &self.projection.display_root,
        )?;
        let namespace_parent_identity = tracked_open_directory_identity(&namespace_parent)
            .map_err(|error| KinError::io(&self.projection.display_root, error))?;
        let expected_root_name = self.projection.display_root.file_name().ok_or_else(|| {
            KinError::Other(format!(
                "projection root has no namespace name: {}",
                self.projection.display_root.display()
            ))
        })?;
        if actual_root_name != expected_root_name {
            return Err(KinError::Other(format!(
                "projection root {} is not linked under its expected namespace name",
                self.projection.display_root.display()
            )));
        }
        if tracked_open_directory_identity(&target.parent)
            .map_err(|error| KinError::io(&target.parent_display_path, error))?
            != namespace_parent_identity
        {
            return Err(KinError::Other(
                "exact eject archive must be a direct sibling of the projection root".to_string(),
            ));
        }

        let root_parent_display = self.projection.display_root.parent().ok_or_else(|| {
            KinError::Other(format!(
                "projection root has no parent: {}",
                self.projection.display_root.display()
            ))
        })?;
        let stage_relative = staged_git
            .parent_display_path
            .strip_prefix(root_parent_display)
            .map_err(|_| {
                KinError::Other(format!(
                    "staged Git parent {} must remain beneath projection namespace parent {}",
                    staged_git.parent_display_path.display(),
                    root_parent_display.display()
                ))
            })?;
        let stage_parent_components =
            exact_relative_directory_components(stage_relative, "staged Git parent")?;
        let reopened_stage_parent = open_exact_relative_directory_components(
            &namespace_parent,
            &stage_parent_components,
            &staged_git.parent_display_path,
        )?;
        if tracked_open_directory_identity(&reopened_stage_parent)
            .map_err(|error| KinError::io(&staged_git.parent_display_path, error))?
            != staged_git.parent_identity
        {
            return Err(KinError::Other(format!(
                "staged Git parent {} is not identity-bound beneath the projection namespace",
                staged_git.parent_display_path.display()
            )));
        }

        Ok(ExactEjectJournal {
            schema: EXACT_EJECT_JOURNAL_SCHEMA,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            phase: ExactEjectJournalPhase::Prepared,
            root_identity: self.root_identity,
            kin_control_identity: self.projection.kin_control_identity,
            control_identity: self.projection.control_identity,
            namespace_parent_identity,
            root_name: actual_root_name.as_bytes().to_vec(),
            archive_name: target.name.as_bytes().to_vec(),
            archive_identity: target.identity,
            stage_parent_components,
            stage_parent_identity: staged_git.parent_identity,
            stage_name: staged_git.name.as_bytes().to_vec(),
            stage_identity: staged_git.identity,
            stage_seal: staged_git.seal,
            archived_kin_name: archived_kin_name.as_bytes().to_vec(),
            archived_git_name: archived_git_name.as_bytes().to_vec(),
            previous_git: previous_git.map(RetainedGitEntry::journal_descriptor),
        })
    }

    #[cfg(unix)]
    fn validate_installed_git(&self, staged_git: &ExactProjectionGitStage) -> Result<()> {
        let named = open_directory_nofollow(&self.projection.root, std::ffi::OsStr::new(".git"))
            .map_err(|error| KinError::io(self.projection.display_root.join(".git"), error))?;
        if tracked_open_directory_identity(&named)
            .map_err(|error| KinError::io(self.projection.display_root.join(".git"), error))?
            != staged_git.identity
            || tracked_open_directory_identity(&staged_git.directory)
                .map_err(|error| KinError::io(&staged_git.display_path, error))?
                != staged_git.identity
        {
            return Err(KinError::Other(format!(
                "installed Git directory {} changed identity during exact eject",
                self.projection.display_root.join(".git").display()
            )));
        }
        let seal = seal_exact_git_directory(
            &staged_git.directory,
            &self.projection.display_root.join(".git"),
        )?;
        if seal != staged_git.seal {
            return Err(KinError::Other(format!(
                "installed Git directory {} changed descendants after exact sealing",
                self.projection.display_root.join(".git").display()
            )));
        }
        if let (Some(proof), Some(expected_tree)) = (&staged_git.proof, &staged_git.expected_tree) {
            kin_git::verify_repository_git_export(
                &self.projection.display_root.join(".git"),
                proof,
                expected_tree,
            )
            .map_err(|error| {
                KinError::Other(format!(
                    "installed Git repository failed post-move repository-v6 proof: {error}"
                ))
            })?;
            let revalidated = seal_exact_git_directory(
                &staged_git.directory,
                &self.projection.display_root.join(".git"),
            )?;
            if revalidated != staged_git.seal {
                return Err(KinError::Other(format!(
                    "installed Git directory {} changed during post-move semantic proof",
                    self.projection.display_root.join(".git").display()
                )));
            }
        }
        Ok(())
    }

    #[cfg(any(unix, windows))]
    fn validate_detached_kin(
        &self,
        target: &ExactProjectionDetachTarget,
        archived_kin_name: &std::ffi::OsStr,
    ) -> Result<()> {
        let display = target.display_path.join(archived_kin_name);
        let named = open_directory_nofollow(&target.directory, archived_kin_name)
            .map_err(|error| KinError::io(&display, error))?;
        if tracked_open_directory_identity(&named).map_err(|error| KinError::io(&display, error))?
            != self.projection.kin_control_identity
            || tracked_open_directory_identity(&self.projection.kin_control)
                .map_err(|error| KinError::io(&display, error))?
                != self.projection.kin_control_identity
        {
            return Err(KinError::Other(format!(
                "detached Kin control directory {} changed identity",
                display.display()
            )));
        }
        self.projection.revalidate_retained_projection_control()
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn rollback_exact_eject(
        &self,
        error: KinError,
        staged_git: &ExactProjectionGitStage,
        target: &ExactProjectionDetachTarget,
        archived_kin_name: &std::ffi::OsStr,
        archived_git_name: &std::ffi::OsStr,
        previous_git: Option<&RetainedGitEntry>,
        kin_detached: bool,
        staged_git_installed: bool,
        previous_git_archived: bool,
    ) -> (KinError, bool) {
        let mut rollback_errors = Vec::new();
        if kin_detached {
            if let Err(rollback) = self
                .projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &target.directory,
                        name: archived_kin_name,
                    },
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".kin"),
                    },
                    &self.projection.kin_control,
                    self.projection.kin_control_identity,
                    &self.projection.display_root.join(".kin"),
                )
            {
                rollback_errors.push(format!("restore `.kin`: {rollback}"));
            }
        }
        if staged_git_installed {
            if let Err(rollback) = self
                .projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".git"),
                    },
                    NamedEntryLocation {
                        parent: &staged_git.parent,
                        name: &staged_git.name,
                    },
                    &staged_git.directory,
                    staged_git.identity,
                    &staged_git.display_path,
                )
            {
                rollback_errors.push(format!("restore staged `.git`: {rollback}"));
            }
        }
        if previous_git_archived {
            if let Some(previous) = previous_git {
                if let Err(rollback) = self.projection.move_retained_git_entry_exact(
                    NamedEntryLocation {
                        parent: &target.directory,
                        name: archived_git_name,
                    },
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".git"),
                    },
                    previous,
                    &self.projection.display_root.join(".git"),
                ) {
                    rollback_errors.push(format!("restore previous `.git`: {rollback}"));
                }
            }
        }
        if rollback_errors.is_empty() {
            (error, true)
        } else {
            (
                KinError::Other(format!(
                    "{error}; retained-capability eject rollback also failed: {}",
                    rollback_errors.join("; ")
                )),
                false,
            )
        }
    }

    #[cfg(unix)]
    fn revalidate_resolved_tree_from_blobs_retained(
        &self,
        verification: &ExactProjectionVerification,
        tree: &ResolvedTree,
        blobs: &kin_blobs::BlobStore,
    ) -> Result<()> {
        let tree_hash =
            compute_resolved_tree_hash(tree).map_err(|error| KinError::Other(error.to_string()))?;
        if tree_hash != verification.tree_hash || tree.len() != verification.entries.len() {
            return Err(KinError::Other(
                "resolved projection tree changed after exact verification".to_string(),
            ));
        }
        if tracked_open_directory_identity(&self.projection.root)
            .map_err(|error| KinError::io(&self.projection.display_root, error))?
            != self.root_identity
        {
            return Err(KinError::Other(format!(
                "retained projection root {} changed identity",
                self.projection.display_root.display()
            )));
        }
        for (artifact, verified) in tree.artifacts_by_path().zip(verification.entries.iter()) {
            if artifact.path != verified.path || artifact.entry != verified.kind {
                return Err(KinError::Other(
                    "exact projection verification does not describe this resolved tree"
                        .to_string(),
                ));
            }
            let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
            match disposition {
                SourceProjectionDisposition::GraphOnlyGitlink
                | SourceProjectionDisposition::GraphOnlyHostUnrepresentable => self
                    .projection
                    .revalidate_frozen_graph_only(&artifact.path, disposition, &verified.proof)?,
                SourceProjectionDisposition::Materialized => {
                    let ExactProjectionEntryProof::Materialized {
                        identity: expected_identity,
                    } = &verified.proof
                    else {
                        return Err(KinError::Other(
                            "exact projection verification mixed materialized and graph-only entry proofs"
                                .to_string(),
                        ));
                    };
                    let content =
                        load_projection_proof_blob(blobs, &artifact.path, artifact.entry)?;
                    let entry = ValidatedSourceEntry {
                        file_id: &artifact.path,
                        kind: artifact.entry,
                        content: &content,
                    };
                    let identity = self.projection.validate_frozen_entry_unchanged(&entry)?;
                    if identity != *expected_identity {
                        let path = validate_projection_proof_path(&artifact.path)?;
                        return Err(KinError::Other(format!(
                            "tracked working-copy path {} changed object identity after exact projection verification",
                            self.projection.display_root.join(&path.relative).display()
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(any(unix, windows))]
    fn detach_after_revalidation(
        self,
        target: &ExactProjectionDetachTarget,
        destination_name: &std::ffi::OsStr,
    ) -> Result<()> {
        self.detach_after_revalidation_with_hook(target, destination_name, || {})
    }

    #[cfg(any(unix, windows))]
    fn detach_after_revalidation_with_hook(
        self,
        target: &ExactProjectionDetachTarget,
        destination_name: &std::ffi::OsStr,
        post_move_hook: impl FnOnce(),
    ) -> Result<()> {
        let mut components = Path::new(destination_name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(KinError::Other(format!(
                "projection detach destination is not one safe path component: {:?}",
                destination_name
            )));
        }
        target.revalidate()?;
        self.revalidate_namespace()?;
        self.projection
            .move_open_directory_from_expected_source_exact(
                NamedEntryLocation {
                    parent: &self.projection.root,
                    name: std::ffi::OsStr::new(".kin"),
                },
                NamedEntryLocation {
                    parent: &target.directory,
                    name: destination_name,
                },
                &self.projection.kin_control,
                self.projection.kin_control_identity,
                &self.projection.display_root.join(".kin"),
            )?;
        post_move_hook();
        let post_move = self
            .revalidate_visible_root()
            .and_then(|()| target.revalidate())
            .and_then(|()| self.validate_detached_kin(target, destination_name));
        if let Err(error) = post_move {
            let restoration = self
                .projection
                .move_open_directory_from_expected_source_exact(
                    NamedEntryLocation {
                        parent: &target.directory,
                        name: destination_name,
                    },
                    NamedEntryLocation {
                        parent: &self.projection.root,
                        name: std::ffi::OsStr::new(".kin"),
                    },
                    &self.projection.kin_control,
                    self.projection.kin_control_identity,
                    &self.projection.display_root.join(".kin"),
                );
            return match restoration {
                Ok(()) => Err(error),
                Err(restore_error) => Err(KinError::Other(format!(
                    "{error}; exact projection detach rollback also failed: {restore_error}"
                ))),
            };
        }
        Ok(())
    }

    #[cfg(any(unix, windows))]
    fn revalidate_visible_root(&self) -> Result<()> {
        let named_root = open_projection_root_nofollow(&self.projection.display_root)?;
        if tracked_open_directory_identity(&named_root)
            .map_err(|error| KinError::io(&self.projection.display_root, error))?
            != self.root_identity
        {
            return Err(KinError::Other(format!(
                "projection root {} was replaced while frozen",
                self.projection.display_root.display()
            )));
        }
        if tracked_open_directory_identity(&self.projection.root)
            .map_err(|error| KinError::io(&self.projection.display_root, error))?
            != self.root_identity
        {
            return Err(KinError::Other(format!(
                "retained projection root {} changed identity",
                self.projection.display_root.display()
            )));
        }
        Ok(())
    }

    #[cfg(any(unix, windows))]
    fn revalidate_namespace(&self) -> Result<()> {
        self.revalidate_visible_root()?;
        self.projection.revalidate_projection_lock()
    }
}

enum ProjectionAuthorityCommit<T> {
    Committed(T),
    DefinitelyNotCommitted(KinError),
    Indeterminate(KinError),
}

impl<T> ProjectionAuthorityCommit<T> {
    fn into_result(self) -> Result<T> {
        match self {
            Self::Committed(value) => Ok(value),
            Self::DefinitelyNotCommitted(error) | Self::Indeterminate(error) => Err(error),
        }
    }
}

const SLOW_AUTHORITY_PUBLICATION: std::time::Duration = std::time::Duration::from_millis(500);

/// Time repository authority publication and record what it cost.
///
/// The daemon times its own commit phases, but its innermost phase spans both
/// the workspace projection this crate performs and the authority publication
/// that runs inside it, so a slow commit cannot be attributed to either side
/// from the daemon log alone. Naming the publication separately splits that
/// span at the crate boundary without changing what either side does. The
/// whole helper is timed rather than its first attempt, because a caller that
/// waits through a retry waited for all of it.
fn timed_authority_publication<T>(work: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let outcome = work();
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    if elapsed >= SLOW_AUTHORITY_PUBLICATION {
        tracing::info!(elapsed_ms, "slow repository authority publication");
    } else {
        tracing::debug!(elapsed_ms, "repository authority publication");
    }
    outcome
}

fn commit_repository_transaction_exact(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> ProjectionAuthorityCommit<RepositoryCommitReceipt> {
    timed_authority_publication(|| {
        commit_repository_transaction_exact_inner(authority, transaction)
    })
}

fn commit_repository_transaction_exact_inner(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> ProjectionAuthorityCommit<RepositoryCommitReceipt> {
    let expected_hash = transaction
        .transaction_hash()
        .expect("projection transaction hash was validated before namespace mutation");
    match authority.commit_repository_transaction(transaction.clone()) {
        Ok(receipt) => ProjectionAuthorityCommit::Committed(receipt),
        Err(first_error) => {
            if let Some(receipt) =
                installed_repository_receipt(authority, transaction.operation_id, expected_hash)
            {
                return ProjectionAuthorityCommit::Committed(receipt);
            }

            match authority.commit_repository_transaction(transaction.clone()) {
                Ok(receipt) => ProjectionAuthorityCommit::Committed(receipt),
                Err(second_error) => {
                    if let Some(receipt) = installed_repository_receipt(
                        authority,
                        transaction.operation_id,
                        expected_hash,
                    ) {
                        return ProjectionAuthorityCommit::Committed(receipt);
                    }
                    let detail = format!(
                        "commit repository projection authority: {first_error}; exact retry: {second_error}"
                    );
                    if repository_commit_error_is_definitely_prepublication(&second_error) {
                        ProjectionAuthorityCommit::DefinitelyNotCommitted(
                            KinError::RepositoryConflict(detail),
                        )
                    } else {
                        ProjectionAuthorityCommit::Indeterminate(
                            KinError::RepositoryCommitIndeterminate(format!(
                                "{detail}; exact projection and authenticated recovery WAL were retained because authority commit outcome is uncertain"
                            )),
                        )
                    }
                }
            }
        }
    }
}

fn commit_repository_transaction_exact_and_freeze(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> ProjectionAuthorityCommit<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    match authority.commit_repository_transaction_and_freeze(transaction.clone()) {
        Ok(committed) => ProjectionAuthorityCommit::Committed(committed),
        Err(first_error) => match authority.commit_repository_transaction_and_freeze(transaction) {
            Ok(committed) => ProjectionAuthorityCommit::Committed(committed),
            Err(second_error) => {
                let detail = format!(
                    "commit and freeze repository projection authority: {first_error}; exact retry: {second_error}"
                );
                if repository_commit_error_is_definitely_prepublication(&second_error) {
                    ProjectionAuthorityCommit::DefinitelyNotCommitted(KinError::RepositoryConflict(
                        detail,
                    ))
                } else {
                    ProjectionAuthorityCommit::Indeterminate(
                        KinError::RepositoryCommitIndeterminate(format!(
                            "{detail}; exact projection and authenticated recovery WAL were retained because authority commit outcome is uncertain"
                        )),
                    )
                }
            }
        },
    }
}

fn installed_repository_receipt(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    operation_id: OperationId,
    transaction_hash: Hash256,
) -> Option<RepositoryCommitReceipt> {
    authority
        .read_authority()
        .metadata()
        .receipts
        .iter()
        .find(|receipt| {
            receipt.operation_id == operation_id && receipt.transaction_hash == transaction_hash
        })
        .cloned()
        .map(|mut receipt| {
            receipt.outcome = RepositoryCommitOutcome::IdempotentReplay;
            receipt
        })
}

fn repository_commit_error_is_definitely_prepublication(error: &kin_db::KinDbError) -> bool {
    matches!(
        error,
        kin_db::KinDbError::Model(_)
            | kin_db::KinDbError::NotFound(_)
            | kin_db::KinDbError::DuplicateEntity(_)
            | kin_db::KinDbError::DuplicateChange(_)
            | kin_db::KinDbError::SourceBlobReadLimitExceeded { .. }
            | kin_db::KinDbError::IncompatibleSnapshotVersion { .. }
            | kin_db::KinDbError::SerializationError(_)
            | kin_db::KinDbError::IndexError(_)
            | kin_db::KinDbError::ConcurrentAccessError(_)
            | kin_db::KinDbError::SliceConversionError(_)
    ) || matches!(
        error,
        // LocalFileBackend currently exposes its compare-and-swap miss
        // through StorageError. The backend has read a
        // different generation and returns before publishing candidate bytes,
        // so this one exact storage outcome is determinate and the projection
        // WAL must roll back. Other storage failures remain indeterminate.
        kin_db::KinDbError::StorageError(message)
            if message.starts_with("generation mismatch for repo ")
                && message.ends_with("(another writer committed since last load)")
    )
}

fn classify_repository_authority_freeze_error(
    context: &str,
    error: kin_db::KinDbError,
) -> KinError {
    match error {
        kin_db::KinDbError::Model(kin_model::ModelError::Conflict(message)) => {
            KinError::RepositoryConflict(format!("{context}: {message}"))
        }
        error => KinError::Other(format!("{context}: {error}")),
    }
}

#[derive(Clone, Copy)]
struct ValidatedSourceEntry<'a> {
    file_id: &'a RepoPath,
    kind: TreeEntry,
    content: &'a [u8],
}

struct ValidatedProjectionPath {
    components: Vec<std::ffi::OsString>,
    relative: std::path::PathBuf,
}

#[cfg(test)]
std::thread_local! {
    static INJECT_PUBLICATION_FAILURE_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inject_next_publication_failure() {
    inject_publication_failure_after(0);
}

#[cfg(test)]
fn inject_publication_failure_after(successful_publications: usize) {
    INJECT_PUBLICATION_FAILURE_AFTER.set(Some(successful_publications));
}

#[cfg(test)]
fn fail_publication_if_injected() -> Result<()> {
    INJECT_PUBLICATION_FAILURE_AFTER.with(|remaining| match remaining.get() {
        None => Ok(()),
        Some(0) => {
            remaining.set(None);
            Err(KinError::Other(
                "injected exact-source publication failure".to_string(),
            ))
        }
        Some(count) => {
            remaining.set(Some(count - 1));
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn fail_publication_if_injected() -> Result<()> {
    Ok(())
}

fn validated_source_entries<'a>(
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<Vec<ValidatedSourceEntry<'a>>> {
    let mut entries: Vec<_> = entries
        .into_iter()
        .map(|(file_id, kind, content)| ValidatedSourceEntry {
            file_id,
            kind,
            content,
        })
        .collect();
    entries.sort_by(|left, right| left.file_id.cmp(right.file_id));
    validate_source_tree(
        entries
            .iter()
            .map(|entry| (entry.file_id, entry.kind, entry.content)),
    )?;
    Ok(entries)
}

fn validated_projection_proof_entries<'a>(
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<Vec<ValidatedSourceEntry<'a>>> {
    let mut entries = entries
        .into_iter()
        .map(|(file_id, kind, content)| ValidatedSourceEntry {
            file_id,
            kind,
            content,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.file_id.cmp(right.file_id));
    validate_projection_proof_paths(entries.iter().map(|entry| entry.file_id))?;
    for entry in &entries {
        validate_projection_proof_entry_path(entry.file_id, entry.kind)?;
    }
    Ok(entries)
}

/// Validate an exact-source entry without touching the projection root.
///
/// Checkout callers use this during their global preflight so unsafe paths,
/// unsupported entry encodings, and escaping symbolic-link targets all fail
/// before any file/directory transition is applied.
pub fn validate_source_entry(file_id: &RepoPath, kind: TreeEntry, content: &[u8]) -> Result<()> {
    validate_source_entry_components(file_id, kind, content).map(|_| ())
}

fn validate_source_entry_components<'a>(
    file_id: &'a RepoPath,
    kind: TreeEntry,
    content: &[u8],
) -> Result<Vec<&'a str>> {
    let path = projection_path(file_id)?;
    let components = validate_source_path(path)?;

    if matches!(kind, TreeEntry::Symlink { .. }) {
        let target = std::str::from_utf8(content).map_err(|_| {
            KinError::Other(format!(
                "symbolic link target is not valid UTF-8 for {}",
                file_id
            ))
        })?;
        validate_source_symlink_target(&components, target)?;

        #[cfg(not(unix))]
        return Err(KinError::Other(
            "safe exact symbolic-link checkout is unsupported on this platform".to_string(),
        ));
    }
    if matches!(kind, TreeEntry::Gitlink { .. }) {
        return Err(KinError::Other(format!(
            "gitlink {file_id} is repository history, not a repository-owned source blob"
        )));
    }
    Ok(components)
}

fn validate_source_content_identity(
    file_id: &RepoPath,
    entry: TreeEntry,
    content: &[u8],
) -> Result<()> {
    let Some(expected) = entry.blob_identity() else {
        return Err(KinError::Other(format!(
            "gitlink {file_id} is repository history, not a repository-owned source blob"
        )));
    };
    let observed = Hash256::from_bytes(kin_blobs::digest_bytes(content));
    if observed != expected {
        return Err(KinError::Other(format!(
            "exact source bytes for {file_id} hash to {observed}, not tree identity {expected}"
        )));
    }
    Ok(())
}

fn validated_session_source_entries<'a>(
    base_metadata: &[u8],
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<Vec<ValidatedSourceEntry<'a>>> {
    if base_metadata.is_empty() {
        return Err(KinError::Other(
            "session projection base metadata must not be empty".to_string(),
        ));
    }
    let entries: Vec<_> = entries.into_iter().collect();
    for (path, entry, body) in &entries {
        validate_source_content_identity(path, *entry, body)?;
    }
    validated_source_entries(entries)
}

fn validate_projection_proof_entry_path(
    file_id: &RepoPath,
    _kind: TreeEntry,
) -> Result<ValidatedProjectionPath> {
    validate_projection_proof_path(file_id)
}

fn validate_projection_proof_paths<'a>(
    paths: impl IntoIterator<Item = &'a RepoPath>,
) -> Result<()> {
    let mut paths = paths
        .into_iter()
        .map(|path| {
            materializable_projection_proof_path(path)?;
            let key = if let Some(path) = path.as_utf8() {
                projection_path_comparison_key(path).into_bytes()
            } else {
                #[cfg(any(windows, target_os = "macos"))]
                {
                    let mut key = path.as_bytes().to_vec();
                    key.make_ascii_lowercase();
                    key
                }
                #[cfg(not(any(windows, target_os = "macos")))]
                {
                    path.as_bytes().to_vec()
                }
            };
            Ok((key, path))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for pair in paths.windows(2) {
        if pair[1].0 == pair[0].0
            || pair[1]
                .0
                .strip_prefix(pair[0].0.as_slice())
                .is_some_and(|suffix| suffix.starts_with(b"/"))
        {
            return Err(KinError::Other(format!(
                "conflicting graph-owned source paths {:?} and {:?}",
                pair[0].1, pair[1].1
            )));
        }
    }
    Ok(())
}

/// Return the host path for an entry that this filesystem can represent.
///
/// Git trees and Kin's graph preserve repository paths as bytes. Linux can
/// address arbitrary non-NUL byte components, while macOS rejects invalid
/// UTF-8 with `EILSEQ` and Windows has no lossless byte-path conversion. Those
/// entries remain graph-only on hosts that cannot name them: exact export
/// still binds their path, kind, and object identity, but workspace proof must
/// neither invent a lossy alias nor infer their absence as a deletion.
fn materializable_projection_proof_path(
    file_id: &RepoPath,
) -> Result<Option<ValidatedProjectionPath>> {
    if file_id.as_utf8().is_none() {
        #[cfg(any(windows, target_os = "macos"))]
        return Ok(None);
    }
    validate_projection_proof_path(file_id).map(Some)
}

fn validate_projection_proof_path(file_id: &RepoPath) -> Result<ValidatedProjectionPath> {
    if let Some(path) = file_id.as_utf8() {
        let components = validate_source_path(path)?;
        let mut relative = std::path::PathBuf::new();
        let components = components
            .into_iter()
            .map(|component| {
                relative.push(component);
                std::ffi::OsString::from(component)
            })
            .collect();
        return Ok(ValidatedProjectionPath {
            components,
            relative,
        });
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let mut relative = std::path::PathBuf::new();
        let mut components = Vec::new();
        for component in file_id.as_bytes().split(|byte| *byte == b'/') {
            if component.len() > 255
                || component.eq_ignore_ascii_case(b".kin")
                || component.eq_ignore_ascii_case(b".git")
                || component.eq_ignore_ascii_case(b".kin-session")
            {
                return Err(KinError::Other(format!(
                    "unsafe graph-owned source path {file_id}"
                )));
            }
            let component = std::ffi::OsStr::from_bytes(component).to_os_string();
            relative.push(&component);
            components.push(component);
        }
        Ok(ValidatedProjectionPath {
            components,
            relative,
        })
    }

    #[cfg(any(not(unix), target_os = "macos"))]
    {
        Err(KinError::Other(format!(
            "byte-exact repository path {file_id} cannot be verified by this filesystem boundary"
        )))
    }
}

fn projection_path(path: &RepoPath) -> Result<&str> {
    path.as_utf8().ok_or_else(|| {
        KinError::Other(format!(
            "byte-exact repository path {path} cannot be projected by this UTF-8 filesystem boundary"
        ))
    })
}

/// Validate a complete exact-source tree without mutating the filesystem.
///
/// In addition to validating every entry kind and symbolic-link target, this
/// rejects path-prefix conflicts such as `a` and `a/b` before callers remove a
/// blocking file or directory.
pub fn validate_source_tree<'a>(
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<()> {
    let entries: Vec<_> = entries.into_iter().collect();
    validate_source_paths(entries.iter().map(|(file_id, _, _)| *file_id))?;
    for (file_id, kind, content) in entries {
        validate_source_entry(file_id, kind, content)?;
    }
    Ok(())
}

/// Validate a complete exact-source path set without retaining source bytes.
///
/// Authority preflights that read blobs from a remote store use this before
/// validating each entry one at a time. Keeping path-shape validation separate
/// from byte validation prevents a repository-sized second copy of the source
/// tree from accumulating in memory merely to detect path-prefix conflicts.
pub fn validate_source_paths<'a>(file_ids: impl IntoIterator<Item = &'a RepoPath>) -> Result<()> {
    validate_source_path_set(file_ids)
}

/// Validate paths for a portable exact-source artifact regardless of the host
/// running the validator. This applies the conservative Windows component
/// rules plus Unicode normalization/case alias detection used by default
/// Windows and macOS filesystems, so an archive accepted on Linux cannot
/// collapse or overwrite entries when extracted elsewhere.
pub fn validate_portable_source_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut paths: Vec<_> = paths
        .into_iter()
        .map(|path| (portable_source_path_comparison_key(path), path))
        .collect();
    paths.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (_, path) in &paths {
        validate_portable_source_path(path)?;
    }
    for pair in paths.windows(2) {
        if pair[1].0 == pair[0].0
            || pair[1]
                .0
                .strip_prefix(&pair[0].0)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(KinError::Other(format!(
                "conflicting graph-owned source paths {:?} and {:?}",
                pair[0].1, pair[1].1
            )));
        }
    }
    Ok(())
}

/// Validate one portable relative symlink using the same cross-platform path
/// rules as [`validate_portable_source_paths`].
pub fn validate_portable_source_symlink(path: &str, target: &str) -> Result<()> {
    let components = validate_portable_source_path(path)?;
    validate_source_symlink_target_with_windows_rules(&components, target, true)
}

/// Validate a complete exact-source path set and remove only filesystem
/// objects whose shape blocks materialization (file-as-parent or
/// directory-as-file).
pub fn prepare_source_tree<'a>(
    root: &Path,
    file_ids: impl IntoIterator<Item = &'a RepoPath>,
) -> Result<()> {
    let file_ids: Vec<_> = file_ids.into_iter().collect();
    validate_source_paths(file_ids.iter().copied())?;

    #[cfg(any(unix, windows))]
    {
        let projection = ProjectionRoot::open(root)?;
        projection.prepare(&file_ids)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        Err(unsupported_safe_projection_error())
    }
}

fn validate_source_path_set<'a>(file_ids: impl IntoIterator<Item = &'a RepoPath>) -> Result<()> {
    let mut paths = Vec::new();
    for file_id in file_ids {
        let path = projection_path(file_id)?;
        paths.push((projection_path_comparison_key(path), path));
    }
    paths.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (_, path) in &paths {
        validate_source_path(path)?;
    }
    for pair in paths.windows(2) {
        if pair[1].0 == pair[0].0
            || pair[1]
                .0
                .strip_prefix(&pair[0].0)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(KinError::Other(format!(
                "conflicting graph-owned source paths {:?} and {:?}",
                pair[0].1, pair[1].1
            )));
        }
    }
    Ok(())
}

fn projection_path_comparison_key(path: &str) -> String {
    #[cfg(any(windows, target_os = "macos"))]
    {
        // Windows and the default macOS filesystem are case-insensitive, and
        // macOS also aliases canonically equivalent Unicode spellings. Build a
        // conservative per-component key using canonical decomposition and
        // Unicode case expansion so those trees fail before any transition is
        // applied. Upper-then-lower also catches folds such as sharp-s and the
        // Greek final sigma that lowercase alone does not collapse.
        path.split('/')
            .map(projection_component_comparison_key)
            .collect::<Vec<_>>()
            .join("/")
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    path.to_string()
}

fn portable_source_path_comparison_key(path: &str) -> String {
    path.split('/')
        .map(projection_component_comparison_key)
        .collect::<Vec<_>>()
        .join("/")
}

fn projection_component_comparison_key(component: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    component
        .nfd()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .nfd()
        .collect()
}

fn project_validated_source_tree(
    root: &Path,
    entries: &[ValidatedSourceEntry<'_>],
    should_preserve: Option<&dyn Fn(&Path) -> bool>,
    after_read_only_preflight: impl FnOnce(),
) -> Result<usize> {
    #[cfg(any(unix, windows))]
    {
        let projection = ProjectionRoot::open(root)?;
        let tracked = TrackedPathClassifier::new(entries.iter().map(|entry| entry.file_id))?;
        let plan = projection.plan_full_replacement(&tracked, should_preserve)?;

        // Tests use this boundary to deterministically swap ambient pathnames
        // after validation and cleanup discovery. All later work must remain
        // anchored to `projection.root`.
        after_read_only_preflight();

        projection.apply_full_replacement(entries, plan)?;
        Ok(entries.len())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, entries, should_preserve, after_read_only_preflight);
        Err(unsupported_safe_projection_error())
    }
}

#[cfg(test)]
fn project_validated_session_source_tree(
    root: &Path,
    entries: &[ValidatedSourceEntry<'_>],
    base_metadata: &[u8],
) -> Result<usize> {
    #[cfg(any(unix, windows))]
    {
        let projection = ProjectionRoot::open_session(root)?;
        let tracked = TrackedPathClassifier::new(entries.iter().map(|entry| entry.file_id))?;
        let plan = projection.plan_full_replacement(&tracked, None)?;
        projection.apply_full_replacement(entries, plan)?;
        projection.install_session_base_metadata(base_metadata)?;
        Ok(entries.len())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, entries, base_metadata);
        Err(unsupported_safe_projection_error())
    }
}

fn project_reconciled_source_tree(
    root: &Path,
    previous_entries: &[ValidatedSourceEntry<'_>],
    entries: &[ValidatedSourceEntry<'_>],
    should_preserve: &dyn Fn(&Path) -> bool,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
) -> Result<usize> {
    project_reconciled_source_tree_and_commit(
        root,
        previous_entries,
        entries,
        should_preserve,
        ReconciledProjectionOptions::default(),
        after_read_only_preflight,
        after_identity_revalidation,
        || {},
        None,
        None,
        || ProjectionAuthorityCommit::Committed(()),
    )
    .map(|(count, ())| count)
}

#[derive(Clone, Copy)]
enum ProjectionOpenMode<'a> {
    CreateOrOpen,
    #[cfg(test)]
    ExistingFrozen,
    ExistingRepositoryFrozen(&'a RepositoryAuthorityManager<LocalFileBackend>),
}

#[derive(Clone, Copy)]
struct GraphOnlyWorkspaceTransition<'a> {
    previous_tree: &'a ResolvedTree,
    target_tree: &'a ResolvedTree,
    scope: Option<&'a RepoPath>,
}

struct ReconciledProjectionOptions<'a> {
    open_mode: ProjectionOpenMode<'a>,
    graph_only_transition: Option<GraphOnlyWorkspaceTransition<'a>>,
    checkout_scope: Option<&'a RepoPath>,
    checkout_projection_authority: Option<CheckoutProjectionAuthority<'a>>,
    checkout_projection_freeze: Option<&'a mut Option<LocalRepositoryAuthorityFreeze>>,
}

impl Default for ReconciledProjectionOptions<'_> {
    fn default() -> Self {
        Self {
            open_mode: ProjectionOpenMode::CreateOrOpen,
            graph_only_transition: None,
            checkout_scope: None,
            checkout_projection_authority: None,
            checkout_projection_freeze: None,
        }
    }
}

#[derive(Clone, Copy)]
struct CheckoutProjectionAuthority<'a> {
    authority: &'a RepositoryAuthorityManager<LocalFileBackend>,
    receipt: &'a CheckoutProjectionReceipt,
}

#[cfg(any(unix, windows))]
struct GraphOnlyWorkspaceTransitionVerification {
    before_mutation: Vec<VerifiedGraphOnlyState>,
    retained_after_mutation: Vec<VerifiedGraphOnlyState>,
    absent_after_mutation: Vec<(RepoPath, SourceProjectionDisposition)>,
    must_create_directories: HashSet<PathBuf>,
}

#[cfg(any(unix, windows))]
struct VerifiedGraphOnlyState {
    path: RepoPath,
    disposition: SourceProjectionDisposition,
    proof: ExactProjectionEntryProof,
}

#[cfg(any(unix, windows))]
enum PreviousProjectionState {
    Exact {
        identity: TrackedEntryIdentity,
    },
    CheckoutAbsent,
    CheckoutObject {
        relative: PathBuf,
        kind: ExistingObjectKind,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
    },
}

#[cfg(any(unix, windows))]
impl GraphOnlyWorkspaceTransitionVerification {
    fn verify(
        projection: &ProjectionRoot,
        previous_tree: &ResolvedTree,
        target_tree: &ResolvedTree,
        scope: Option<&RepoPath>,
    ) -> Result<Self> {
        validate_projection_proof_paths(
            previous_tree
                .artifacts_by_path()
                .map(|artifact| &artifact.path),
        )?;
        validate_projection_proof_paths(
            target_tree
                .artifacts_by_path()
                .map(|artifact| &artifact.path),
        )?;

        let mut before_mutation = Vec::new();
        let mut retained_after_mutation = Vec::new();
        let mut absent_after_mutation = Vec::new();
        let mut must_create_directories = HashSet::new();

        for artifact in previous_tree.artifacts_by_path() {
            if scope
                .is_some_and(|scope| !repository_path_is_same_or_descendant(&artifact.path, scope))
            {
                continue;
            }
            let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
            if disposition == SourceProjectionDisposition::Materialized {
                continue;
            }
            let proof = projection.verify_frozen_graph_only(&artifact.path, disposition)?;
            let exact_target_disposition = tree_entry_at_path(target_tree, &artifact.path)
                .map(|entry| source_projection_disposition(&artifact.path, entry))
                .transpose()?;
            let stable_graph_only_path = exact_target_disposition == Some(disposition);
            let target_reuses_path = !stable_graph_only_path
                && tree_has_related_repository_path(target_tree, &artifact.path);
            if target_reuses_path && !graph_only_proof_is_absent(&proof) {
                return Err(KinError::Other(format!(
                    "graph-only path {} has retained host state that cannot be traversed or relabeled by a related repository tree transition",
                    artifact.path
                )));
            }
            if target_reuses_path && tree_has_materialized_descendant(target_tree, &artifact.path)?
            {
                if let Some(path) = materializable_projection_proof_path(&artifact.path)? {
                    must_create_directories.insert(path.relative);
                }
            }

            let verified = VerifiedGraphOnlyState {
                path: artifact.path.clone(),
                disposition,
                proof,
            };
            if stable_graph_only_path || !target_reuses_path {
                retained_after_mutation.push(VerifiedGraphOnlyState {
                    path: verified.path.clone(),
                    disposition,
                    proof: clone_graph_only_proof(&verified.proof)?,
                });
            }
            before_mutation.push(verified);
        }

        for artifact in target_tree.artifacts_by_path() {
            if scope
                .is_some_and(|scope| !repository_path_is_same_or_descendant(&artifact.path, scope))
            {
                continue;
            }
            let disposition = source_projection_disposition(&artifact.path, artifact.entry)?;
            if disposition == SourceProjectionDisposition::Materialized {
                continue;
            }
            let exact_previous_disposition = tree_entry_at_path(previous_tree, &artifact.path)
                .map(|entry| source_projection_disposition(&artifact.path, entry))
                .transpose()?;
            if exact_previous_disposition == Some(disposition) {
                continue;
            }
            if tree_has_related_repository_path(previous_tree, &artifact.path) {
                absent_after_mutation.push((artifact.path.clone(), disposition));
                continue;
            }

            let proof = projection.verify_frozen_graph_only(&artifact.path, disposition)?;
            retained_after_mutation.push(VerifiedGraphOnlyState {
                path: artifact.path.clone(),
                disposition,
                proof: clone_graph_only_proof(&proof)?,
            });
            before_mutation.push(VerifiedGraphOnlyState {
                path: artifact.path.clone(),
                disposition,
                proof,
            });
        }

        Ok(Self {
            before_mutation,
            retained_after_mutation,
            absent_after_mutation,
            must_create_directories,
        })
    }

    fn revalidate_before_mutation(&self, projection: &ProjectionRoot) -> Result<()> {
        for verified in &self.before_mutation {
            projection.revalidate_frozen_graph_only(
                &verified.path,
                verified.disposition,
                &verified.proof,
            )?;
        }
        Ok(())
    }

    fn revalidate_after_mutation(&self, projection: &ProjectionRoot) -> Result<()> {
        for verified in &self.retained_after_mutation {
            projection.revalidate_frozen_graph_only(
                &verified.path,
                verified.disposition,
                &verified.proof,
            )?;
        }
        for (path, disposition) in &self.absent_after_mutation {
            let actual = projection.verify_frozen_graph_only(path, *disposition)?;
            if !graph_only_proof_is_absent(&actual) {
                return Err(KinError::Other(format!(
                    "graph-only target {path} was not absent after exact workspace transition",
                )));
            }
        }
        Ok(())
    }
}

fn tree_has_materialized_descendant(tree: &ResolvedTree, ancestor: &RepoPath) -> Result<bool> {
    for artifact in tree.artifacts_by_path() {
        if artifact
            .path
            .as_bytes()
            .strip_prefix(ancestor.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
            && source_projection_disposition(&artifact.path, artifact.entry)?
                == SourceProjectionDisposition::Materialized
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(unix, windows))]
fn graph_only_proof_is_absent(proof: &ExactProjectionEntryProof) -> bool {
    matches!(
        proof,
        ExactProjectionEntryProof::GitlinkAbsent
            | ExactProjectionEntryProof::HostUnrepresentableAbsent
    )
}

#[cfg(any(unix, windows))]
fn clone_graph_only_proof(proof: &ExactProjectionEntryProof) -> Result<ExactProjectionEntryProof> {
    match proof {
        ExactProjectionEntryProof::GitlinkAbsent => Ok(ExactProjectionEntryProof::GitlinkAbsent),
        ExactProjectionEntryProof::HostUnrepresentableAbsent => {
            Ok(ExactProjectionEntryProof::HostUnrepresentableAbsent)
        }
        ExactProjectionEntryProof::GitlinkDirectory {
            directory,
            identity,
        } => Ok(ExactProjectionEntryProof::GitlinkDirectory {
            directory: directory
                .try_clone()
                .map_err(|error| KinError::Other(format!("retain graph-only Gitlink: {error}")))?,
            identity: *identity,
        }),
        ExactProjectionEntryProof::Materialized { .. } => Err(KinError::Other(
            "graph-only workspace transition received a materialized proof".to_string(),
        )),
    }
}

fn tree_entry_at_path(tree: &ResolvedTree, path: &RepoPath) -> Option<TreeEntry> {
    tree.artifacts_by_path()
        .find(|artifact| &artifact.path == path)
        .map(|artifact| artifact.entry)
}

fn tree_has_related_repository_path(tree: &ResolvedTree, path: &RepoPath) -> bool {
    tree.artifacts_by_path()
        .any(|artifact| repository_paths_are_related(&artifact.path, path))
}

fn repository_paths_are_related(left: &RepoPath, right: &RepoPath) -> bool {
    repository_path_is_same_or_descendant(left, right)
        || repository_path_is_same_or_descendant(right, left)
}

fn repository_path_is_same_or_descendant(path: &RepoPath, ancestor: &RepoPath) -> bool {
    path == ancestor
        || path
            .as_bytes()
            .strip_prefix(ancestor.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

#[allow(clippy::too_many_arguments)]
fn project_reconciled_source_tree_and_commit<T>(
    root: &Path,
    previous_entries: &[ValidatedSourceEntry<'_>],
    entries: &[ValidatedSourceEntry<'_>],
    should_preserve: &dyn Fn(&Path) -> bool,
    options: ReconciledProjectionOptions<'_>,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    after_projection_mutation: impl FnOnce(),
    authority_commit: Option<ReconciliationAuthorityCommit>,
    checkout_projection_commit: Option<CheckoutProjectionReceipt>,
    commit: impl FnOnce() -> ProjectionAuthorityCommit<T>,
) -> Result<(usize, T)> {
    #[cfg(any(unix, windows))]
    {
        let frozen = match options.open_mode {
            ProjectionOpenMode::CreateOrOpen => None,
            #[cfg(test)]
            ProjectionOpenMode::ExistingFrozen => Some(
                ExactProjectionFreeze::acquire_existing_for_transition(root)?,
            ),
            ProjectionOpenMode::ExistingRepositoryFrozen(authority) => Some(
                ExactProjectionFreeze::acquire_existing_for_repository_transition(root, authority)?,
            ),
        };
        let opened = match options.open_mode {
            ProjectionOpenMode::CreateOrOpen => Some(ProjectionRoot::open(root)?),
            #[cfg(test)]
            ProjectionOpenMode::ExistingFrozen => None,
            ProjectionOpenMode::ExistingRepositoryFrozen(_) => None,
        };
        let projection = frozen
            .as_ref()
            .map(|freeze| &freeze.projection)
            .or(opened.as_ref())
            .expect("one projection authority is open");
        let checkout_scope = options.checkout_scope;
        let mut checkout_authority_freeze = options
            .checkout_projection_authority
            .map(|binding| {
                let frozen = binding
                    .authority
                    .freeze_current_authority(&binding.receipt.authority_roots)
                    .map_err(|error| {
                        classify_repository_authority_freeze_error(
                            &format!(
                                "freeze checkout projection authority at generation {}",
                                binding.receipt.authority_roots.generation
                            ),
                            error,
                        )
                    })?;
                validate_checkout_projection_workspace(frozen.authority(), binding.receipt)?;
                Ok::<_, KinError>(frozen)
            })
            .transpose()?;
        if let Some(retained) = options.checkout_projection_freeze {
            if retained.is_some() {
                return Err(KinError::Other(
                    "checkout projection authority retention slot was already occupied".to_string(),
                ));
            }
            *retained = checkout_authority_freeze.take();
        }
        if let Some(expected) = &checkout_projection_commit {
            if let Some(installed) =
                projection.load_checkout_projection_receipt(expected.operation_id)?
            {
                if installed != *expected {
                    return Err(KinError::Other(format!(
                        "checkout operation {} was already completed for a different projection request",
                        expected.operation_id
                    )));
                }
                return commit().into_result().map(|committed| (0, committed));
            }
        }
        if checkout_scope.is_some() {
            if let Some(marker) = &authority_commit {
                if projection
                    .load_checkout_projection_receipt(marker.operation_id)?
                    .is_some()
                {
                    return Err(KinError::Other(format!(
                        "repository operation {} was already consumed by a projection-only checkout",
                        marker.operation_id
                    )));
                }
            }
        }
        let graph_only_verification = options
            .graph_only_transition
            .map(|transition| {
                GraphOnlyWorkspaceTransitionVerification::verify(
                    projection,
                    transition.previous_tree,
                    transition.target_tree,
                    transition.scope,
                )
            })
            .transpose()?;
        let requires_target_revalidation =
            authority_commit.is_some() || checkout_projection_commit.is_some();
        let is_selected = |path: &RepoPath| {
            checkout_scope.is_some_and(|scope| repository_path_is_same_or_descendant(path, scope))
        };
        let previous =
            TrackedPathClassifier::new(previous_entries.iter().map(|entry| entry.file_id))?;
        let target = TrackedPathClassifier::new(entries.iter().map(|entry| entry.file_id))?;
        let target_by_path: HashMap<_, _> =
            entries.iter().map(|entry| (entry.file_id, entry)).collect();
        let previous_by_path: HashMap<_, _> = previous_entries
            .iter()
            .map(|entry| (entry.file_id, entry))
            .collect();
        let affected_previous: Vec<_> = previous_entries
            .iter()
            .filter(|previous_entry| {
                is_selected(previous_entry.file_id)
                    || target_by_path
                        .get(previous_entry.file_id)
                        .is_none_or(|target_entry| {
                            !source_entries_match(previous_entry, target_entry)
                        })
            })
            .collect();
        let mut removed_file_ids = Vec::new();
        for entry in previous_entries {
            let relative = Path::new(projection_path(entry.file_id)?);
            if target.relation(relative) != TrackedPathRelation::Exact {
                removed_file_ids.push(entry.file_id);
            }
        }
        removed_file_ids.sort_unstable();
        let removed = TrackedPathClassifier::new(removed_file_ids.iter().copied())?;
        let entries_to_materialize: Vec<_> = entries
            .iter()
            .copied()
            .filter(|target_entry| {
                is_selected(target_entry.file_id)
                    || previous_by_path
                        .get(target_entry.file_id)
                        .is_none_or(|previous_entry| {
                            !source_entries_match(previous_entry, target_entry)
                        })
            })
            .collect();

        // This is one read-only preflight boundary: first prove that every old
        // path the switch would mutate is still byte/kind-exact, then validate
        // every target collision. No deletion or replacement occurs until all
        // local-edit and untracked-path conflicts have been rejected.
        //
        // A repository-authority transition additionally proves every tracked
        // path. Otherwise an unchanged-but-locally-edited file could survive
        // while the workspace transaction declares the exact target tree
        // clean, making the physical projection lie about graph authority.
        let preflight_previous = if authority_commit.is_some() && checkout_scope.is_none() {
            previous_entries.iter().collect::<Vec<_>>()
        } else {
            affected_previous
                .iter()
                .copied()
                .filter(|entry| !is_selected(entry.file_id))
                .collect::<Vec<_>>()
        };
        let preflight_identities =
            projection.validate_tracked_entries_unchanged(&preflight_previous)?;
        let identity_by_path = preflight_previous
            .iter()
            .zip(&preflight_identities)
            .map(|(entry, identity)| (entry.file_id, *identity))
            .collect::<HashMap<_, _>>();
        let previous_states = affected_previous
            .iter()
            .map(|entry| {
                if is_selected(entry.file_id) {
                    projection.inspect_checkout_previous_entry(entry.file_id)
                } else {
                    identity_by_path
                        .get(entry.file_id)
                        .copied()
                        .map(|identity| PreviousProjectionState::Exact { identity })
                        .ok_or_else(|| {
                            KinError::Other(format!(
                                "affected exact-source path {} was omitted from preflight",
                                entry.file_id
                            ))
                        })
                }
            })
            .collect::<Result<Vec<_>>>()?;
        projection.validate_reconciliation_targets(&entries_to_materialize, &previous, &removed)?;

        let mut files_to_delete = Vec::with_capacity(removed_file_ids.len());
        for file_id in &removed_file_ids {
            files_to_delete.push(PathBuf::from(projection_path(file_id)?));
        }

        // A generated-directory name is preservation policy only for
        // unrelated occupants. When the previous graph owns every leaf under
        // a directory and the target graph owns the directory path as a file,
        // remove that now-empty graph-owned directory explicitly so names such
        // as target/vendor/dist/build/node_modules can transition exactly.
        let mut replacement_roots = Vec::new();
        for entry in &entries_to_materialize {
            let relative = Path::new(projection_path(entry.file_id)?);
            if previous.relation(relative) == TrackedPathRelation::Ancestor
                && removed.relation(relative) == TrackedPathRelation::Ancestor
            {
                replacement_roots.push(relative.to_path_buf());
            }
        }
        let mut directories_to_replace = HashSet::new();
        for removed_path in &files_to_delete {
            for replacement_root in &replacement_roots {
                if !removed_path.starts_with(replacement_root) {
                    continue;
                }
                let mut directory = removed_path.parent();
                while let Some(relative) = directory {
                    if !relative.starts_with(replacement_root) {
                        break;
                    }
                    directories_to_replace.insert(relative.to_path_buf());
                    if relative == replacement_root {
                        break;
                    }
                    directory = relative.parent();
                }
            }
        }
        let mut directories_to_replace: Vec<_> = directories_to_replace.into_iter().collect();
        directories_to_replace.sort_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });

        let replacement_directory_set: HashSet<_> =
            directories_to_replace.iter().cloned().collect();
        let mut cleanup_directories = HashSet::new();
        for removed_path in &files_to_delete {
            let mut directory = removed_path.parent();
            while let Some(relative) = directory {
                if relative.as_os_str().is_empty() {
                    break;
                }
                if !should_preserve(relative)
                    && removed.relation(relative) == TrackedPathRelation::Ancestor
                    && !replacement_directory_set.contains(relative)
                {
                    cleanup_directories.insert(relative.to_path_buf());
                }
                directory = relative.parent();
            }
        }
        let mut cleanup_directories: Vec<_> = cleanup_directories.into_iter().collect();
        cleanup_directories.sort_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });

        let mut directory_identities = HashMap::new();
        for relative in directories_to_replace.iter().chain(&cleanup_directories) {
            let identity = projection
                .relative_directory_identity(relative)?
                .ok_or_else(|| {
                    KinError::Other(format!(
                        "graph-owned directory {} disappeared during exact-source preflight",
                        projection.display_root.join(relative).display()
                    ))
                })?;
            directory_identities.insert(relative.clone(), identity);
        }

        after_read_only_preflight();
        if let Some(freeze) = &frozen {
            freeze.revalidate_namespace()?;
        }
        if let Some(verification) = &graph_only_verification {
            verification.revalidate_before_mutation(projection)?;
        }
        projection
            .revalidate_tracked_entries_unchanged(&preflight_previous, &preflight_identities)?;
        for (entry, state) in affected_previous.iter().zip(&previous_states) {
            if is_selected(entry.file_id) {
                projection.revalidate_checkout_previous_entry(entry.file_id, state)?;
            }
        }
        for (relative, expected_identity) in &directory_identities {
            let actual = projection.relative_directory_identity(relative)?;
            if actual != Some(*expected_identity) {
                return Err(KinError::Other(format!(
                    "graph-owned directory {} changed identity after exact-source preflight",
                    projection.display_root.join(relative).display()
                )));
            }
        }

        let file_ids: Vec<_> = entries_to_materialize
            .iter()
            .map(|entry| entry.file_id)
            .collect();

        // Stage every target object before the first destructive namespace
        // operation. The transaction directory is retained until either all
        // publications succeed or every displaced old object is restored.
        let mut transaction = projection.create_reconciliation_transaction_with_commit_markers(
            authority_commit,
            checkout_projection_commit.clone(),
        )?;
        let staged = match projection
            .stage_reconciliation_entries(&transaction.directory, &entries_to_materialize)
        {
            Ok(staged) => staged,
            Err(error) => {
                return match projection.cleanup_reconciliation_transaction(transaction) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(KinError::Other(format!(
                        "{error}; staged exact-source cleanup also failed: {cleanup_error}"
                    ))),
                };
            }
        };
        let staged_identity_by_path = staged
            .iter()
            .map(|staged| (staged.entry.file_id, staged.identity))
            .collect::<HashMap<_, _>>();
        let target_entry_refs = if requires_target_revalidation {
            entries
                .iter()
                .filter(|entry| checkout_scope.is_none() || is_selected(entry.file_id))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let target_identities = if requires_target_revalidation {
            target_entry_refs
                .iter()
                .map(|entry| {
                    previous_by_path
                        .get(entry.file_id)
                        .filter(|previous| source_entries_match(previous, entry))
                        .and_then(|_| identity_by_path.get(entry.file_id))
                        .or_else(|| staged_identity_by_path.get(entry.file_id))
                        .copied()
                        .ok_or_else(|| {
                            KinError::Other(format!(
                                "exact workspace target {} has no retained publication identity",
                                entry.file_id
                            ))
                        })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };

        // Tests exercise the final namespace race here. Every later removal is
        // a compare-and-swap: the named object is first moved into the retained
        // transaction, then its exact preflight identity/kind/content is
        // verified before any replacement can publish.
        after_identity_revalidation();
        if let Some(freeze) = &frozen {
            freeze.revalidate_namespace()?;
        }
        if let Some(verification) = &graph_only_verification {
            verification.revalidate_before_mutation(projection)?;
        }

        let mut created_directories = Vec::new();
        let mut removed_directories = Vec::new();
        let empty_must_create_directories = HashSet::new();
        let must_create_directories = graph_only_verification
            .as_ref()
            .map(|verification| &verification.must_create_directories)
            .unwrap_or(&empty_must_create_directories);

        let mutation_result: Result<()> = (|| {
            for (name_index, (entry, state)) in
                affected_previous.iter().zip(&previous_states).enumerate()
            {
                match state {
                    PreviousProjectionState::Exact { identity } => projection
                        .displace_previous_entry(
                            &mut transaction,
                            **entry,
                            *identity,
                            name_index,
                        )?,
                    PreviousProjectionState::CheckoutAbsent => {}
                    PreviousProjectionState::CheckoutObject {
                        relative,
                        kind,
                        identity,
                        state,
                    } => projection.back_up_existing_object(
                        &mut transaction,
                        &PlannedExistingObject {
                            relative: relative.clone(),
                            kind: *kind,
                            identity: *identity,
                            state: *state,
                        },
                        name_index,
                    )?,
                }
            }

            for relative in &directories_to_replace {
                removed_directories.push(projection.back_up_planned_empty_directory(
                    &mut transaction,
                    relative,
                    directory_identities[relative],
                    removed_directories.len(),
                )?);
            }

            projection.prepare_without_replacement_transactional(
                &mut transaction,
                &file_ids,
                &mut created_directories,
                must_create_directories,
            )?;
            for staged_entry in &staged {
                projection.publish_staged_entry(&mut transaction, staged_entry)?;
            }

            for relative in &cleanup_directories {
                if projection.relative_directory_is_empty(relative)? {
                    removed_directories.push(projection.back_up_planned_empty_directory(
                        &mut transaction,
                        relative,
                        directory_identities[relative],
                        removed_directories.len(),
                    )?);
                }
            }
            after_projection_mutation();
            if requires_target_revalidation {
                projection
                    .revalidate_tracked_entries_unchanged(&target_entry_refs, &target_identities)?;
            }
            if let Some(verification) = &graph_only_verification {
                verification.revalidate_after_mutation(projection)?;
            }
            if let Some(freeze) = &frozen {
                freeze.revalidate_namespace()?;
            } else {
                projection.revalidate_projection_lock()?;
            }
            Ok(())
        })();

        if let Err(error) = mutation_result {
            let rollback = projection.rollback_reconciliation_manifest(&transaction);
            return match rollback {
                Ok(()) => match projection.cleanup_reconciliation_transaction(transaction) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(KinError::Other(format!(
                        "{error}; exact-source rollback succeeded but transaction cleanup failed: {cleanup_error}"
                    ))),
                },
                Err(rollback_error) => Err(KinError::Other(format!(
                    "{error}; {rollback_error}; retained recovery transaction at {}",
                    projection
                        .reconciliation_control_path()
                        .join(&transaction.name)
                        .display()
                ))),
            };
        }

        let committed = match commit() {
            ProjectionAuthorityCommit::Committed(committed) => committed,
            ProjectionAuthorityCommit::DefinitelyNotCommitted(error) => {
                let rollback = projection.rollback_reconciliation_manifest(&transaction);
                return match rollback {
                    Ok(()) => match projection.cleanup_reconciliation_transaction(transaction) {
                        Ok(()) => Err(error),
                        Err(cleanup_error) => Err(KinError::Other(format!(
                            "{error}; exact-source rollback succeeded but transaction cleanup failed: {cleanup_error}"
                        ))),
                    },
                    Err(rollback_error) => Err(KinError::Other(format!(
                        "{error}; {rollback_error}; retained recovery transaction at {}",
                        projection
                            .reconciliation_control_path()
                            .join(&transaction.name)
                            .display()
                    ))),
                };
            }
            ProjectionAuthorityCommit::Indeterminate(error) => {
                return Err(error);
            }
        };

        if let Some(receipt) = &checkout_projection_commit {
            if let Err(error) = projection.persist_checkout_projection_receipt(receipt) {
                let installed =
                    projection.load_checkout_projection_receipt(receipt.operation_id)?;
                if installed.as_ref() != Some(receipt) {
                    return Err(KinError::Other(format!(
                        "{error}; exact projection and authenticated recovery WAL were retained because local checkout receipt publication is uncertain"
                    )));
                }
            }
        }

        projection
            .cleanup_reconciliation_transaction(transaction)
            .map_err(|error| {
                KinError::Other(format!(
                    "exact projection commit marker was installed but transaction cleanup failed; \
                     recovery will finalize the committed projection: {error}"
                ))
            })?;
        Ok((entries_to_materialize.len(), committed))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (
            root,
            previous_entries,
            entries,
            should_preserve,
            options,
            after_read_only_preflight,
            after_identity_revalidation,
            after_projection_mutation,
            authority_commit,
            checkout_projection_commit,
            commit,
        );
        Err(unsupported_safe_projection_error())
    }
}

fn source_entries_match(left: &ValidatedSourceEntry<'_>, right: &ValidatedSourceEntry<'_>) -> bool {
    left.kind == right.kind && left.content == right.content
}

#[cfg(not(any(unix, windows)))]
fn unsupported_safe_projection_error() -> KinError {
    KinError::Other(
        "safe exact source checkout is unsupported on this platform because retained no-follow directory capabilities are unavailable"
            .to_string(),
    )
}

#[cfg(any(unix, windows))]
struct ProjectionRoot {
    root: cap_std::fs::Dir,
    kin_control: cap_std::fs::Dir,
    control: cap_std::fs::Dir,
    projection_lock: std::fs::File,
    projection_lock_identity: TrackedEntryIdentity,
    display_root: PathBuf,
    projection_control_name: OsString,
    display_projection_control: PathBuf,
    kin_control_identity: TrackedEntryIdentity,
    control_identity: TrackedEntryIdentity,
    authority_key: [u8; 32],
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct TrackedEntryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
struct StagedReconciliationEntry<'a> {
    entry: ValidatedSourceEntry<'a>,
    name_index: usize,
    identity: TrackedEntryIdentity,
    state: TrackedObjectState,
}

#[cfg(any(unix, windows))]
struct ReconciliationTransaction {
    name: OsString,
    directory: cap_std::fs::Dir,
    identity: TrackedEntryIdentity,
    manifest: ReconciliationManifest,
    action_log_bytes: u64,
    action_tail_authentication: Vec<u8>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
enum ExistingObjectKind {
    File,
    Symlink,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct TrackedObjectState {
    content_sha256: [u8; 32],
    /// Unix permission bits. Windows exact-source projection binds bytes and
    /// FILE_ID_128, but sets this to zero because Win32 ACLs are not a stable
    /// mode scalar and are outside the current projection transaction model.
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct ExactGitDirectorySeal {
    digest: [u8; 32],
    entry_count: u64,
    multiply_linked_files: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ExactEjectJournalPhase {
    Prepared,
    PreviousGitMovePending,
    StageInstallPending,
    DetachPending,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExactEjectPreviousGit {
    File {
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
    },
    Directory {
        identity: TrackedEntryIdentity,
        seal: ExactGitDirectorySeal,
    },
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExactEjectJournal {
    schema: u32,
    transaction_id: String,
    phase: ExactEjectJournalPhase,
    root_identity: TrackedEntryIdentity,
    kin_control_identity: TrackedEntryIdentity,
    control_identity: TrackedEntryIdentity,
    namespace_parent_identity: TrackedEntryIdentity,
    root_name: Vec<u8>,
    archive_name: Vec<u8>,
    archive_identity: TrackedEntryIdentity,
    stage_parent_components: Vec<Vec<u8>>,
    stage_parent_identity: TrackedEntryIdentity,
    stage_name: Vec<u8>,
    stage_identity: TrackedEntryIdentity,
    stage_seal: ExactGitDirectorySeal,
    archived_kin_name: Vec<u8>,
    archived_git_name: Vec<u8>,
    previous_git: Option<ExactEjectPreviousGit>,
}

#[cfg(unix)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedExactEjectJournal {
    journal: ExactEjectJournal,
    authentication: Vec<u8>,
}

#[cfg(unix)]
const MAX_EXACT_GIT_SEAL_ENTRIES: u64 = 10_000_000;
#[cfg(unix)]
const MAX_EXACT_GIT_SEAL_DEPTH: usize = 256;

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ReconciliationManifest {
    schema: u32,
    transaction_id: String,
    root_identity: TrackedEntryIdentity,
    kin_control_identity: TrackedEntryIdentity,
    control_identity: TrackedEntryIdentity,
    transaction_identity: TrackedEntryIdentity,
    authority_commit: Option<ReconciliationAuthorityCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkout_projection_commit: Option<CheckoutProjectionReceipt>,
    state: ReconciliationTransactionState,
    actions: Vec<ReconciliationRecoveryAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct ReconciliationAuthorityCommit {
    repository_id: RepositoryId,
    operation_id: OperationId,
    transaction_hash: Hash256,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReconciliationTransactionState {
    Pending,
    Committed,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct AuthenticatedReconciliationManifest {
    manifest: ReconciliationManifest,
    authentication: Vec<u8>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct AuthenticatedReconciliationAction {
    sequence: u64,
    previous_authentication: Vec<u8>,
    action: ReconciliationRecoveryAction,
    authentication: Vec<u8>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedCheckoutProjectionReceipt {
    receipt: CheckoutProjectionReceipt,
    authentication: Vec<u8>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum ReconciliationRecoveryAction {
    BackupObject {
        relative: PathBuf,
        kind: ExistingObjectKind,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
        slot: String,
    },
    BackupDirectory {
        relative: PathBuf,
        identity: TrackedEntryIdentity,
        slot: String,
    },
    PublishObject {
        relative: PathBuf,
        kind: ExistingObjectKind,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
        slot: String,
    },
    PublishDirectory {
        relative: PathBuf,
        identity: TrackedEntryIdentity,
        slot: String,
    },
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug)]
struct PlannedExistingObject {
    relative: PathBuf,
    kind: ExistingObjectKind,
    identity: TrackedEntryIdentity,
    state: TrackedObjectState,
}

#[cfg(any(unix, windows))]
struct BackedUpDirectory {
    _directory: cap_std::fs::Dir,
}

#[cfg(any(unix, windows))]
struct PublishedDirectory {
    relative: PathBuf,
    identity: TrackedEntryIdentity,
    #[cfg(all(test, unix))]
    name_index: usize,
    directory: cap_std::fs::Dir,
}

#[cfg(any(unix, windows))]
struct FullReplacementPlan {
    objects: Vec<PlannedExistingObject>,
    directories: Vec<(PathBuf, TrackedEntryIdentity)>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
struct NamedEntryLocation<'a> {
    parent: &'a cap_std::fs::Dir,
    name: &'a std::ffi::OsStr,
}

#[cfg(unix)]
enum RetainedGitEntry {
    File {
        file: cap_std::fs::File,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
    },
    Directory {
        directory: cap_std::fs::Dir,
        identity: TrackedEntryIdentity,
        seal: ExactGitDirectorySeal,
    },
}

#[cfg(unix)]
impl RetainedGitEntry {
    fn identity(&self) -> TrackedEntryIdentity {
        match self {
            Self::File { identity, .. } | Self::Directory { identity, .. } => *identity,
        }
    }

    fn journal_descriptor(&self) -> ExactEjectPreviousGit {
        match self {
            Self::File {
                identity, state, ..
            } => ExactEjectPreviousGit::File {
                identity: *identity,
                state: *state,
            },
            Self::Directory { identity, seal, .. } => ExactEjectPreviousGit::Directory {
                identity: *identity,
                seal: *seal,
            },
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactProjectionEjectHookPoint {
    BeforeNamespaceMutation,
    AfterPreviousGitArchived,
    AfterStagedGitInstalled,
    AfterKinDetached,
}

#[cfg(unix)]
fn tracked_entry_identity(metadata: &cap_std::fs::Metadata) -> TrackedEntryIdentity {
    use cap_std::fs::MetadataExt;

    TrackedEntryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn tracked_open_file_identity(metadata: &std::fs::Metadata) -> TrackedEntryIdentity {
    use std::os::unix::fs::MetadataExt;

    TrackedEntryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn tracked_open_file_identity(file: &cap_std::fs::File) -> std::io::Result<TrackedEntryIdentity> {
    use std::os::windows::io::AsRawHandle;

    tracked_windows_handle_identity(file.as_raw_handle().cast())
}

#[cfg(unix)]
fn tracked_open_file_identity_for_std(
    file: &std::fs::File,
) -> std::io::Result<TrackedEntryIdentity> {
    file.metadata()
        .map(|metadata| tracked_open_file_identity(&metadata))
}

#[cfg(unix)]
fn tracked_cap_file_identity(file: &cap_std::fs::File) -> std::io::Result<TrackedEntryIdentity> {
    file.metadata()
        .map(|metadata| tracked_entry_identity(&metadata))
}

#[cfg(windows)]
fn tracked_cap_file_identity(file: &cap_std::fs::File) -> std::io::Result<TrackedEntryIdentity> {
    tracked_open_file_identity(file)
}

#[cfg(windows)]
fn tracked_open_file_identity_for_std(
    file: &std::fs::File,
) -> std::io::Result<TrackedEntryIdentity> {
    use std::os::windows::io::AsRawHandle;

    tracked_windows_handle_identity(file.as_raw_handle().cast())
}

#[cfg(unix)]
fn tracked_open_directory_identity(
    directory: &cap_std::fs::Dir,
) -> std::io::Result<TrackedEntryIdentity> {
    directory
        .dir_metadata()
        .map(|metadata| tracked_entry_identity(&metadata))
}

#[cfg(windows)]
fn tracked_open_directory_identity(
    directory: &cap_std::fs::Dir,
) -> std::io::Result<TrackedEntryIdentity> {
    use std::os::windows::io::AsRawHandle;

    tracked_windows_handle_identity(directory.as_raw_handle().cast())
}

/// Report whether the directory opened for a component is the entry the
/// preceding no-follow `metadata` described.
///
/// Unix binds the observation to the opened handle through the device and inode
/// pair, which closes the window between the `symlink_metadata` call and the
/// open. Windows binds identity to an open handle rather than to `Metadata`, so
/// there is no pre-open identity to carry across; `open_directory_nofollow`
/// instead reads the reparse and directory attributes off the handle it returns
/// and refuses anything else, which binds the same guarantee at the open itself.
#[cfg(unix)]
fn opened_directory_matches_entry(
    directory: &cap_std::fs::Dir,
    metadata: &cap_std::fs::Metadata,
) -> std::io::Result<bool> {
    Ok(tracked_open_directory_identity(directory)? == tracked_entry_identity(metadata))
}

#[cfg(windows)]
fn opened_directory_matches_entry(
    _directory: &cap_std::fs::Dir,
    _metadata: &cap_std::fs::Metadata,
) -> std::io::Result<bool> {
    Ok(true)
}

#[cfg(windows)]
fn tracked_windows_handle_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<TrackedEntryIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    // FILE_ID_INFO is the Windows namespace authority for modern filesystems.
    // The legacy 64-bit file index exposed by metadata can alias on ReFS, so it
    // must never authorize a destructive exact-source transition.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let inspected = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if inspected == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let identity = TrackedEntryIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    };
    if identity.volume_serial == 0 || identity.file_id.iter().all(|byte| *byte == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows exact-source object returned a zero volume or FILE_ID_128 identity",
        ));
    }
    Ok(identity)
}

#[cfg(any(unix, windows))]
fn reconciliation_hmac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    const BLOCK_BYTES: usize = 64;
    let mut inner_key = [0x36_u8; BLOCK_BYTES];
    let mut outer_key = [0x5c_u8; BLOCK_BYTES];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    outer.finalize().into()
}

#[cfg(unix)]
fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (*left ^ *right)
            })
            == 0
}

#[cfg(any(unix, windows))]
fn sync_directory_capability(directory: &cap_std::fs::Dir, display: &Path) -> Result<()> {
    #[cfg(unix)]
    rustix::fs::fsync(directory)
        .map_err(|error| KinError::io(display, std::io::Error::from(error)))?;
    #[cfg(windows)]
    {
        // Win32 has no supported equivalent of fsync for a directory handle;
        // FlushFileBuffers requires GENERIC_WRITE and applies to file data, not
        // directory namespace entries. The file contents and recovery manifest
        // are flushed through their retained file handles before any rename.
        let _ = (directory, display);
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn sync_namespace_parents(
    source: &cap_std::fs::Dir,
    source_display: &Path,
    destination: &cap_std::fs::Dir,
    destination_display: &Path,
) -> Result<()> {
    sync_directory_capability(source, source_display)?;
    if tracked_open_directory_identity(source)
        .map_err(|error| KinError::io(source_display, error))?
        != tracked_open_directory_identity(destination)
            .map_err(|error| KinError::io(destination_display, error))?
    {
        sync_directory_capability(destination, destination_display)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_exact_namespace_component(label: &str, name: &std::ffi::OsStr) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        return Err(KinError::Other(format!(
            "{label} destination is not one safe path component: {name:?}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn exact_relative_directory_components(relative: &Path, label: &str) -> Result<Vec<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt as _;

    relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(component) if !component.as_bytes().is_empty() => {
                Ok(component.as_bytes().to_vec())
            }
            _ => Err(KinError::Other(format!(
                "{label} is not a safe relative directory path: {}",
                relative.display()
            ))),
        })
        .collect()
}

/// The refusal for an eject journal Kin will not act on.
///
/// Names the file, what is wrong with it, the archive the eject it records
/// used when the journal could say, and the way out in both states that
/// archive can be in. A refusal without those sent a stranger from `HTTP 500`
/// to `rm -rf .kin/` on 0.5.52 (FIR-2664).
#[cfg(unix)]
fn exact_eject_journal_blocked(journal: &Path, archive: Option<&Path>, what: &str) -> KinError {
    let archive = match archive {
        Some(archive) => archive.display().to_string(),
        None => "the .kin-ejected-* archive beside the repository".to_string(),
    };
    KinError::ProjectionBlocked(format!(
        "exact eject journal {} {what}, so Kin will not replay the eject it records here. If that \
         eject completed, the repository root holds an ordinary .git and {archive} holds kin/ and \
         previous-git/, and this journal is a leftover: remove the file and rerun. If it did not, \
         {archive} holds whatever the eject had moved when it stopped and the journal is the \
         record of it; put those entries back by hand before removing it. To rebuild Kin from Git \
         history instead, remove .kin/ and run `kin init`.",
        journal.display()
    ))
}

#[cfg(unix)]
fn exact_eject_journal_name(bytes: &[u8], label: &str) -> Result<OsString> {
    use std::os::unix::ffi::OsStringExt as _;

    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        return Err(KinError::Other(format!(
            "exact eject journal contains an unsafe {label} namespace name"
        )));
    }
    Ok(OsString::from_vec(bytes.to_vec()))
}

#[cfg(unix)]
fn exact_eject_previous_git_identity(previous: &ExactEjectPreviousGit) -> TrackedEntryIdentity {
    match previous {
        ExactEjectPreviousGit::File { identity, .. }
        | ExactEjectPreviousGit::Directory { identity, .. } => *identity,
    }
}

#[cfg(unix)]
fn open_exact_relative_directory_components(
    root: &cap_std::fs::Dir,
    components: &[Vec<u8>],
    display: &Path,
) -> Result<cap_std::fs::Dir> {
    use std::os::unix::ffi::OsStrExt as _;

    if components.len() > MAX_EXACT_GIT_SEAL_DEPTH {
        return Err(KinError::Other(format!(
            "exact eject retained path {} exceeds depth limit {}",
            display.display(),
            MAX_EXACT_GIT_SEAL_DEPTH
        )));
    }
    let mut directory = root
        .try_clone()
        .map_err(|error| KinError::io(display, error))?;
    for component in components {
        if component.is_empty() || component == b"." || component == b".." || component.contains(&0)
        {
            return Err(KinError::Other(format!(
                "exact eject retained path {} contains an unsafe component",
                display.display()
            )));
        }
        directory = open_directory_nofollow(
            &directory,
            std::ffi::OsStr::from_bytes(component.as_slice()),
        )
        .map_err(|error| KinError::io(display, error))?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn ensure_named_entry_absent(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<()> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KinError::io(display, error)),
        Ok(_) => Err(KinError::Other(format!(
            "exact eject destination already exists: {}",
            display.display()
        ))),
    }
}

#[cfg(unix)]
fn seal_exact_git_directory(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<ExactGitDirectorySeal> {
    use sha2::{Digest, Sha256};

    let root_identity =
        tracked_open_directory_identity(directory).map_err(|error| KinError::io(display, error))?;
    let mut digest = Sha256::new();
    digest.update(b"kin.exact-git-directory-seal.v1\0");
    update_exact_git_seal_identity(&mut digest, root_identity);
    let mut entry_count = 0_u64;
    let mut multiply_linked_files = 0_u64;
    let mut relative = Vec::new();
    seal_exact_git_directory_recursive(
        directory,
        display,
        &mut relative,
        0,
        &mut entry_count,
        &mut multiply_linked_files,
        &mut digest,
    )?;
    let retained_identity =
        tracked_open_directory_identity(directory).map_err(|error| KinError::io(display, error))?;
    if retained_identity != root_identity {
        return Err(KinError::Other(format!(
            "staged Git directory {} changed identity while sealing descendants",
            display.display()
        )));
    }
    Ok(ExactGitDirectorySeal {
        digest: digest.finalize().into(),
        entry_count,
        multiply_linked_files,
    })
}

#[cfg(unix)]
fn seal_exact_git_directory_recursive(
    directory: &cap_std::fs::Dir,
    display: &Path,
    relative: &mut Vec<Vec<u8>>,
    depth: usize,
    entry_count: &mut u64,
    multiply_linked_files: &mut u64,
    digest: &mut sha2::Sha256,
) -> Result<()> {
    use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
    use sha2::Digest as _;
    use std::os::unix::ffi::OsStrExt as _;

    if depth > MAX_EXACT_GIT_SEAL_DEPTH {
        return Err(KinError::Other(format!(
            "staged Git directory {} exceeds the exact-seal depth limit of {}",
            display.display(),
            MAX_EXACT_GIT_SEAL_DEPTH
        )));
    }
    let directory_identity =
        tracked_open_directory_identity(directory).map_err(|error| KinError::io(display, error))?;
    let mut names = directory
        .entries()
        .map_err(|error| KinError::io(display, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| KinError::io(display, error))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        *entry_count = entry_count.checked_add(1).ok_or_else(|| {
            KinError::Other("staged Git exact-seal entry count overflow".to_string())
        })?;
        if *entry_count > MAX_EXACT_GIT_SEAL_ENTRIES {
            return Err(KinError::Other(format!(
                "staged Git directory {} exceeds the exact-seal entry limit of {}",
                display.display(),
                MAX_EXACT_GIT_SEAL_ENTRIES
            )));
        }
        let raw_name = name.as_bytes().to_vec();
        relative.push(raw_name);
        let child_display = display.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(|error| KinError::io(&child_display, error))?;
        if metadata_is_reparse(&metadata) {
            return Err(KinError::Other(format!(
                "staged Git descendant {} is a symbolic link; exact Git staging accepts only real directories and regular files",
                child_display.display()
            )));
        }

        update_exact_git_seal_path(digest, relative)?;
        let identity = tracked_entry_identity(&metadata);
        update_exact_git_seal_identity(digest, identity);
        let mode = metadata.permissions().mode();
        digest.update(mode.to_le_bytes());

        if metadata.is_dir() {
            digest.update([b'd']);
            let child = open_directory_nofollow(directory, &name)
                .map_err(|error| KinError::io(&child_display, error))?;
            if tracked_open_directory_identity(&child)
                .map_err(|error| KinError::io(&child_display, error))?
                != identity
            {
                return Err(KinError::Other(format!(
                    "staged Git directory {} changed identity while sealing",
                    child_display.display()
                )));
            }
            seal_exact_git_directory_recursive(
                &child,
                &child_display,
                relative,
                depth + 1,
                entry_count,
                multiply_linked_files,
                digest,
            )?;
            let named = directory
                .symlink_metadata(&name)
                .map_err(|error| KinError::io(&child_display, error))?;
            if metadata_is_reparse(&named)
                || !named.is_dir()
                || tracked_entry_identity(&named) != identity
                || named.permissions().mode() != mode
                || tracked_open_directory_identity(&child)
                    .map_err(|error| KinError::io(&child_display, error))?
                    != identity
            {
                return Err(KinError::Other(format!(
                    "staged Git directory {} changed while sealing descendants",
                    child_display.display()
                )));
            }
        } else if metadata.is_file() {
            digest.update([b'f']);
            digest.update(metadata.len().to_le_bytes());
            digest.update(metadata.nlink().to_le_bytes());
            if metadata.nlink() > 1 {
                *multiply_linked_files = multiply_linked_files.checked_add(1).ok_or_else(|| {
                    KinError::Other("staged Git multiply-linked file count overflow".to_string())
                })?;
            }
            let mut file = open_regular_file_nofollow_for_removal(directory, &name)
                .map_err(|error| KinError::io(&child_display, error))?;
            if tracked_cap_file_identity(&file)
                .map_err(|error| KinError::io(&child_display, error))?
                != identity
            {
                return Err(KinError::Other(format!(
                    "staged Git file {} changed identity while sealing",
                    child_display.display()
                )));
            }
            let mut content_digest = sha2::Sha256::new();
            let mut length = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| KinError::io(&child_display, error))?;
                if read == 0 {
                    break;
                }
                length = length.checked_add(read as u64).ok_or_else(|| {
                    KinError::Other(format!(
                        "staged Git file length overflow for {}",
                        child_display.display()
                    ))
                })?;
                content_digest.update(&buffer[..read]);
            }
            file.sync_all()
                .map_err(|error| KinError::io(&child_display, error))?;
            let revalidated = file
                .metadata()
                .map_err(|error| KinError::io(&child_display, error))?;
            if !revalidated.is_file()
                || tracked_cap_file_identity(&file)
                    .map_err(|error| KinError::io(&child_display, error))?
                    != identity
                || revalidated.len() != metadata.len()
                || length != metadata.len()
                || revalidated.nlink() != metadata.nlink()
                || revalidated.permissions().mode() != mode
            {
                return Err(KinError::Other(format!(
                    "staged Git file {} changed bytes, mode, length, or identity while sealing",
                    child_display.display()
                )));
            }
            digest.update(content_digest.finalize());
        } else {
            return Err(KinError::Other(format!(
                "staged Git descendant {} has an unsupported filesystem kind",
                child_display.display()
            )));
        }
        relative.pop();
    }

    if tracked_open_directory_identity(directory).map_err(|error| KinError::io(display, error))?
        != directory_identity
    {
        return Err(KinError::Other(format!(
            "staged Git directory {} changed identity while sealing",
            display.display()
        )));
    }
    sync_directory_capability(directory, display)?;
    Ok(())
}

#[cfg(unix)]
fn update_exact_git_seal_path(digest: &mut sha2::Sha256, components: &[Vec<u8>]) -> Result<()> {
    use sha2::Digest as _;

    let component_count = u32::try_from(components.len()).map_err(|_| {
        KinError::Other("staged Git exact-seal path has too many components".to_string())
    })?;
    digest.update(component_count.to_le_bytes());
    for component in components {
        let length = u32::try_from(component.len()).map_err(|_| {
            KinError::Other("staged Git exact-seal path component is too long".to_string())
        })?;
        digest.update(length.to_le_bytes());
        digest.update(component);
    }
    Ok(())
}

#[cfg(unix)]
fn update_exact_git_seal_identity(digest: &mut sha2::Sha256, identity: TrackedEntryIdentity) {
    use sha2::Digest as _;

    digest.update(identity.device.to_le_bytes());
    digest.update(identity.inode.to_le_bytes());
}

#[cfg(unix)]
fn open_regular_file_nofollow_for_removal(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::File> {
    let descriptor = rustix::fs::openat(
        parent,
        component,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = cap_std::fs::File::from_std(std::fs::File::from(descriptor));
    let metadata = file.metadata()?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(std::io::Error::other(
            "exact eject Git entry is a symlink or non-file",
        ));
    }
    Ok(file)
}

#[cfg(any(unix, windows))]
fn open_or_create_private_directory(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<cap_std::fs::Dir> {
    for _ in 0..8 {
        // Open the control-plane directory read-only. This handle is held for the
        // projection's lifetime and never deletes its own directory (children are
        // removed through their own per-child handles), so it must not request
        // DELETE access. On Windows a peer that already holds this directory open
        // without FILE_SHARE_DELETE — for example the graph store's snapshot/index
        // under `.kin` — denies any DELETE-access open regardless of the sharing we
        // offer; POSIX imposes no such bilateral constraint. Directory removal uses
        // `open_directory_nofollow_for_removal` at the point of deletion instead.
        match open_directory_nofollow(parent, name) {
            Ok(directory) => {
                #[cfg(unix)]
                rustix::fs::fchmod(&directory, rustix::fs::Mode::from_raw_mode(0o700))
                    .map_err(|error| KinError::io(display, error.into()))?;
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match parent.create_dir(name) {
                    Ok(()) => {
                        sync_directory_capability(parent, display.parent().unwrap_or(display))?
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(KinError::io(display, error)),
                }
            }
            Err(error) => return Err(KinError::io(display, error)),
        }
    }
    Err(KinError::Other(format!(
        "control-plane directory {} changed repeatedly during exact-source initialization",
        display.display()
    )))
}

fn validate_session_projection_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == std::ffi::OsStr::new(name))
        || components.next().is_some()
        || !name.starts_with("session-")
        || name.len() == "session-".len()
    {
        return Err(KinError::Other(format!(
            "session projection name must be one 'session-<id>' path component: {name:?}"
        )));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn ensure_session_child_absent(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<()> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KinError::io(display, error)),
        Ok(_) => Err(KinError::Other(format!(
            "session workspace {} already exists; Kin never reuses a materialized workspace",
            display.display()
        ))),
    }
}

#[cfg(any(unix, windows))]
fn validate_named_directory_identity(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    retained: &cap_std::fs::Dir,
    expected_identity: TrackedEntryIdentity,
    display: &Path,
    label: &str,
) -> Result<()> {
    let named =
        open_directory_nofollow(parent, name).map_err(|error| KinError::io(display, error))?;
    if tracked_open_directory_identity(&named).map_err(|error| KinError::io(display, error))?
        != expected_identity
    {
        return Err(KinError::Other(format!(
            "{label} {} was replaced while retained",
            display.display()
        )));
    }
    if tracked_open_directory_identity(retained).map_err(|error| KinError::io(display, error))?
        != expected_identity
    {
        return Err(KinError::Other(format!(
            "retained {label} {} changed identity",
            display.display()
        )));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn create_retained_session_stage(
    runs: &cap_std::fs::Dir,
    runs_display: &Path,
) -> Result<(OsString, PathBuf, TrackedEntryIdentity, cap_std::fs::Dir)> {
    for _ in 0..8 {
        let stage_name = OsString::from(format!(
            "{SESSION_STAGING_DIRECTORY_PREFIX}{}",
            uuid::Uuid::new_v4()
        ));
        let stage_display = runs_display.join(&stage_name);
        match runs.create_dir(&stage_name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(KinError::io(&stage_display, error)),
        }
        sync_directory_capability(runs, runs_display)?;
        let stage = open_directory_nofollow_for_removal(runs, &stage_name)
            .map_err(|error| KinError::io(&stage_display, error))?;
        #[cfg(unix)]
        rustix::fs::fchmod(&stage, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|error| KinError::io(&stage_display, error.into()))?;
        let identity = tracked_open_directory_identity(&stage)
            .map_err(|error| KinError::io(&stage_display, error))?;
        validate_named_directory_identity(
            runs,
            &stage_name,
            &stage,
            identity,
            &stage_display,
            "session staging directory",
        )?;
        sync_directory_capability(&stage, &stage_display)?;
        sync_directory_capability(runs, runs_display)?;
        return Ok((stage_name, stage_display, identity, stage));
    }
    Err(KinError::Other(format!(
        "could not allocate a unique retained session staging directory beneath {}",
        runs_display.display()
    )))
}

#[cfg(unix)]
fn open_reconciliation_control_file(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::File> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map(cap_std::fs::File::from_std)
    .map_err(Into::into)
}

#[cfg(windows)]
fn open_reconciliation_control_file(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    parent.open_with(name, &options)
}

#[cfg(any(unix, windows))]
fn load_or_create_reconciliation_authority_key(
    control: &cap_std::fs::Dir,
    display_control: &Path,
) -> Result<[u8; 32]> {
    for _ in 0..8 {
        match open_reconciliation_control_file(
            control,
            std::ffi::OsStr::new(RECONCILIATION_AUTHORITY_FILE),
        ) {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(|error| {
                    KinError::io(display_control.join(RECONCILIATION_AUTHORITY_FILE), error)
                })?;
                if !metadata.is_file() || metadata.len() != 32 {
                    return Err(KinError::Other(format!(
                        "reconciliation authority {} is not an exact 32-byte regular file",
                        display_control
                            .join(RECONCILIATION_AUTHORITY_FILE)
                            .display()
                    )));
                }
                let mut key = [0_u8; 32];
                file.read_exact(&mut key).map_err(|error| {
                    KinError::io(display_control.join(RECONCILIATION_AUTHORITY_FILE), error)
                })?;
                return Ok(key);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0_u8; 32];
                key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
                key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
                let temporary = OsString::from(format!(".authority-{}.tmp", uuid::Uuid::new_v4()));
                let mut options = cap_std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                match control.open_with(&temporary, &options) {
                    Ok(mut file) => {
                        #[cfg(unix)]
                        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600)).map_err(
                            |error| KinError::io(display_control.join(&temporary), error.into()),
                        )?;
                        file.write_all(&key)
                            .and_then(|()| file.sync_all())
                            .map_err(|error| {
                                KinError::io(display_control.join(&temporary), error)
                            })?;
                        let publication =
                            control.hard_link(&temporary, control, RECONCILIATION_AUTHORITY_FILE);
                        match publication {
                            Ok(()) => {
                                file.sync_all().map_err(|error| {
                                    KinError::io(
                                        display_control.join(RECONCILIATION_AUTHORITY_FILE),
                                        error,
                                    )
                                })?;
                                drop(file);
                                sync_directory_capability(control, display_control)?;
                                control.remove_file(&temporary).map_err(|error| {
                                    KinError::io(display_control.join(&temporary), error)
                                })?;
                                sync_directory_capability(control, display_control)?;
                                return Ok(key);
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::AlreadyExists
                                        | std::io::ErrorKind::PermissionDenied
                                ) =>
                            {
                                drop(file);
                                let _ = control.remove_file(&temporary);
                                continue;
                            }
                            Err(error) => {
                                drop(file);
                                let _ = control.remove_file(&temporary);
                                return Err(KinError::io(
                                    display_control.join(RECONCILIATION_AUTHORITY_FILE),
                                    error,
                                ));
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(KinError::io(
                            display_control.join(RECONCILIATION_AUTHORITY_FILE),
                            error,
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(KinError::io(
                    display_control.join(RECONCILIATION_AUTHORITY_FILE),
                    error,
                ));
            }
        }
    }
    Err(KinError::Other(format!(
        "reconciliation authority {} changed repeatedly during initialization",
        display_control
            .join(RECONCILIATION_AUTHORITY_FILE)
            .display()
    )))
}

#[cfg(any(unix, windows))]
fn load_existing_reconciliation_authority_key(
    control: &cap_std::fs::Dir,
    display_control: &Path,
) -> Result<[u8; 32]> {
    let display = display_control.join(RECONCILIATION_AUTHORITY_FILE);
    let mut file = open_reconciliation_control_file(
        control,
        std::ffi::OsStr::new(RECONCILIATION_AUTHORITY_FILE),
    )
    .map_err(|error| KinError::io(&display, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| KinError::io(&display, error))?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(KinError::Other(format!(
            "reconciliation authority {} is not an exact 32-byte regular file",
            display.display()
        )));
    }
    let mut key = [0_u8; 32];
    file.read_exact(&mut key)
        .map_err(|error| KinError::io(&display, error))?;
    Ok(key)
}

#[cfg(any(unix, windows))]
enum ProjectionLockAttemptError {
    /// The kernel lock is held by a live projection; the caller may wait.
    Contended(std::io::Error),
    /// Any other failure; surfaced immediately.
    Failed(KinError),
}

#[cfg(any(unix, windows))]
impl From<KinError> for ProjectionLockAttemptError {
    fn from(error: KinError) -> Self {
        Self::Failed(error)
    }
}

#[cfg(any(unix, windows))]
fn try_acquire_reconciliation_projection_lock(
    control: &cap_std::fs::Dir,
    display_control: &Path,
    create_if_missing: bool,
) -> std::result::Result<(std::fs::File, TrackedEntryIdentity), ProjectionLockAttemptError> {
    let name = std::ffi::OsStr::new(RECONCILIATION_PROJECTION_LOCK_FILE);
    #[cfg(unix)]
    let file = {
        let mut flags =
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        if create_if_missing {
            flags |= rustix::fs::OFlags::CREATE;
        }
        rustix::fs::openat(control, name, flags, rustix::fs::Mode::from_raw_mode(0o600))
    }
    .map(std::fs::File::from)
    .map_err(|error| {
        KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            error.into(),
        )
    })?;
    #[cfg(windows)]
    let file = {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create_if_missing)
            .follow(FollowSymlinks::No);
        control
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|error| {
                KinError::io(
                    display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
                    error,
                )
            })?
    };
    let metadata = file.metadata().map_err(|error| {
        KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            error,
        )
    })?;
    if !metadata.is_file() {
        return Err(KinError::Other(format!(
            "projection lock {} is not a regular file",
            display_control
                .join(RECONCILIATION_PROJECTION_LOCK_FILE)
                .display()
        ))
        .into());
    }
    let identity = tracked_open_file_identity_for_std(&file).map_err(|error| {
        KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            error,
        )
    })?;
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock
            || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
        {
            return ProjectionLockAttemptError::Contended(error);
        }
        ProjectionLockAttemptError::Failed(KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            std::io::Error::new(
                error.kind(),
                format!("another exact-source projection is active: {error}"),
            ),
        ))
    })?;

    let named = open_reconciliation_control_file(control, name).map_err(|error| {
        KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            error,
        )
    })?;
    let named_identity = tracked_cap_file_identity(&named).map_err(|error| {
        KinError::io(
            display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
            error,
        )
    })?;
    if named_identity != identity {
        return Err(KinError::Other(format!(
            "projection lock {} changed identity while acquiring",
            display_control
                .join(RECONCILIATION_PROJECTION_LOCK_FILE)
                .display()
        ))
        .into());
    }
    Ok((file, identity))
}

/// Acquire the exact-source projection lock, waiting out a live holder up to
/// `wait_deadline` before failing loud.
///
/// A held lock means another projection is finishing legitimate work, so the
/// caller retries the full attempt (open, lock, identity check) with backoff
/// rather than surfacing WouldBlock to a user who merely ran two kin commands
/// close together. Every retry revalidates the lock file's identity from
/// scratch, so a holder that deletes or swaps the file mid-wait is caught by
/// the same checks a first attempt performs. On timeout the error names the
/// recorded holder when one is legible.
#[cfg(any(unix, windows))]
fn acquire_reconciliation_projection_lock(
    control: &cap_std::fs::Dir,
    display_control: &Path,
    wait_deadline: std::time::Duration,
) -> Result<(std::fs::File, TrackedEntryIdentity)> {
    acquire_reconciliation_projection_lock_with_creation(
        control,
        display_control,
        wait_deadline,
        true,
    )
}

#[cfg(any(unix, windows))]
fn acquire_existing_reconciliation_projection_lock(
    control: &cap_std::fs::Dir,
    display_control: &Path,
    wait_deadline: std::time::Duration,
) -> Result<(std::fs::File, TrackedEntryIdentity)> {
    acquire_reconciliation_projection_lock_with_creation(
        control,
        display_control,
        wait_deadline,
        false,
    )
}

#[cfg(any(unix, windows))]
fn acquire_reconciliation_projection_lock_with_creation(
    control: &cap_std::fs::Dir,
    display_control: &Path,
    wait_deadline: std::time::Duration,
    create_if_missing: bool,
) -> Result<(std::fs::File, TrackedEntryIdentity)> {
    let started = std::time::Instant::now();
    let mut backoff = std::time::Duration::from_millis(25);
    loop {
        match try_acquire_reconciliation_projection_lock(
            control,
            display_control,
            create_if_missing,
        ) {
            Ok((file, identity)) => {
                record_projection_lock_holder(&file);
                return Ok((file, identity));
            }
            Err(ProjectionLockAttemptError::Failed(error)) => return Err(error),
            Err(ProjectionLockAttemptError::Contended(source)) => {
                if started.elapsed() >= wait_deadline {
                    let holder = read_projection_lock_holder(control)
                        .map(|holder| format!(" (lock file records {holder})"))
                        .unwrap_or_default();
                    return Err(KinError::io(
                        display_control.join(RECONCILIATION_PROJECTION_LOCK_FILE),
                        std::io::Error::new(
                            source.kind(),
                            format!(
                                "another exact-source projection is active after waiting \
                                 {:.1}s{holder}: {source}",
                                wait_deadline.as_secs_f64(),
                            ),
                        ),
                    ));
                }
                let remaining = wait_deadline.saturating_sub(started.elapsed());
                std::thread::sleep(backoff.min(remaining));
                backoff = (backoff * 2).min(std::time::Duration::from_millis(250));
            }
        }
    }
}

/// Best-effort holder record written through the held lock handle so a later
/// contender's timeout error can name who was projecting.
#[cfg(any(unix, windows))]
fn record_projection_lock_holder(file: &std::fs::File) {
    use std::io::Seek as _;
    let mut file = file;
    let start_unix_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let _ = file.set_len(0);
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = write!(
        file,
        "pid={} start_unix_s={start_unix_s}",
        std::process::id()
    );
    let _ = file.flush();
}

/// Best-effort read of the holder record; advisory locks do not block reads.
#[cfg(any(unix, windows))]
fn read_projection_lock_holder(control: &cap_std::fs::Dir) -> Option<String> {
    let mut file = open_reconciliation_control_file(
        control,
        std::ffi::OsStr::new(RECONCILIATION_PROJECTION_LOCK_FILE),
    )
    .ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    let trimmed = contents.trim();
    (!trimmed.is_empty() && trimmed.len() <= 128).then(|| trimmed.to_string())
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
enum ExistingReconciliationDisposition {
    Refuse,
    #[cfg(test)]
    Recover,
    Retain,
}

#[cfg(any(unix, windows))]
impl ProjectionRoot {
    fn open(root: &Path) -> Result<Self> {
        Self::open_with_projection_lock_deadline(root, PROJECTION_LOCK_WAIT_DEADLINE)
    }

    #[cfg(test)]
    fn open_session(root: &Path) -> Result<Self> {
        Self::open_with_control_directory(
            root,
            std::ffi::OsStr::new(SESSION_PROJECTION_CONTROL_DIRECTORY),
            PROJECTION_LOCK_WAIT_DEADLINE,
        )
    }

    fn open_session_from_capability(root: cap_std::fs::Dir, display_root: &Path) -> Result<Self> {
        Self::open_with_control_directory_capability(
            root,
            display_root,
            std::ffi::OsStr::new(SESSION_PROJECTION_CONTROL_DIRECTORY),
            PROJECTION_LOCK_WAIT_DEADLINE,
        )
    }

    fn open_with_projection_lock_deadline(
        root: &Path,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        Self::open_with_control_directory(root, std::ffi::OsStr::new(".kin"), lock_deadline)
    }

    fn open_with_control_directory(
        root: &Path,
        projection_control_name: &std::ffi::OsStr,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        let capability = open_projection_root_nofollow(root)?;
        Self::open_with_control_directory_capability(
            capability,
            root,
            projection_control_name,
            lock_deadline,
        )
    }

    fn open_with_control_directory_capability(
        capability: cap_std::fs::Dir,
        root: &Path,
        projection_control_name: &std::ffi::OsStr,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        let display_projection_control = root.join(projection_control_name);
        let kin_control = open_or_create_private_directory(
            &capability,
            projection_control_name,
            &display_projection_control,
        )?;
        let kin_control_identity = tracked_open_directory_identity(&kin_control)
            .map_err(|error| KinError::io(&display_projection_control, error))?;
        let control = open_or_create_private_directory(
            &kin_control,
            std::ffi::OsStr::new(RECONCILIATION_CONTROL_DIRECTORY),
            &display_projection_control.join(RECONCILIATION_CONTROL_DIRECTORY),
        )?;
        let control_identity = tracked_open_directory_identity(&control).map_err(|error| {
            KinError::io(
                display_projection_control.join(RECONCILIATION_CONTROL_DIRECTORY),
                error,
            )
        })?;
        let display_control = display_projection_control.join(RECONCILIATION_CONTROL_DIRECTORY);
        let (projection_lock, projection_lock_identity) =
            acquire_reconciliation_projection_lock(&control, &display_control, lock_deadline)?;
        let authority_key =
            load_or_create_reconciliation_authority_key(&control, &display_control)?;
        let projection = Self {
            root: capability,
            kin_control,
            control,
            projection_lock,
            projection_lock_identity,
            display_root: root.to_path_buf(),
            projection_control_name: projection_control_name.to_os_string(),
            display_projection_control,
            kin_control_identity,
            control_identity,
            authority_key,
        };
        #[cfg(unix)]
        projection.recover_exact_eject()?;
        projection.recover_reconciliation_transactions()?;
        Ok(projection)
    }

    fn retarget_display_root(&mut self, display_root: PathBuf) {
        self.display_projection_control = display_root.join(&self.projection_control_name);
        self.display_root = display_root;
    }

    fn open_existing_for_freeze(root: &Path, lock_deadline: std::time::Duration) -> Result<Self> {
        Self::open_existing_with_reconciliation_disposition(
            root,
            lock_deadline,
            ExistingReconciliationDisposition::Refuse,
        )
    }

    #[cfg(test)]
    fn open_existing_for_reconciliation(
        root: &Path,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        Self::open_existing_with_reconciliation_disposition(
            root,
            lock_deadline,
            ExistingReconciliationDisposition::Recover,
        )
    }

    fn open_existing_for_replay_recovery(
        root: &Path,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        Self::open_existing_with_reconciliation_disposition(
            root,
            lock_deadline,
            ExistingReconciliationDisposition::Retain,
        )
    }

    fn open_existing_with_reconciliation_disposition(
        root: &Path,
        lock_deadline: std::time::Duration,
        disposition: ExistingReconciliationDisposition,
    ) -> Result<Self> {
        let capability = open_projection_root_nofollow(root)?;
        let display_projection_control = root.join(".kin");
        let kin_control = open_directory_nofollow(&capability, std::ffi::OsStr::new(".kin"))
            .map_err(|error| KinError::io(&display_projection_control, error))?;
        let kin_control_identity = tracked_open_directory_identity(&kin_control)
            .map_err(|error| KinError::io(&display_projection_control, error))?;
        let display_control = display_projection_control.join(RECONCILIATION_CONTROL_DIRECTORY);
        let control = open_directory_nofollow(
            &kin_control,
            std::ffi::OsStr::new(RECONCILIATION_CONTROL_DIRECTORY),
        )
        .map_err(|error| KinError::io(&display_control, error))?;
        let control_identity = tracked_open_directory_identity(&control)
            .map_err(|error| KinError::io(&display_control, error))?;
        let (projection_lock, projection_lock_identity) =
            acquire_existing_reconciliation_projection_lock(
                &control,
                &display_control,
                lock_deadline,
            )?;
        let authority_key = load_existing_reconciliation_authority_key(&control, &display_control)?;
        let projection = Self {
            root: capability,
            kin_control,
            control,
            projection_lock,
            projection_lock_identity,
            display_root: root.to_path_buf(),
            projection_control_name: std::ffi::OsString::from(".kin"),
            display_projection_control,
            kin_control_identity,
            control_identity,
            authority_key,
        };
        projection.revalidate_projection_lock()?;
        #[cfg(unix)]
        projection.recover_exact_eject()?;
        match disposition {
            ExistingReconciliationDisposition::Refuse => {
                projection.refuse_reconciliation_transactions()?
            }
            #[cfg(test)]
            ExistingReconciliationDisposition::Recover => {
                projection.recover_reconciliation_transactions()?
            }
            ExistingReconciliationDisposition::Retain => {}
        }
        Ok(projection)
    }

    fn refuse_reconciliation_transactions(&self) -> Result<()> {
        let entries = self
            .control
            .entries()
            .map_err(|error| KinError::io(self.reconciliation_control_path(), error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| KinError::io(self.reconciliation_control_path(), error))?;
            if entry.file_name().to_string_lossy().starts_with("tx-") {
                return Err(KinError::Other(format!(
                    "exact projection freeze refused while reconciliation transaction {} remains; recover it before eject",
                    self.reconciliation_control_path()
                        .join(entry.file_name())
                        .display()
                )));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn authenticate_exact_eject_journal(&self, journal: &ExactEjectJournal) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(journal)
            .map_err(|error| KinError::Other(format!("encode exact eject journal: {error}")))?;
        let mut authenticated = b"kin.exact-eject-journal.v1\0".to_vec();
        authenticated.extend_from_slice(&encoded);
        Ok(reconciliation_hmac(&self.authority_key, &authenticated).to_vec())
    }

    #[cfg(unix)]
    fn persist_exact_eject_journal(
        &self,
        journal: &ExactEjectJournal,
        create_new: bool,
    ) -> Result<()> {
        let authenticated = AuthenticatedExactEjectJournal {
            journal: journal.clone(),
            authentication: self.authenticate_exact_eject_journal(journal)?,
        };
        let bytes = serde_json::to_vec(&authenticated)
            .map_err(|error| KinError::Other(format!("encode exact eject journal: {error}")))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EXACT_EJECT_JOURNAL_BYTES {
            return Err(KinError::Other(format!(
                "exact eject journal exceeds {} KiB",
                MAX_EXACT_EJECT_JOURNAL_BYTES / 1024
            )));
        }
        let display = self
            .reconciliation_control_path()
            .join(EXACT_EJECT_JOURNAL_FILE);
        if create_new {
            ensure_named_entry_absent(
                &self.control,
                std::ffi::OsStr::new(EXACT_EJECT_JOURNAL_FILE),
                &display,
            )?;
        }
        let temporary = OsString::from(format!(".exact-eject-{}.tmp", uuid::Uuid::new_v4()));
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = self
            .control
            .open_with(&temporary, &options)
            .map_err(|error| KinError::io(&display, error))?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| KinError::io(&display, error.into()))?;
        if let Err(error) = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| KinError::io(&display, error))
        {
            drop(file);
            let _ = self.control.remove_file(&temporary);
            return Err(error);
        }
        let publish = if create_new {
            self.control.hard_link(
                &temporary,
                &self.control,
                std::ffi::OsStr::new(EXACT_EJECT_JOURNAL_FILE),
            )
        } else {
            self.control.rename(
                &temporary,
                &self.control,
                std::ffi::OsStr::new(EXACT_EJECT_JOURNAL_FILE),
            )
        };
        if let Err(error) = publish {
            drop(file);
            let _ = self.control.remove_file(&temporary);
            return Err(KinError::io(&display, error));
        }
        file.sync_all()
            .map_err(|error| KinError::io(&display, error))?;
        sync_directory_capability(&self.control, &display)?;
        if create_new {
            self.control
                .remove_file(&temporary)
                .map_err(|error| KinError::io(&display, error))?;
            sync_directory_capability(&self.control, &display)?;
        }
        let persisted = self.load_exact_eject_journal()?.ok_or_else(|| {
            KinError::Other(format!(
                "exact eject journal disappeared after durable publication: {}",
                display.display()
            ))
        })?;
        if persisted != *journal {
            return Err(KinError::Other(format!(
                "exact eject journal changed after durable publication: {}",
                display.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn load_exact_eject_journal(&self) -> Result<Option<ExactEjectJournal>> {
        let display = self
            .reconciliation_control_path()
            .join(EXACT_EJECT_JOURNAL_FILE);
        let file = match open_reconciliation_control_file(
            &self.control,
            std::ffi::OsStr::new(EXACT_EJECT_JOURNAL_FILE),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(&display, error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| KinError::io(&display, error))?;
        if !metadata.is_file() || metadata_is_reparse(&metadata) {
            return Err(KinError::Other(format!(
                "exact eject journal {} is not a regular no-follow file",
                display.display()
            )));
        }
        if metadata.len() > MAX_EXACT_EJECT_JOURNAL_BYTES {
            return Err(KinError::Other(format!(
                "exact eject journal {} exceeds {} KiB",
                display.display(),
                MAX_EXACT_EJECT_JOURNAL_BYTES / 1024
            )));
        }
        let mut bytes = Vec::new();
        file.take(MAX_EXACT_EJECT_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| KinError::io(&display, error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EXACT_EJECT_JOURNAL_BYTES {
            return Err(KinError::Other(format!(
                "exact eject journal {} exceeds {} KiB",
                display.display(),
                MAX_EXACT_EJECT_JOURNAL_BYTES / 1024
            )));
        }
        let authenticated: AuthenticatedExactEjectJournal = serde_json::from_slice(&bytes)
            .map_err(|error| {
                exact_eject_journal_blocked(
                    &display,
                    None,
                    &format!("could not be decoded: {error}"),
                )
            })?;
        let expected = self.authenticate_exact_eject_journal(&authenticated.journal)?;
        if !constant_time_bytes_equal(&authenticated.authentication, &expected) {
            return Err(exact_eject_journal_blocked(
                &display,
                None,
                "failed authentication against this store's authority key",
            ));
        }
        Ok(Some(authenticated.journal))
    }

    /// Retire one journal through the open control handle.
    ///
    /// `display` is where that handle's directory lives now, which after a
    /// finished eject is inside the archive rather than under the root.
    #[cfg(unix)]
    fn remove_exact_eject_journal(
        &self,
        expected: &ExactEjectJournal,
        display: &Path,
    ) -> Result<()> {
        let actual = self.load_exact_eject_journal()?.ok_or_else(|| {
            KinError::Other(format!(
                "exact eject journal disappeared before cleanup: {}",
                display.display()
            ))
        })?;
        if actual != *expected {
            return Err(KinError::Other(format!(
                "exact eject journal changed before cleanup: {}",
                display.display()
            )));
        }
        self.control
            .remove_file(std::ffi::OsStr::new(EXACT_EJECT_JOURNAL_FILE))
            .map_err(|error| KinError::io(display, error))?;
        sync_directory_capability(&self.control, display)
    }

    /// Where the archive an eject journal names would be, for a message.
    #[cfg(unix)]
    fn exact_eject_journal_archive_display(&self, journal: &ExactEjectJournal) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStrExt as _;

        self.display_root
            .parent()
            .map(|parent| parent.join(std::ffi::OsStr::from_bytes(&journal.archive_name)))
    }

    /// Whether `journal` was written for a `.kin` that now lives detached in
    /// the archive it names, so the copy of it found here is a leftover of a
    /// finished eject rather than a transaction to recover.
    ///
    /// Every step binds by identity. The repository root, its parent, the
    /// archive directory, the archived `.kin` and that `.kin`'s reconciliation
    /// directory all have to be the inodes the journal recorded, and the
    /// journal has to be at the detach phase, the only phase that moves
    /// `.kin`. A `.kin` copied out of the archive carries the journal along
    /// under fresh inodes of its own, which is the exact shape an identity
    /// check alone reported as an invalid descriptor. Anything that cannot be
    /// opened or does not match answers `false`, and the caller refuses with
    /// the file and the way out named.
    #[cfg(unix)]
    fn exact_eject_journal_names_a_detached_kin(
        &self,
        journal: &ExactEjectJournal,
        root_identity: TrackedEntryIdentity,
    ) -> Result<bool> {
        use std::os::unix::ffi::OsStrExt as _;

        if journal.phase != ExactEjectJournalPhase::DetachPending
            || journal.root_identity != root_identity
        {
            return Ok(false);
        }
        let (namespace_parent, root_name) =
            self.locate_open_directory(&self.root, root_identity, &self.display_root)?;
        let namespace_parent_identity = tracked_open_directory_identity(&namespace_parent)
            .map_err(|error| KinError::io(&self.display_root, error))?;
        if namespace_parent_identity != journal.namespace_parent_identity
            || root_name.as_bytes() != journal.root_name
        {
            return Ok(false);
        }
        let archive_name = exact_eject_journal_name(&journal.archive_name, "archive directory")?;
        let archived_kin_name =
            exact_eject_journal_name(&journal.archived_kin_name, "archived Kin")?;
        let mut directory = namespace_parent;
        for (name, expected) in [
            (archive_name.as_os_str(), journal.archive_identity),
            (archived_kin_name.as_os_str(), journal.kin_control_identity),
            (
                std::ffi::OsStr::new(RECONCILIATION_CONTROL_DIRECTORY),
                journal.control_identity,
            ),
        ] {
            let Ok(next) = open_directory_nofollow(&directory, name) else {
                return Ok(false);
            };
            let Ok(identity) = tracked_open_directory_identity(&next) else {
                return Ok(false);
            };
            if identity != expected {
                return Ok(false);
            }
            directory = next;
        }
        Ok(true)
    }

    #[cfg(unix)]
    fn recover_exact_eject(&self) -> Result<()> {
        let Some(journal) = self.load_exact_eject_journal()? else {
            return Ok(());
        };
        let journal_path = self
            .reconciliation_control_path()
            .join(EXACT_EJECT_JOURNAL_FILE);
        let archive = self.exact_eject_journal_archive_display(&journal);
        self.revalidate_projection_lock()?;
        let root_identity = tracked_open_directory_identity(&self.root)
            .map_err(|error| KinError::io(&self.display_root, error))?;
        if journal.schema != EXACT_EJECT_JOURNAL_SCHEMA
            || uuid::Uuid::parse_str(&journal.transaction_id).is_err()
        {
            return Err(exact_eject_journal_blocked(
                &journal_path,
                archive.as_deref(),
                "carries a schema or transaction id this build does not recognize",
            ));
        }
        if journal.root_identity != root_identity
            || journal.kin_control_identity != self.kin_control_identity
            || journal.control_identity != self.control_identity
        {
            // The journal names a `.kin` other than the one it was found in.
            // One shape of that is benign and common: a `.kin` copied back out
            // of an eject archive carries the journal of the eject that
            // detached the original, under inodes of its own. When the archive
            // still holds that original, inode for inode, the eject it records
            // finished and the copy has nothing to recover, so the journal is
            // retired here and nothing in the namespace is touched. Every other
            // mismatch is refused with the file and the way out named, because
            // a descriptor that matches nothing could as easily be a forged
            // one, and a forged one must never drive a namespace move.
            if self.exact_eject_journal_names_a_detached_kin(&journal, root_identity)? {
                return self.remove_exact_eject_journal(&journal, &journal_path);
            }
            return Err(exact_eject_journal_blocked(
                &journal_path,
                archive.as_deref(),
                "is bound to a different repository or .kin directory than the one it was found \
                 in, the shape a .kin copied out of an eject archive has",
            ));
        }
        self.replay_exact_eject_journal(&journal, root_identity, &journal_path)
            .map_err(|error| match error {
                KinError::ProjectionBlocked(_) => error,
                error => exact_eject_journal_blocked(
                    &journal_path,
                    archive.as_deref(),
                    &format!("could not be replayed: {error}"),
                ),
            })
    }

    /// Replay one journal whose identities all match this projection: finish
    /// or roll back the namespace moves it records, then retire it.
    #[cfg(unix)]
    fn replay_exact_eject_journal(
        &self,
        journal: &ExactEjectJournal,
        root_identity: TrackedEntryIdentity,
        journal_path: &Path,
    ) -> Result<()> {
        use std::os::unix::ffi::OsStrExt as _;

        let (namespace_parent, root_name) =
            self.locate_open_directory(&self.root, root_identity, &self.display_root)?;
        let namespace_parent_identity = tracked_open_directory_identity(&namespace_parent)
            .map_err(|error| KinError::io(&self.display_root, error))?;
        if namespace_parent_identity != journal.namespace_parent_identity
            || root_name.as_bytes() != journal.root_name
        {
            return Err(KinError::Other(
                "exact eject recovery refused because the projection root namespace changed"
                    .to_string(),
            ));
        }

        let archive_name = exact_eject_journal_name(&journal.archive_name, "archive directory")?;
        let archive = open_directory_nofollow(&namespace_parent, &archive_name)
            .map_err(|error| KinError::io(self.display_root.join(&archive_name), error))?;
        if tracked_open_directory_identity(&archive)
            .map_err(|error| KinError::io(self.display_root.join(&archive_name), error))?
            != journal.archive_identity
        {
            return Err(KinError::Other(
                "exact eject recovery archive changed identity".to_string(),
            ));
        }
        let stage_parent = open_exact_relative_directory_components(
            &namespace_parent,
            &journal.stage_parent_components,
            &self.display_root,
        )?;
        if tracked_open_directory_identity(&stage_parent)
            .map_err(|error| KinError::io(&self.display_root, error))?
            != journal.stage_parent_identity
        {
            return Err(KinError::Other(
                "exact eject recovery stage parent changed identity".to_string(),
            ));
        }
        let stage_name = exact_eject_journal_name(&journal.stage_name, "staged Git")?;
        let archived_git_name =
            exact_eject_journal_name(&journal.archived_git_name, "archived Git")?;
        let archived_kin_name =
            exact_eject_journal_name(&journal.archived_kin_name, "archived Kin")?;
        ensure_named_entry_absent(
            &archive,
            &archived_kin_name,
            &self
                .display_root
                .join(&archive_name)
                .join(&archived_kin_name),
        )?;
        let git_name = std::ffi::OsStr::new(".git");

        let root_entry = self.inspect_exact_eject_named_entry(
            &self.root,
            git_name,
            &self.display_root.join(".git"),
        )?;
        let stage_entry = self.inspect_exact_eject_named_entry(
            &stage_parent,
            &stage_name,
            &self.display_root.join(&stage_name),
        )?;
        let archive_entry = self.inspect_exact_eject_named_entry(
            &archive,
            &archived_git_name,
            &self
                .display_root
                .join(&archive_name)
                .join(&archived_git_name),
        )?;
        let previous_identity = journal
            .previous_git
            .as_ref()
            .map(exact_eject_previous_git_identity);

        let root_is_stage =
            root_entry.is_some_and(|(_, identity)| identity == journal.stage_identity);
        let root_is_previous = previous_identity
            .is_some_and(|identity| root_entry.is_some_and(|(_, actual)| actual == identity));
        let stage_is_stage =
            stage_entry.is_some_and(|(_, identity)| identity == journal.stage_identity);
        let archive_is_previous = previous_identity
            .is_some_and(|identity| archive_entry.is_some_and(|(_, actual)| actual == identity));

        if root_entry.is_some() && !root_is_stage && !root_is_previous {
            return Err(KinError::Other(
                "exact eject recovery found an unexpected replacement at root `.git`".to_string(),
            ));
        }
        if stage_entry.is_some() && !stage_is_stage {
            return Err(KinError::Other(
                "exact eject recovery found an unexpected replacement at the staged Git name"
                    .to_string(),
            ));
        }
        if archive_entry.is_some() && !archive_is_previous {
            return Err(KinError::Other(
                "exact eject recovery found an unexpected replacement at the archived Git name"
                    .to_string(),
            ));
        }

        if root_is_stage {
            self.validate_exact_eject_stage_at(
                &self.root,
                git_name,
                &journal,
                &self.display_root.join(".git"),
            )?;
        }
        if stage_is_stage {
            self.validate_exact_eject_stage_at(
                &stage_parent,
                &stage_name,
                &journal,
                &self.display_root.join(&stage_name),
            )?;
        }
        if root_is_previous {
            self.validate_exact_eject_previous_at(
                &self.root,
                git_name,
                journal.previous_git.as_ref().expect("identity is present"),
                &self.display_root.join(".git"),
            )?;
        }
        if archive_is_previous {
            self.validate_exact_eject_previous_at(
                &archive,
                &archived_git_name,
                journal.previous_git.as_ref().expect("identity is present"),
                &self
                    .display_root
                    .join(&archive_name)
                    .join(&archived_git_name),
            )?;
        }

        let valid_prepared = stage_is_stage
            && archive_entry.is_none()
            && match journal.previous_git.as_ref() {
                Some(_) => root_is_previous,
                None => root_entry.is_none(),
            };
        let valid_previous_archived = stage_is_stage
            && root_entry.is_none()
            && match journal.previous_git.as_ref() {
                Some(_) => archive_is_previous,
                None => archive_entry.is_none(),
            };
        let valid_stage_installed = root_is_stage
            && stage_entry.is_none()
            && match journal.previous_git.as_ref() {
                Some(_) => archive_is_previous,
                None => archive_entry.is_none(),
            };
        if !valid_prepared && !valid_previous_archived && !valid_stage_installed {
            return Err(KinError::Other(format!(
                "exact eject journal {} does not match any recoverable namespace state",
                self.reconciliation_control_path()
                    .join(EXACT_EJECT_JOURNAL_FILE)
                    .display()
            )));
        }

        if valid_stage_installed {
            let stage = open_directory_nofollow_for_removal(&self.root, git_name)
                .map_err(|error| KinError::io(self.display_root.join(".git"), error))?;
            self.move_open_directory_from_expected_source_exact(
                NamedEntryLocation {
                    parent: &self.root,
                    name: git_name,
                },
                NamedEntryLocation {
                    parent: &stage_parent,
                    name: &stage_name,
                },
                &stage,
                journal.stage_identity,
                &self.display_root.join(".git"),
            )?;
        }
        if valid_previous_archived || valid_stage_installed {
            if let Some(previous) = journal.previous_git.as_ref() {
                let retained = self.open_exact_eject_previous_at(
                    &archive,
                    &archived_git_name,
                    previous,
                    &self
                        .display_root
                        .join(&archive_name)
                        .join(&archived_git_name),
                )?;
                self.move_retained_git_entry_exact(
                    NamedEntryLocation {
                        parent: &archive,
                        name: &archived_git_name,
                    },
                    NamedEntryLocation {
                        parent: &self.root,
                        name: git_name,
                    },
                    &retained,
                    &self.display_root.join(".git"),
                )?;
            }
        }

        self.validate_exact_eject_stage_at(
            &stage_parent,
            &stage_name,
            &journal,
            &self.display_root.join(&stage_name),
        )?;
        ensure_named_entry_absent(
            &archive,
            &archived_git_name,
            &self
                .display_root
                .join(&archive_name)
                .join(&archived_git_name),
        )?;
        ensure_named_entry_absent(
            &archive,
            &archived_kin_name,
            &self
                .display_root
                .join(&archive_name)
                .join(&archived_kin_name),
        )?;
        match journal.previous_git.as_ref() {
            Some(previous) => self.validate_exact_eject_previous_at(
                &self.root,
                git_name,
                previous,
                &self.display_root.join(".git"),
            )?,
            None => {
                ensure_named_entry_absent(&self.root, git_name, &self.display_root.join(".git"))?
            }
        }
        self.remove_exact_eject_journal(journal, journal_path)
    }

    #[cfg(unix)]
    fn inspect_exact_eject_named_entry(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<Option<(bool, TrackedEntryIdentity)>> {
        let metadata = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(display, error)),
        };
        if metadata_is_reparse(&metadata) || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(KinError::Other(format!(
                "exact eject recovery entry {} has an unsupported kind",
                display.display()
            )));
        }
        Ok(Some((metadata.is_dir(), tracked_entry_identity(&metadata))))
    }

    #[cfg(unix)]
    fn validate_exact_eject_stage_at(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        journal: &ExactEjectJournal,
        display: &Path,
    ) -> Result<()> {
        let directory =
            open_directory_nofollow(parent, name).map_err(|error| KinError::io(display, error))?;
        if tracked_open_directory_identity(&directory)
            .map_err(|error| KinError::io(display, error))?
            != journal.stage_identity
            || seal_exact_git_directory(&directory, display)? != journal.stage_seal
        {
            return Err(KinError::Other(format!(
                "exact eject recovery staged Git {} failed its identity or descendant seal",
                display.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn validate_exact_eject_previous_at(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        expected: &ExactEjectPreviousGit,
        display: &Path,
    ) -> Result<()> {
        let retained = self.open_exact_eject_previous_at(parent, name, expected, display)?;
        self.validate_retained_git_entry_at(&retained, parent, name, display)
    }

    #[cfg(unix)]
    fn open_exact_eject_previous_at(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        expected: &ExactEjectPreviousGit,
        display: &Path,
    ) -> Result<RetainedGitEntry> {
        match expected {
            ExactEjectPreviousGit::File { identity, state } => {
                let (actual_identity, actual_state) = self.inspect_named_existing_object(
                    parent,
                    name,
                    ExistingObjectKind::File,
                    display,
                )?;
                let file = open_regular_file_nofollow_for_removal(parent, name)
                    .map_err(|error| KinError::io(display, error))?;
                if actual_identity != *identity
                    || actual_state != *state
                    || tracked_cap_file_identity(&file)
                        .map_err(|error| KinError::io(display, error))?
                        != *identity
                {
                    return Err(KinError::Other(format!(
                        "exact eject recovery previous Git file {} changed",
                        display.display()
                    )));
                }
                Ok(RetainedGitEntry::File {
                    file,
                    identity: *identity,
                    state: *state,
                })
            }
            ExactEjectPreviousGit::Directory { identity, seal } => {
                let directory = open_directory_nofollow_for_removal(parent, name)
                    .map_err(|error| KinError::io(display, error))?;
                if tracked_open_directory_identity(&directory)
                    .map_err(|error| KinError::io(display, error))?
                    != *identity
                    || seal_exact_git_directory(&directory, display)? != *seal
                {
                    return Err(KinError::Other(format!(
                        "exact eject recovery previous Git directory {} changed",
                        display.display()
                    )));
                }
                Ok(RetainedGitEntry::Directory {
                    directory,
                    identity: *identity,
                    seal: *seal,
                })
            }
        }
    }

    fn create_reconciliation_transaction(&self) -> Result<ReconciliationTransaction> {
        self.create_reconciliation_transaction_with_commit_markers(None, None)
    }

    fn create_reconciliation_transaction_with_commit_markers(
        &self,
        authority_commit: Option<ReconciliationAuthorityCommit>,
        checkout_projection_commit: Option<CheckoutProjectionReceipt>,
    ) -> Result<ReconciliationTransaction> {
        if authority_commit.is_some() && checkout_projection_commit.is_some() {
            return Err(KinError::Other(
                "one projection WAL cannot mix repository and local checkout commit markers"
                    .to_string(),
            ));
        }
        self.revalidate_projection_lock()?;
        for _ in 0..8 {
            let id = uuid::Uuid::new_v4().to_string();
            let name = OsString::from(format!("tx-{id}"));
            match self.control.create_dir(&name) {
                Ok(()) => {
                    let directory = open_directory_nofollow_for_removal(&self.control, &name)
                        .map_err(|error| {
                            KinError::io(self.reconciliation_control_path().join(&name), error)
                        })?;
                    #[cfg(unix)]
                    rustix::fs::fchmod(&directory, rustix::fs::Mode::from_raw_mode(0o700))
                        .map_err(|error| {
                            KinError::io(
                                self.reconciliation_control_path().join(&name),
                                error.into(),
                            )
                        })?;
                    let identity =
                        tracked_open_directory_identity(&directory).map_err(|error| {
                            KinError::io(self.reconciliation_control_path().join(&name), error)
                        })?;
                    sync_directory_capability(&self.control, &self.reconciliation_control_path())?;
                    let root_identity = tracked_open_directory_identity(&self.root)
                        .map_err(|error| KinError::io(&self.display_root, error))?;
                    let mut transaction = ReconciliationTransaction {
                        name,
                        directory,
                        identity,
                        manifest: ReconciliationManifest {
                            schema: RECONCILIATION_MANIFEST_SCHEMA,
                            transaction_id: id,
                            root_identity,
                            kin_control_identity: self.kin_control_identity,
                            control_identity: self.control_identity,
                            transaction_identity: identity,
                            authority_commit: authority_commit.clone(),
                            checkout_projection_commit: checkout_projection_commit.clone(),
                            state: ReconciliationTransactionState::Pending,
                            actions: Vec::new(),
                        },
                        action_log_bytes: 0,
                        action_tail_authentication: Vec::new(),
                    };
                    if let Err(error) = self.persist_reconciliation_manifest(&transaction) {
                        let cleanup = self.cleanup_reconciliation_transaction(transaction);
                        return match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup_error) => Err(KinError::Other(format!(
                                "{error}; empty reconciliation transaction cleanup also failed: {cleanup_error}"
                            ))),
                        };
                    }
                    // Keep the value mutable at its construction boundary so
                    // every later namespace intent can be journaled in-place.
                    transaction.manifest.actions.reserve(16);
                    return Ok(transaction);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(KinError::io(
                        self.reconciliation_control_path().join(&name),
                        error,
                    ));
                }
            }
        }
        Err(KinError::Other(
            "could not allocate a unique exact-source reconciliation transaction".to_string(),
        ))
    }

    fn cleanup_reconciliation_transaction(
        &self,
        transaction: ReconciliationTransaction,
    ) -> Result<()> {
        let display = self.reconciliation_control_path().join(&transaction.name);
        let actual = tracked_open_directory_identity(&transaction.directory)
            .map_err(|error| KinError::io(&display, error))?;
        if actual != transaction.identity {
            return Err(KinError::Other(format!(
                "exact-source transaction capability identity changed for {}",
                display.display()
            )));
        }
        #[cfg(unix)]
        transaction
            .directory
            .remove_open_dir_all()
            .map_err(|error| KinError::io(display, error))?;
        #[cfg(windows)]
        {
            self.remove_windows_directory_contents(
                &transaction.directory,
                Path::new(&transaction.name),
            )?;
            mark_windows_directory_for_deletion(transaction.directory)
                .map_err(|error| KinError::io(display, error))?;
        }
        sync_directory_capability(&self.control, &self.reconciliation_control_path())?;
        Ok(())
    }

    fn reconciliation_control_path(&self) -> PathBuf {
        self.display_projection_control
            .join(RECONCILIATION_CONTROL_DIRECTORY)
    }

    fn install_session_base_metadata(&self, metadata: &[u8]) -> Result<()> {
        if self.projection_control_name
            != std::ffi::OsStr::new(SESSION_PROJECTION_CONTROL_DIRECTORY)
        {
            return Err(KinError::Other(
                "session base metadata may only be installed in a session projection".to_string(),
            ));
        }
        self.revalidate_projection_lock()?;
        let display = self
            .display_projection_control
            .join(SESSION_PROJECTION_BASE_FILE);
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = self
            .kin_control
            .open_with(SESSION_PROJECTION_BASE_FILE, &options)
            .map_err(|error| KinError::io(&display, error))?;
        #[cfg(unix)]
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| KinError::io(&display, error.into()))?;
        file.write_all(metadata)
            .and_then(|()| file.sync_all())
            .map_err(|error| KinError::io(&display, error))?;
        sync_directory_capability(&self.kin_control, &self.display_projection_control)?;
        self.revalidate_projection_lock()
    }

    fn revalidate_projection_lock(&self) -> Result<()> {
        // Read-only identity check, not a removal: requesting DELETE access on
        // the control directory here would be vetoed on Windows by a live
        // graph-store handle under a primary `.kin`, and is unnecessary for
        // the session-owned `.kin-session` control plane.
        let named_kin = open_directory_nofollow(&self.root, &self.projection_control_name)
            .map_err(|error| KinError::io(&self.display_projection_control, error))?;
        if tracked_open_directory_identity(&named_kin)
            .map_err(|error| KinError::io(&self.display_projection_control, error))?
            != self.kin_control_identity
        {
            let control_kind =
                if self.projection_control_name.as_os_str() == std::ffi::OsStr::new(".kin") {
                    "repository control directory"
                } else {
                    "session projection control directory"
                };
            return Err(KinError::Other(format!(
                "{control_kind} {} was replaced while the projection lock was held",
                self.display_projection_control.display()
            )));
        }
        self.revalidate_retained_projection_control()
    }

    fn revalidate_retained_projection_control(&self) -> Result<()> {
        if tracked_open_directory_identity(&self.kin_control)
            .map_err(|error| KinError::io(&self.display_projection_control, error))?
            != self.kin_control_identity
        {
            return Err(KinError::Other(format!(
                "retained projection control directory {} changed identity",
                self.display_projection_control.display()
            )));
        }
        // Read-only identity check, matching the control-root open above. The
        // reconciliation directory is projection-owned and does not collide
        // today, but narrowing it closes the gratuitous-DELETE-access class.
        let named_control = open_directory_nofollow(
            &self.kin_control,
            std::ffi::OsStr::new(RECONCILIATION_CONTROL_DIRECTORY),
        )
        .map_err(|error| KinError::io(self.reconciliation_control_path(), error))?;
        if tracked_open_directory_identity(&named_control)
            .map_err(|error| KinError::io(self.reconciliation_control_path(), error))?
            != self.control_identity
        {
            return Err(KinError::Other(format!(
                "reconciliation control directory {} was replaced while the projection lock was held",
                self.reconciliation_control_path().display()
            )));
        }
        let display = self
            .reconciliation_control_path()
            .join(RECONCILIATION_PROJECTION_LOCK_FILE);
        let held_identity = tracked_open_file_identity_for_std(&self.projection_lock)
            .map_err(|error| KinError::io(&display, error))?;
        if held_identity != self.projection_lock_identity {
            return Err(KinError::Other(format!(
                "projection lock capability changed identity for {}",
                display.display()
            )));
        }
        let named = open_reconciliation_control_file(
            &self.control,
            std::ffi::OsStr::new(RECONCILIATION_PROJECTION_LOCK_FILE),
        )
        .map_err(|error| KinError::io(&display, error))?;
        if tracked_cap_file_identity(&named).map_err(|error| KinError::io(&display, error))?
            != self.projection_lock_identity
        {
            return Err(KinError::Other(format!(
                "projection lock {} was replaced while held; refusing namespace mutation",
                display.display()
            )));
        }
        Ok(())
    }

    fn checkout_projection_receipt_name(operation_id: OperationId) -> OsString {
        OsString::from(format!(
            "{CHECKOUT_PROJECTION_RECEIPT_PREFIX}{}.json",
            operation_id
        ))
    }

    fn authenticate_checkout_projection_receipt(
        &self,
        receipt: &CheckoutProjectionReceipt,
    ) -> Result<Vec<u8>> {
        receipt.validate()?;
        let encoded = serde_json::to_vec(receipt).map_err(|error| {
            KinError::Other(format!("encode checkout projection receipt: {error}"))
        })?;
        let mut authenticated = b"kin.checkout-projection-receipt.v1\0".to_vec();
        authenticated.extend_from_slice(&encoded);
        Ok(reconciliation_hmac(&self.authority_key, &authenticated).to_vec())
    }

    fn load_checkout_projection_receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CheckoutProjectionReceipt>> {
        let name = Self::checkout_projection_receipt_name(operation_id);
        let display = self.reconciliation_control_path().join(&name);
        let file = match open_reconciliation_control_file(&self.control, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(&display, error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| KinError::io(&display, error))?;
        if metadata.len() > MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES {
            return Err(KinError::Other(format!(
                "checkout projection receipt {} exceeds {} KiB",
                display.display(),
                MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES / 1024
            )));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| KinError::io(&display, error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES {
            return Err(KinError::Other(format!(
                "checkout projection receipt {} exceeds its read bound",
                display.display()
            )));
        }
        let authenticated: AuthenticatedCheckoutProjectionReceipt = serde_json::from_slice(&bytes)
            .map_err(|error| {
                KinError::Other(format!(
                    "decode checkout projection receipt {}: {error}",
                    display.display()
                ))
            })?;
        if authenticated.receipt.operation_id != operation_id {
            return Err(KinError::Other(format!(
                "checkout projection receipt {} has the wrong operation identity",
                display.display()
            )));
        }
        let expected = self.authenticate_checkout_projection_receipt(&authenticated.receipt)?;
        let valid = authenticated.authentication.len() == expected.len()
            && authenticated
                .authentication
                .iter()
                .zip(&expected)
                .fold(0_u8, |difference, (actual, expected)| {
                    difference | (*actual ^ *expected)
                })
                == 0;
        if !valid {
            return Err(KinError::Other(format!(
                "checkout projection receipt {} failed authentication",
                display.display()
            )));
        }
        Ok(Some(authenticated.receipt))
    }

    fn persist_checkout_projection_receipt(
        &self,
        receipt: &CheckoutProjectionReceipt,
    ) -> Result<()> {
        receipt.validate()?;
        if let Some(existing) = self.load_checkout_projection_receipt(receipt.operation_id)? {
            if existing == *receipt {
                return Ok(());
            }
            return Err(KinError::Other(format!(
                "checkout operation {} already has a different projection receipt",
                receipt.operation_id
            )));
        }
        let authenticated = AuthenticatedCheckoutProjectionReceipt {
            receipt: receipt.clone(),
            authentication: self.authenticate_checkout_projection_receipt(receipt)?,
        };
        let bytes = serde_json::to_vec(&authenticated).map_err(|error| {
            KinError::Other(format!(
                "encode authenticated checkout projection receipt: {error}"
            ))
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES {
            return Err(KinError::Other(format!(
                "checkout projection receipt exceeds {} KiB",
                MAX_CHECKOUT_PROJECTION_RECEIPT_BYTES / 1024
            )));
        }
        let name = Self::checkout_projection_receipt_name(receipt.operation_id);
        let display = self.reconciliation_control_path().join(&name);
        let temporary = OsString::from(format!(".checkout-receipt-{}.tmp", uuid::Uuid::new_v4()));
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = self
            .control
            .open_with(&temporary, &options)
            .map_err(|error| KinError::io(&display, error))?;
        #[cfg(unix)]
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| KinError::io(&display, error.into()))?;
        if let Err(error) = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| KinError::io(&display, error))
        {
            drop(file);
            let _ = self.control.remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = self.control.hard_link(&temporary, &self.control, &name) {
            drop(file);
            let _ = self.control.remove_file(&temporary);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                let existing = self
                    .load_checkout_projection_receipt(receipt.operation_id)?
                    .ok_or_else(|| {
                        KinError::Other(format!(
                            "checkout receipt {} appeared and disappeared during publication",
                            display.display()
                        ))
                    })?;
                if existing == *receipt {
                    return Ok(());
                }
            }
            return Err(KinError::io(&display, error));
        }
        drop(file);
        sync_directory_capability(&self.control, &display)?;
        self.control
            .remove_file(&temporary)
            .map_err(|error| KinError::io(&display, error))?;
        sync_directory_capability(&self.control, &display)?;
        let installed = self
            .load_checkout_projection_receipt(receipt.operation_id)?
            .ok_or_else(|| {
                KinError::Other(format!(
                    "checkout projection receipt {} disappeared after publication",
                    display.display()
                ))
            })?;
        if installed != *receipt {
            return Err(KinError::Other(format!(
                "checkout projection receipt {} changed after publication",
                display.display()
            )));
        }
        Ok(())
    }

    fn checkout_projection_commit_is_installed_with_authority(
        &self,
        marker: &CheckoutProjectionReceipt,
        authority: Option<&RepositoryAuthorityState>,
    ) -> Result<bool> {
        let Some(installed) = self.load_checkout_projection_receipt(marker.operation_id)? else {
            return Ok(false);
        };
        if installed != *marker {
            return Err(KinError::Other(format!(
                "checkout operation {} exists with a different projection identity during recovery",
                marker.operation_id
            )));
        }
        let authority = authority.ok_or_else(|| {
            KinError::Other(format!(
                "checkout projection recovery at {} requires an explicitly retained frozen \
                 repository authority; refusing ambient path reopen",
                self.display_root.display()
            ))
        })?;
        validate_checkout_projection_workspace(authority, marker)?;
        Ok(true)
    }

    fn authenticate_reconciliation_manifest(
        &self,
        manifest: &ReconciliationManifest,
    ) -> Result<Vec<u8>> {
        let encoded = serde_json::to_vec(manifest)
            .map_err(|error| KinError::Other(format!("encode reconciliation manifest: {error}")))?;
        Ok(reconciliation_hmac(&self.authority_key, &encoded).to_vec())
    }

    fn persist_reconciliation_manifest(
        &self,
        transaction: &ReconciliationTransaction,
    ) -> Result<()> {
        let mut descriptor = transaction.manifest.clone();
        // Recovery actions live in the append-only authenticated WAL. Keeping
        // the fixed descriptor action-free makes every phase update bounded,
        // independent of repository size.
        descriptor.actions.clear();
        let authenticated = AuthenticatedReconciliationManifest {
            authentication: self.authenticate_reconciliation_manifest(&descriptor)?,
            manifest: descriptor,
        };
        let bytes = serde_json::to_vec(&authenticated).map_err(|error| {
            KinError::Other(format!(
                "encode authenticated reconciliation manifest: {error}"
            ))
        })?;
        let temporary = OsString::from(format!(".manifest-{}.tmp", uuid::Uuid::new_v4()));
        let display = self
            .reconciliation_control_path()
            .join(&transaction.name)
            .join(RECONCILIATION_MANIFEST_FILE);
        // Every step below reports the same manifest path; on Windows the control
        // renames all funnel through one handle helper, so tag each operation so CI
        // failure output identifies which step failed rather than only the path. Unix
        // keeps the bare path so existing error-path expectations are unchanged.
        #[cfg(windows)]
        let step = |name: &str| -> PathBuf {
            let mut raw = display.as_os_str().to_os_string();
            raw.push(" [");
            raw.push(name);
            raw.push("]");
            PathBuf::from(raw)
        };
        #[cfg(not(windows))]
        let step = |_name: &str| -> PathBuf { display.clone() };
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            options
                .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        }
        let mut file = transaction
            .directory
            .open_with(&temporary, &options)
            .map_err(|error| KinError::io(step("create-temp"), error))?;
        #[cfg(unix)]
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| KinError::io(&display, error.into()))?;
        let write_result = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| KinError::io(step("write-temp"), error));
        if let Err(error) = write_result {
            drop(file);
            let _ = transaction.directory.remove_file(&temporary);
            return Err(error);
        }
        #[cfg(unix)]
        let publish = transaction.directory.rename(
            &temporary,
            &transaction.directory,
            std::ffi::OsStr::new(RECONCILIATION_MANIFEST_FILE),
        );
        #[cfg(windows)]
        let publish = replace_windows_file_handle_exact(
            &file,
            &transaction.directory,
            std::ffi::OsStr::new(RECONCILIATION_MANIFEST_FILE),
            true,
        );
        if let Err(error) = publish {
            drop(file);
            let _ = transaction.directory.remove_file(&temporary);
            return Err(KinError::io(step("publish-rename"), error));
        }
        file.sync_all()
            .map_err(|error| KinError::io(step("sync-final"), error))?;
        drop(file);
        sync_directory_capability(&transaction.directory, &display)?;
        Ok(())
    }

    fn record_reconciliation_action(
        &self,
        transaction: &mut ReconciliationTransaction,
        action: ReconciliationRecoveryAction,
    ) -> Result<()> {
        if transaction.manifest.actions.len() >= MAX_RECONCILIATION_ACTIONS {
            return Err(KinError::Other(format!(
                "exact-source reconciliation exceeds the bounded {}-action recovery log",
                MAX_RECONCILIATION_ACTIONS
            )));
        }
        let sequence = u64::try_from(transaction.manifest.actions.len()).map_err(|_| {
            KinError::Other("exact-source recovery action sequence overflow".to_string())
        })?;
        let previous_authentication = transaction.action_tail_authentication.clone();
        let authentication =
            self.authenticate_reconciliation_action(sequence, &previous_authentication, &action)?;
        let record = AuthenticatedReconciliationAction {
            sequence,
            previous_authentication,
            action: action.clone(),
            authentication: authentication.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            KinError::Other(format!(
                "encode authenticated reconciliation action: {error}"
            ))
        })?;
        let record_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if record_bytes > MAX_RECONCILIATION_ACTION_RECORD_BYTES
            || transaction.action_log_bytes.saturating_add(record_bytes)
                > MAX_RECONCILIATION_ACTION_LOG_BYTES
        {
            return Err(KinError::Other(format!(
                "exact-source reconciliation action log exceeds its bounded {} MiB recovery limit",
                MAX_RECONCILIATION_ACTION_LOG_BYTES / (1024 * 1024)
            )));
        }

        let name = format!("{RECONCILIATION_ACTION_FILE_PREFIX}{sequence:020}.json");
        let temporary = OsString::from(format!(".action-{}.tmp", uuid::Uuid::new_v4()));
        let display = self
            .reconciliation_control_path()
            .join(&transaction.name)
            .join(&name);
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = transaction
            .directory
            .open_with(&temporary, &options)
            .map_err(|error| KinError::io(&display, error))?;
        #[cfg(unix)]
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| KinError::io(&display, error.into()))?;
        if let Err(error) = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| KinError::io(&display, error))
        {
            drop(file);
            let _ = transaction.directory.remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = transaction
            .directory
            .hard_link(&temporary, &transaction.directory, &name)
            .map_err(|error| KinError::io(&display, error))
        {
            drop(file);
            let _ = transaction.directory.remove_file(&temporary);
            return Err(error);
        }
        file.sync_all()
            .map_err(|error| KinError::io(&display, error))?;
        sync_directory_capability(&transaction.directory, &display)?;
        transaction
            .directory
            .remove_file(&temporary)
            .map_err(|error| KinError::io(&display, error))?;
        sync_directory_capability(&transaction.directory, &display)?;

        transaction.manifest.actions.push(action);
        transaction.action_log_bytes += record_bytes;
        transaction.action_tail_authentication = authentication;
        Ok(())
    }

    fn authenticate_reconciliation_action(
        &self,
        sequence: u64,
        previous_authentication: &[u8],
        action: &ReconciliationRecoveryAction,
    ) -> Result<Vec<u8>> {
        let encoded =
            serde_json::to_vec(&(sequence, previous_authentication, action)).map_err(|error| {
                KinError::Other(format!("encode reconciliation action payload: {error}"))
            })?;
        Ok(reconciliation_hmac(&self.authority_key, &encoded).to_vec())
    }

    fn load_reconciliation_manifest(
        &self,
        transaction_name: &std::ffi::OsStr,
        directory: &cap_std::fs::Dir,
    ) -> Result<Option<ReconciliationManifest>> {
        let display = self
            .reconciliation_control_path()
            .join(transaction_name)
            .join(RECONCILIATION_MANIFEST_FILE);
        let file = match open_reconciliation_control_file(
            directory,
            std::ffi::OsStr::new(RECONCILIATION_MANIFEST_FILE),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(&display, error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| KinError::io(&display, error))?;
        if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
            return Err(KinError::Other(format!(
                "reconciliation manifest {} is not a bounded regular file",
                display.display()
            )));
        }
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| KinError::io(&display, error))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(KinError::Other(format!(
                "reconciliation manifest {} exceeds 4 MiB",
                display.display()
            )));
        }
        let authenticated: AuthenticatedReconciliationManifest = serde_json::from_slice(&bytes)
            .map_err(|error| {
                KinError::Other(format!(
                    "decode reconciliation manifest {}: {error}",
                    display.display()
                ))
            })?;
        let encoded = serde_json::to_vec(&authenticated.manifest)
            .map_err(|error| KinError::Other(format!("encode reconciliation manifest: {error}")))?;
        let expected = reconciliation_hmac(&self.authority_key, &encoded);
        let authentication_valid = authenticated.authentication.len() == expected.len()
            && authenticated
                .authentication
                .iter()
                .zip(expected)
                .fold(0_u8, |difference, (actual, expected)| {
                    difference | (*actual ^ expected)
                })
                == 0;
        if !authentication_valid {
            return Err(KinError::Other(format!(
                "reconciliation manifest {} failed authentication",
                display.display()
            )));
        }
        Ok(Some(authenticated.manifest))
    }

    fn load_reconciliation_actions(
        &self,
        transaction_name: &std::ffi::OsStr,
        directory: &cap_std::fs::Dir,
    ) -> Result<(Vec<ReconciliationRecoveryAction>, u64, Vec<u8>)> {
        let mut names = Vec::new();
        for entry in directory.entries().map_err(|error| {
            KinError::io(
                self.reconciliation_control_path().join(transaction_name),
                error,
            )
        })? {
            let entry = entry.map_err(|error| {
                KinError::io(
                    self.reconciliation_control_path().join(transaction_name),
                    error,
                )
            })?;
            let name = entry.file_name();
            if name.to_str().is_some_and(|name| {
                name.starts_with(RECONCILIATION_ACTION_FILE_PREFIX) && name.ends_with(".json")
            }) {
                names.push(name);
            }
        }
        names.sort();
        if names.len() > MAX_RECONCILIATION_ACTIONS {
            return Err(KinError::Other(format!(
                "reconciliation transaction {} exceeds the bounded action count",
                self.reconciliation_control_path()
                    .join(transaction_name)
                    .display()
            )));
        }

        let mut actions = Vec::with_capacity(names.len());
        let mut total_bytes = 0_u64;
        let mut tail = Vec::new();
        for (index, name) in names.into_iter().enumerate() {
            let expected_name = format!("{RECONCILIATION_ACTION_FILE_PREFIX}{index:020}.json");
            if name != std::ffi::OsStr::new(&expected_name) {
                return Err(KinError::Other(format!(
                    "reconciliation action log {} is not contiguous at sequence {}",
                    self.reconciliation_control_path()
                        .join(transaction_name)
                        .display(),
                    index
                )));
            }
            let display = self
                .reconciliation_control_path()
                .join(transaction_name)
                .join(&name);
            let file = open_reconciliation_control_file(directory, &name)
                .map_err(|error| KinError::io(&display, error))?;
            let metadata = file
                .metadata()
                .map_err(|error| KinError::io(&display, error))?;
            if !metadata.is_file() || metadata.len() > MAX_RECONCILIATION_ACTION_RECORD_BYTES {
                return Err(KinError::Other(format!(
                    "reconciliation action {} is not a bounded regular file",
                    display.display()
                )));
            }
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > MAX_RECONCILIATION_ACTION_LOG_BYTES {
                return Err(KinError::Other(format!(
                    "reconciliation action log {} exceeds {} MiB",
                    self.reconciliation_control_path()
                        .join(transaction_name)
                        .display(),
                    MAX_RECONCILIATION_ACTION_LOG_BYTES / (1024 * 1024)
                )));
            }
            let mut bytes = Vec::new();
            file.take(MAX_RECONCILIATION_ACTION_RECORD_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| KinError::io(&display, error))?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                > MAX_RECONCILIATION_ACTION_RECORD_BYTES
            {
                return Err(KinError::Other(format!(
                    "reconciliation action {} exceeds its record bound",
                    display.display()
                )));
            }
            let record: AuthenticatedReconciliationAction = serde_json::from_slice(&bytes)
                .map_err(|error| {
                    KinError::Other(format!(
                        "decode reconciliation action {}: {error}",
                        display.display()
                    ))
                })?;
            if record.sequence != index as u64 || record.previous_authentication != tail {
                return Err(KinError::Other(format!(
                    "reconciliation action {} broke the authenticated sequence chain",
                    display.display()
                )));
            }
            let expected = self.authenticate_reconciliation_action(
                record.sequence,
                &record.previous_authentication,
                &record.action,
            )?;
            let authentication_valid = record.authentication.len() == expected.len()
                && record
                    .authentication
                    .iter()
                    .zip(&expected)
                    .fold(0_u8, |difference, (actual, expected)| {
                        difference | (*actual ^ *expected)
                    })
                    == 0;
            if !authentication_valid {
                return Err(KinError::Other(format!(
                    "reconciliation action {} failed authentication",
                    display.display()
                )));
            }
            tail = record.authentication;
            actions.push(record.action);
        }
        Ok((actions, total_bytes, tail))
    }

    fn recover_reconciliation_transactions(&self) -> Result<()> {
        self.recover_reconciliation_transactions_with_optional_authority(None)
    }

    fn recover_reconciliation_transactions_with_authority(
        &self,
        authority: &RepositoryAuthorityState,
    ) -> Result<()> {
        self.recover_reconciliation_transactions_with_optional_authority(Some(authority))
    }

    fn recover_reconciliation_transactions_with_optional_authority(
        &self,
        authority: Option<&RepositoryAuthorityState>,
    ) -> Result<()> {
        self.revalidate_projection_lock()?;
        let root_identity = tracked_open_directory_identity(&self.root)
            .map_err(|error| KinError::io(&self.display_root, error))?;
        let mut transactions = Vec::new();
        let entries = self
            .control
            .entries()
            .map_err(|error| KinError::io(self.reconciliation_control_path(), error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| KinError::io(self.reconciliation_control_path(), error))?;
            let name = entry.file_name();
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if !name_text.starts_with("tx-") {
                continue;
            }
            transactions.push(name);
        }
        transactions.sort();

        for name in transactions {
            let directory =
                open_directory_nofollow_for_removal(&self.control, &name).map_err(|error| {
                    KinError::io(self.reconciliation_control_path().join(&name), error)
                })?;
            let identity = tracked_open_directory_identity(&directory).map_err(|error| {
                KinError::io(self.reconciliation_control_path().join(&name), error)
            })?;
            let manifest = match self.load_reconciliation_manifest(&name, &directory)? {
                Some(manifest) => manifest,
                None => {
                    let transaction = ReconciliationTransaction {
                        name,
                        directory,
                        identity,
                        manifest: ReconciliationManifest {
                            schema: RECONCILIATION_MANIFEST_SCHEMA,
                            transaction_id: String::new(),
                            root_identity,
                            kin_control_identity: self.kin_control_identity,
                            control_identity: self.control_identity,
                            transaction_identity: identity,
                            authority_commit: None,
                            checkout_projection_commit: None,
                            state: ReconciliationTransactionState::Pending,
                            actions: Vec::new(),
                        },
                        action_log_bytes: 0,
                        action_tail_authentication: Vec::new(),
                    };
                    self.cleanup_reconciliation_transaction(transaction)?;
                    continue;
                }
            };
            let expected_name = format!("tx-{}", manifest.transaction_id);
            if manifest.schema != RECONCILIATION_MANIFEST_SCHEMA
                || name != std::ffi::OsStr::new(&expected_name)
                || manifest.root_identity != root_identity
                || manifest.kin_control_identity != self.kin_control_identity
                || manifest.control_identity != self.control_identity
                || manifest.transaction_identity != identity
            {
                return Err(KinError::Other(format!(
                    "reconciliation transaction {} has an invalid identity-bound descriptor",
                    self.reconciliation_control_path().join(&name).display()
                )));
            }
            if !manifest.actions.is_empty() {
                return Err(KinError::Other(format!(
                    "reconciliation transaction {} embedded actions in its fixed descriptor",
                    self.reconciliation_control_path().join(&name).display()
                )));
            }
            if manifest.state == ReconciliationTransactionState::Committed {
                let transaction = ReconciliationTransaction {
                    name,
                    directory,
                    identity,
                    manifest,
                    action_log_bytes: 0,
                    action_tail_authentication: Vec::new(),
                };
                self.cleanup_reconciliation_transaction(transaction)?;
                continue;
            }
            let authority_committed = match &manifest.authority_commit {
                Some(marker) => {
                    let authority = authority.ok_or_else(|| {
                        KinError::Other(format!(
                            "repository projection recovery at {} requires an explicitly retained \
                             frozen repository authority; refusing ambient path reopen",
                            self.display_root.display()
                        ))
                    })?;
                    repository_authority_state_contains_commit(authority, marker)?
                }
                None => false,
            };
            let checkout_committed = match &manifest.checkout_projection_commit {
                Some(marker) => {
                    self.checkout_projection_commit_is_installed_with_authority(marker, authority)?
                }
                None => false,
            };
            if authority_committed || checkout_committed {
                let transaction = ReconciliationTransaction {
                    name,
                    directory,
                    identity,
                    manifest,
                    action_log_bytes: 0,
                    action_tail_authentication: Vec::new(),
                };
                self.cleanup_reconciliation_transaction(transaction)?;
                continue;
            }
            let (actions, action_log_bytes, action_tail_authentication) =
                self.load_reconciliation_actions(&name, &directory)?;
            let mut manifest = manifest;
            manifest.actions = actions;
            let transaction = ReconciliationTransaction {
                name,
                directory,
                identity,
                manifest,
                action_log_bytes,
                action_tail_authentication,
            };
            self.rollback_reconciliation_manifest(&transaction)?;
            self.cleanup_reconciliation_transaction(transaction)?;
        }
        Ok(())
    }

    fn rollback_reconciliation_manifest(
        &self,
        transaction: &ReconciliationTransaction,
    ) -> Result<()> {
        let mut failures = Vec::new();

        for (index, action) in transaction.manifest.actions.iter().enumerate().rev() {
            if let ReconciliationRecoveryAction::PublishObject {
                relative,
                kind,
                identity,
                state,
                slot,
            } = action
            {
                if let Err(error) = self.recover_published_object(
                    transaction,
                    relative,
                    *kind,
                    *identity,
                    *state,
                    slot,
                    index,
                ) {
                    failures.push(error.to_string());
                }
            }
        }

        let mut published_directories: Vec<_> = transaction
            .manifest
            .actions
            .iter()
            .enumerate()
            .filter_map(|(index, action)| match action {
                ReconciliationRecoveryAction::PublishDirectory {
                    relative,
                    identity,
                    slot,
                } => Some((index, relative, identity, slot)),
                _ => None,
            })
            .collect();
        published_directories.sort_by(|left, right| {
            right
                .1
                .components()
                .count()
                .cmp(&left.1.components().count())
                .then_with(|| left.1.cmp(right.1))
        });
        for (index, relative, identity, slot) in published_directories {
            if let Err(error) =
                self.recover_published_directory(transaction, relative, *identity, slot, index)
            {
                failures.push(error.to_string());
            }
        }

        let mut backed_directories: Vec<_> = transaction
            .manifest
            .actions
            .iter()
            .filter_map(|action| match action {
                ReconciliationRecoveryAction::BackupDirectory {
                    relative,
                    identity,
                    slot,
                } => Some((relative, identity, slot)),
                _ => None,
            })
            .collect();
        backed_directories.sort_by(|left, right| {
            left.0
                .components()
                .count()
                .cmp(&right.0.components().count())
                .then_with(|| left.0.cmp(right.0))
        });
        for (relative, identity, slot) in backed_directories {
            if let Err(error) =
                self.recover_backed_directory(transaction, relative, *identity, slot)
            {
                failures.push(error.to_string());
            }
        }

        let mut backed_objects: Vec<_> = transaction
            .manifest
            .actions
            .iter()
            .filter_map(|action| match action {
                ReconciliationRecoveryAction::BackupObject {
                    relative,
                    kind,
                    identity,
                    state,
                    slot,
                } => Some((relative, kind, identity, state, slot)),
                _ => None,
            })
            .collect();
        backed_objects.sort_by(|left, right| {
            left.0
                .components()
                .count()
                .cmp(&right.0.components().count())
                .then_with(|| left.0.cmp(right.0))
        });
        for (relative, kind, identity, state, slot) in backed_objects {
            if let Err(error) =
                self.recover_backed_object(transaction, relative, *kind, *identity, *state, slot)
            {
                failures.push(error.to_string());
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(KinError::Other(format!(
                "exact-source startup recovery failed for {}: {}",
                self.reconciliation_control_path()
                    .join(&transaction.name)
                    .display(),
                failures.join("; ")
            )))
        }
    }

    fn optional_existing_object_inspection(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        kind: ExistingObjectKind,
        display: &Path,
    ) -> Result<Option<(TrackedEntryIdentity, TrackedObjectState)>> {
        match parent.symlink_metadata(name) {
            Ok(_) => self
                .inspect_named_existing_object(parent, name, kind, display)
                .map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(KinError::io(display, error)),
        }
    }

    fn require_recovery_object_state(
        &self,
        actual: Option<(TrackedEntryIdentity, TrackedObjectState)>,
        expected_identity: TrackedEntryIdentity,
        expected_state: TrackedObjectState,
        display: &Path,
        location: &str,
    ) -> Result<bool> {
        match actual {
            Some((identity, state)) if identity == expected_identity && state == expected_state => {
                Ok(true)
            }
            Some((identity, state)) if identity == expected_identity => Err(KinError::Other(
                format!(
                    "exact-source recovery refused to overwrite {}: the identity-bound {} changed content or mode after the crash (expected {:?}, found {:?})",
                    display.display(),
                    location,
                    expected_state,
                    state
                ),
            )),
            _ => Ok(false),
        }
    }

    fn optional_directory_identity(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<Option<TrackedEntryIdentity>> {
        match parent.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(KinError::io(display, error)),
            Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                // Read-only identity probe: the handle only reads its directory
                // identity and is dropped, so it must not request DELETE access.
                let directory = open_directory_nofollow(parent, name)
                    .map_err(|error| KinError::io(display, error))?;
                tracked_open_directory_identity(&directory)
                    .map(Some)
                    .map_err(|error| KinError::io(display, error))
            }
            Ok(_) => Err(KinError::Other(format!(
                "exact-source recovery path {} changed into a non-directory",
                display.display()
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_published_object(
        &self,
        transaction: &ReconciliationTransaction,
        relative: &Path,
        kind: ExistingObjectKind,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
        slot: &str,
        action_index: usize,
    ) -> Result<()> {
        let path = relative
            .to_str()
            .ok_or_else(|| KinError::Other(format!("recovery path is not UTF-8: {relative:?}")))?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let display = self.display_root.join(relative);
        let root =
            self.optional_existing_object_inspection(&parent, source_name, kind, &display)?;
        if self.require_recovery_object_state(
            root,
            identity,
            state,
            &display,
            "published object",
        )? {
            let discard = format!("recovery-discard-object-{action_index}");
            self.move_existing_object_exact(
                NamedEntryLocation {
                    parent: &parent,
                    name: source_name,
                },
                NamedEntryLocation {
                    parent: &transaction.directory,
                    name: std::ffi::OsStr::new(&discard),
                },
                kind,
                identity,
                state,
                &display,
            )?;
            return Ok(());
        }
        let staged = self.optional_existing_object_inspection(
            &transaction.directory,
            std::ffi::OsStr::new(slot),
            kind,
            &display,
        )?;
        let discard = format!("recovery-discard-object-{action_index}");
        let discarded = self.optional_existing_object_inspection(
            &transaction.directory,
            std::ffi::OsStr::new(&discard),
            kind,
            &display,
        )?;
        if self.require_recovery_object_state(staged, identity, state, &display, "staged object")?
            || self.require_recovery_object_state(
                discarded,
                identity,
                state,
                &display,
                "discarded object",
            )?
        {
            return Ok(());
        }
        Err(KinError::Other(format!(
            "published exact-source object {} is not recoverably attached to its root or transaction",
            display.display()
        )))
    }

    fn recover_published_directory(
        &self,
        transaction: &ReconciliationTransaction,
        relative: &Path,
        identity: TrackedEntryIdentity,
        slot: &str,
        action_index: usize,
    ) -> Result<()> {
        let path = relative
            .to_str()
            .ok_or_else(|| KinError::Other(format!("recovery path is not UTF-8: {relative:?}")))?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let display = self.display_root.join(relative);
        if self.optional_directory_identity(&parent, source_name, &display)? == Some(identity) {
            let directory = open_directory_nofollow_for_removal(&parent, source_name)
                .map_err(|error| KinError::io(&display, error))?;
            if directory
                .entries()
                .map_err(|error| KinError::io(&display, error))?
                .next()
                .transpose()
                .map_err(|error| KinError::io(&display, error))?
                .is_some()
            {
                return Err(KinError::Other(format!(
                    "exact-source rollback refused to remove Kin-created directory {} because it contains an unexpected object; the authenticated recovery transaction was retained",
                    display.display()
                )));
            }
            let discard = OsString::from(format!("recovery-discard-directory-{action_index}"));
            self.move_open_directory_exact(
                NamedEntryLocation {
                    parent: &parent,
                    name: source_name,
                },
                NamedEntryLocation {
                    parent: &transaction.directory,
                    name: &discard,
                },
                &directory,
                identity,
                &display,
            )?;
            return Ok(());
        }
        let staged = self.optional_directory_identity(
            &transaction.directory,
            std::ffi::OsStr::new(slot),
            &display,
        )?;
        let discard = OsString::from(format!("recovery-discard-directory-{action_index}"));
        let discarded =
            self.optional_directory_identity(&transaction.directory, &discard, &display)?;
        if staged == Some(identity) || discarded == Some(identity) {
            return Ok(());
        }
        Err(KinError::Other(format!(
            "published exact-source directory {} is not recoverably attached to its root or transaction",
            display.display()
        )))
    }

    fn recover_backed_directory(
        &self,
        transaction: &ReconciliationTransaction,
        relative: &Path,
        identity: TrackedEntryIdentity,
        slot: &str,
    ) -> Result<()> {
        let path = relative
            .to_str()
            .ok_or_else(|| KinError::Other(format!("recovery path is not UTF-8: {relative:?}")))?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let destination_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let display = self.display_root.join(relative);
        if self.optional_directory_identity(&parent, destination_name, &display)? == Some(identity)
        {
            return Ok(());
        }
        if self.optional_directory_identity(
            &transaction.directory,
            std::ffi::OsStr::new(slot),
            &display,
        )? != Some(identity)
        {
            return Err(KinError::Other(format!(
                "backed-up exact-source directory {} is missing from its authenticated transaction slot",
                display.display()
            )));
        }
        let directory =
            open_directory_nofollow_for_removal(&transaction.directory, std::ffi::OsStr::new(slot))
                .map_err(|error| KinError::io(&display, error))?;
        self.move_open_directory_exact(
            NamedEntryLocation {
                parent: &transaction.directory,
                name: std::ffi::OsStr::new(slot),
            },
            NamedEntryLocation {
                parent: &parent,
                name: destination_name,
            },
            &directory,
            identity,
            &display,
        )
    }

    fn recover_backed_object(
        &self,
        transaction: &ReconciliationTransaction,
        relative: &Path,
        kind: ExistingObjectKind,
        identity: TrackedEntryIdentity,
        state: TrackedObjectState,
        slot: &str,
    ) -> Result<()> {
        let path = relative
            .to_str()
            .ok_or_else(|| KinError::Other(format!("recovery path is not UTF-8: {relative:?}")))?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let destination_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let display = self.display_root.join(relative);
        let root =
            self.optional_existing_object_inspection(&parent, destination_name, kind, &display)?;
        if self.require_recovery_object_state(root, identity, state, &display, "restored object")? {
            return Ok(());
        }
        let staged = self.optional_existing_object_inspection(
            &transaction.directory,
            std::ffi::OsStr::new(slot),
            kind,
            &display,
        )?;
        if !self.require_recovery_object_state(
            staged,
            identity,
            state,
            &display,
            "backed-up object",
        )? {
            return Err(KinError::Other(format!(
                "backed-up exact-source object {} is missing from its authenticated transaction slot",
                display.display()
            )));
        }
        self.move_existing_object_exact(
            NamedEntryLocation {
                parent: &transaction.directory,
                name: std::ffi::OsStr::new(slot),
            },
            NamedEntryLocation {
                parent: &parent,
                name: destination_name,
            },
            kind,
            identity,
            state,
            &display,
        )
    }

    fn plan_full_replacement(
        &self,
        tracked: &TrackedPathClassifier,
        should_preserve: Option<&dyn Fn(&Path) -> bool>,
    ) -> Result<FullReplacementPlan> {
        let mut plan = FullReplacementPlan {
            objects: Vec::new(),
            directories: Vec::new(),
        };
        self.plan_full_replacement_from(
            &self.root,
            Path::new(""),
            tracked,
            should_preserve,
            false,
            &mut plan,
        )?;
        plan.objects.sort_by(|left, right| {
            right
                .relative
                .components()
                .count()
                .cmp(&left.relative.components().count())
                .then_with(|| left.relative.cmp(&right.relative))
        });
        plan.directories.sort_by(|left, right| {
            right
                .0
                .components()
                .count()
                .cmp(&left.0.components().count())
                .then_with(|| left.0.cmp(&right.0))
        });
        Ok(plan)
    }

    fn plan_full_replacement_from(
        &self,
        current: &cap_std::fs::Dir,
        relative_directory: &Path,
        tracked: &TrackedPathClassifier,
        should_preserve: Option<&dyn Fn(&Path) -> bool>,
        force_remove: bool,
        plan: &mut FullReplacementPlan,
    ) -> Result<bool> {
        let entries = current
            .entries()
            .map_err(|error| KinError::io(self.display_root.join(relative_directory), error))?;
        let mut all_children_removed = true;
        for entry in entries {
            let entry = entry
                .map_err(|error| KinError::io(self.display_root.join(relative_directory), error))?;
            let name = entry.file_name();
            let relative = relative_directory.join(&name);
            if relative_directory.as_os_str().is_empty()
                && projection_control_names_match(&name, &self.projection_control_name)
            {
                all_children_removed = false;
                continue;
            }
            let relation = tracked.relation(&relative);
            let preserved_unrelated = relation == TrackedPathRelation::Unrelated
                && should_preserve.is_some_and(|preserve| preserve(&relative));
            let cleanup_unrelated = relation == TrackedPathRelation::Unrelated
                && should_preserve.is_some()
                && !preserved_unrelated;
            let metadata = current
                .symlink_metadata(&name)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?;

            if metadata.is_dir() && !metadata_is_reparse(&metadata) {
                if preserved_unrelated && !force_remove {
                    all_children_removed = false;
                    continue;
                }
                if relation == TrackedPathRelation::Unrelated && !cleanup_unrelated && !force_remove
                {
                    all_children_removed = false;
                    continue;
                }
                let directory =
                    self.open_existing_directory_for_removal(current, &name, &relative)?;
                let identity = tracked_open_directory_identity(&directory)
                    .map_err(|error| KinError::io(self.display_root.join(&relative), error))?;
                let remove_entire_directory = force_remove
                    || matches!(
                        relation,
                        TrackedPathRelation::Exact | TrackedPathRelation::Descendant
                    );
                let children_removed = self.plan_full_replacement_from(
                    &directory,
                    &relative,
                    tracked,
                    should_preserve,
                    remove_entire_directory,
                    plan,
                )?;
                let remove_directory = remove_entire_directory
                    || (cleanup_unrelated && children_removed)
                    || (force_remove && children_removed);
                if remove_directory {
                    plan.directories.push((relative, identity));
                } else {
                    all_children_removed = false;
                }
                continue;
            }

            let remove_object =
                force_remove || relation != TrackedPathRelation::Unrelated || cleanup_unrelated;
            if !remove_object || (preserved_unrelated && !force_remove) {
                all_children_removed = false;
                continue;
            }
            let kind = if metadata_is_reparse(&metadata) {
                ExistingObjectKind::Symlink
            } else if metadata.is_file() {
                ExistingObjectKind::File
            } else {
                return Err(KinError::Other(format!(
                    "working-copy object {} has an unsupported kind for atomic exact-source replacement",
                    self.display_root.join(&relative).display()
                )));
            };
            let (identity, state) = self.inspect_named_existing_object(
                current,
                &name,
                kind,
                &self.display_root.join(&relative),
            )?;
            plan.objects.push(PlannedExistingObject {
                relative,
                kind,
                identity,
                state,
            });
        }
        Ok(all_children_removed)
    }

    fn apply_full_replacement(
        &self,
        entries: &[ValidatedSourceEntry<'_>],
        plan: FullReplacementPlan,
    ) -> Result<()> {
        let mut transaction = self.create_reconciliation_transaction()?;
        let staged = match self.stage_reconciliation_entries(&transaction.directory, entries) {
            Ok(staged) => staged,
            Err(error) => {
                return match self.cleanup_reconciliation_transaction(transaction) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(KinError::Other(format!(
                        "{error}; staged full-tree cleanup also failed: {cleanup_error}"
                    ))),
                };
            }
        };

        let mut backed_directories = Vec::with_capacity(plan.directories.len());
        let mut created_directories = Vec::new();
        let mut next_object_backup = plan.objects.len();
        let file_ids: Vec<_> = entries.iter().map(|entry| entry.file_id).collect();
        let mutation_result: Result<()> = (|| {
            for (name_index, object) in plan.objects.iter().enumerate() {
                self.back_up_existing_object(&mut transaction, object, name_index)?;
            }
            for (relative, expected_identity) in &plan.directories {
                let backup = self.back_up_planned_empty_directory(
                    &mut transaction,
                    relative,
                    *expected_identity,
                    backed_directories.len(),
                )?;
                backed_directories.push(backup);
            }
            self.prepare_full_replacement_transactional(
                &mut transaction,
                &file_ids,
                &mut created_directories,
                &mut next_object_backup,
                &mut backed_directories,
            )?;
            for staged_entry in &staged {
                self.publish_staged_entry(&mut transaction, staged_entry)?;
            }
            Ok(())
        })();

        if let Err(error) = mutation_result {
            let rollback = self.rollback_reconciliation_manifest(&transaction);
            return match rollback {
                Ok(()) => match self.cleanup_reconciliation_transaction(transaction) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(KinError::Other(format!(
                        "{error}; full-tree rollback succeeded but transaction cleanup failed: {cleanup_error}"
                    ))),
                },
                Err(rollback_error) => Err(KinError::Other(format!(
                    "{error}; {rollback_error}; retained recovery transaction at {}",
                    self.reconciliation_control_path()
                        .join(&transaction.name)
                        .display()
                ))),
            };
        }

        self.cleanup_reconciliation_transaction(transaction)
    }

    fn stage_reconciliation_entries<'a>(
        &self,
        transaction: &cap_std::fs::Dir,
        entries: &[ValidatedSourceEntry<'a>],
    ) -> Result<Vec<StagedReconciliationEntry<'a>>> {
        let mut staged = Vec::with_capacity(entries.len());
        for (name_index, entry) in entries.iter().copied().enumerate() {
            let name = format!("stage-{name_index}");
            let identity = self.stage_reconciliation_entry(transaction, &name, &entry)?;
            let kind = match entry.kind {
                TreeEntry::Blob { .. } => ExistingObjectKind::File,
                TreeEntry::Symlink { .. } => ExistingObjectKind::Symlink,
                TreeEntry::Gitlink { .. } => {
                    return Err(KinError::Other(format!(
                        "gitlink {} cannot be staged as a source object",
                        entry.file_id
                    )));
                }
            };
            let display = self.display_root.join(projection_path(entry.file_id)?);
            let (inspected_identity, state) = self.inspect_named_existing_object(
                transaction,
                std::ffi::OsStr::new(&name),
                kind,
                &display,
            )?;
            if inspected_identity != identity {
                return Err(KinError::Other(format!(
                    "staged exact-source object {} changed identity before journaling",
                    display.display()
                )));
            }
            staged.push(StagedReconciliationEntry {
                entry,
                name_index,
                identity,
                state,
            });
        }
        #[cfg(unix)]
        rustix::fs::fsync(transaction)
            .map_err(|error| KinError::io(&self.display_root, error.into()))?;
        Ok(staged)
    }

    #[cfg(unix)]
    fn stage_reconciliation_entry(
        &self,
        transaction: &cap_std::fs::Dir,
        name: &str,
        entry: &ValidatedSourceEntry<'_>,
    ) -> Result<TrackedEntryIdentity> {
        let display = self.display_root.join(projection_path(entry.file_id)?);
        match entry.kind {
            TreeEntry::Blob { executable, .. } => {
                let fd = rustix::fs::openat(
                    transaction,
                    name,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::from_raw_mode(0o600),
                )
                .map_err(|error| KinError::io(&display, error.into()))?;
                let mut file = std::fs::File::from(fd);
                file.write_all(entry.content)
                    .map_err(|error| KinError::io(&display, error))?;
                rustix::fs::fchmod(
                    &file,
                    rustix::fs::Mode::from_raw_mode(if executable { 0o755 } else { 0o644 }),
                )
                .map_err(|error| KinError::io(&display, error.into()))?;
                file.sync_all()
                    .map_err(|error| KinError::io(&display, error))?;
                let metadata = file
                    .metadata()
                    .map_err(|error| KinError::io(&display, error))?;
                Ok(tracked_open_file_identity(&metadata))
            }
            TreeEntry::Symlink { .. } => {
                let target =
                    std::str::from_utf8(entry.content).expect("validated UTF-8 symlink target");
                rustix::fs::symlinkat(target, transaction, name)
                    .map_err(|error| KinError::io(&display, error.into()))?;
                let metadata = transaction
                    .symlink_metadata(name)
                    .map_err(|error| KinError::io(&display, error))?;
                Ok(tracked_entry_identity(&metadata))
            }
            TreeEntry::Gitlink { .. } => Err(KinError::Other(format!(
                "gitlink {} cannot be staged as a source object",
                entry.file_id
            ))),
        }
    }

    #[cfg(windows)]
    fn stage_reconciliation_entry(
        &self,
        transaction: &cap_std::fs::Dir,
        name: &str,
        entry: &ValidatedSourceEntry<'_>,
    ) -> Result<TrackedEntryIdentity> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::DELETE;

        if matches!(entry.kind, TreeEntry::Symlink { .. }) {
            return Err(KinError::Other(
                "safe exact symbolic-link checkout is unsupported on Windows".to_string(),
            ));
        }
        if matches!(entry.kind, TreeEntry::Gitlink { .. }) {
            return Err(KinError::Other(format!(
                "gitlink {} cannot be staged as a source object",
                entry.file_id
            )));
        }
        let display = self.display_root.join(projection_path(entry.file_id)?);
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .follow(FollowSymlinks::No);
        let mut file = transaction
            .open_with(name, &options)
            .map_err(|error| KinError::io(&display, error))?;
        file.write_all(entry.content)
            .map_err(|error| KinError::io(&display, error))?;
        file.sync_all()
            .map_err(|error| KinError::io(&display, error))?;
        tracked_open_file_identity(&file).map_err(|error| KinError::io(&display, error))
    }

    fn prepare(&self, file_ids: &[&RepoPath]) -> Result<()> {
        let mut paths: Vec<_> = file_ids
            .iter()
            .map(|file_id| projection_path(file_id).and_then(validate_source_path))
            .collect::<Result<_>>()?;
        paths.sort_unstable();

        for components in &paths {
            let mut parent = self.clone_root()?;
            for component in &components[..components.len() - 1] {
                parent = self.open_or_create_directory(&parent, component)?;
            }
        }

        // A graph-owned file or link cannot be atomically renamed over a
        // directory. Remove only those leaf directories, relative to held
        // parent capabilities, before staging replacements.
        for components in paths {
            let parent = self.open_existing_parent(&components)?;
            let name = components[components.len() - 1];
            match parent.symlink_metadata(name) {
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    self.remove_directory_tree(
                        &parent,
                        std::ffi::OsStr::new(name),
                        Path::new(&components.join("/")),
                    )?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(KinError::io(self.display_path(&components), error));
                }
            }
        }
        Ok(())
    }

    fn prepare_without_replacement_transactional(
        &self,
        transaction: &mut ReconciliationTransaction,
        file_ids: &[&RepoPath],
        created_directories: &mut Vec<PublishedDirectory>,
        must_create_directories: &HashSet<PathBuf>,
    ) -> Result<()> {
        let mut paths: Vec<_> = file_ids
            .iter()
            .map(|file_id| projection_path(file_id).and_then(validate_source_path))
            .collect::<Result<_>>()?;
        paths.sort_unstable();
        for components in &paths {
            let mut parent = self.clone_root()?;
            let mut relative = PathBuf::new();
            for component in &components[..components.len() - 1] {
                relative.push(component);
                parent = loop {
                    match open_directory_nofollow(&parent, std::ffi::OsStr::new(component)) {
                        Ok(directory) => {
                            if must_create_directories.contains(&relative) {
                                let Some(published) = created_directories
                                    .iter()
                                    .find(|published| published.relative == relative)
                                else {
                                    return Err(KinError::Other(format!(
                                        "working-copy directory {} appeared at an expected-absent graph-only boundary during exact workspace reconciliation",
                                        self.display_root.join(&relative).display()
                                    )));
                                };
                                let actual = tracked_open_directory_identity(&directory).map_err(
                                    |error| KinError::io(self.display_root.join(&relative), error),
                                )?;
                                if actual != published.identity {
                                    return Err(KinError::Other(format!(
                                        "Kin-created directory {} changed identity during exact workspace reconciliation",
                                        self.display_root.join(&relative).display()
                                    )));
                                }
                            }
                            break directory;
                        }
                        Err(_) => match parent.symlink_metadata(component) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                let published = self.stage_and_publish_directory(
                                    transaction,
                                    &parent,
                                    std::ffi::OsStr::new(component),
                                    &relative,
                                    created_directories.len(),
                                )?;
                                let directory =
                                    published.directory.try_clone().map_err(|error| {
                                        KinError::io(self.display_root.join(&relative), error)
                                    })?;
                                created_directories.push(published);
                                break directory;
                            }
                            Ok(metadata)
                                if metadata.is_dir() && !metadata_is_reparse(&metadata) =>
                            {
                                continue;
                            }
                            Ok(_) => {
                                return Err(KinError::Other(format!(
                                    "working-copy path {} changed into an untracked blocker during exact workspace reconciliation",
                                    self.display_root.join(&relative).display()
                                )));
                            }
                            Err(error) => {
                                return Err(KinError::io(self.display_root.join(&relative), error));
                            }
                        },
                    }
                };
            }
        }

        for components in paths {
            let parent = self.open_existing_parent(&components)?;
            let name = components[components.len() - 1];
            match parent.symlink_metadata(name) {
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    return Err(KinError::Other(format!(
                        "working-copy directory {} conflicts with an exact workspace file",
                        self.display_path(&components).display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(KinError::io(self.display_path(&components), error)),
            }
        }
        Ok(())
    }

    fn prepare_full_replacement_transactional(
        &self,
        transaction: &mut ReconciliationTransaction,
        file_ids: &[&RepoPath],
        created_directories: &mut Vec<PublishedDirectory>,
        next_object_backup: &mut usize,
        backed_directories: &mut Vec<BackedUpDirectory>,
    ) -> Result<()> {
        let mut paths: Vec<_> = file_ids
            .iter()
            .map(|file_id| projection_path(file_id).and_then(validate_source_path))
            .collect::<Result<_>>()?;
        paths.sort_unstable();
        for components in &paths {
            let mut parent = self.clone_root()?;
            let mut relative = PathBuf::new();
            for component in &components[..components.len() - 1] {
                relative.push(component);
                parent = loop {
                    match open_directory_nofollow(&parent, std::ffi::OsStr::new(component)) {
                        Ok(directory) => break directory,
                        Err(_) => match parent.symlink_metadata(component) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                let published = self.stage_and_publish_directory(
                                    transaction,
                                    &parent,
                                    std::ffi::OsStr::new(component),
                                    &relative,
                                    created_directories.len(),
                                )?;
                                let directory =
                                    published.directory.try_clone().map_err(|error| {
                                        KinError::io(self.display_root.join(&relative), error)
                                    })?;
                                created_directories.push(published);
                                break directory;
                            }
                            Ok(metadata)
                                if metadata.is_dir() && !metadata_is_reparse(&metadata) =>
                            {
                                continue;
                            }
                            Ok(metadata) => {
                                let kind = if metadata_is_reparse(&metadata) {
                                    ExistingObjectKind::Symlink
                                } else if metadata.is_file() {
                                    ExistingObjectKind::File
                                } else {
                                    return Err(KinError::Other(format!(
                                        "working-copy object {} has an unsupported kind for atomic exact-source replacement",
                                        self.display_root.join(&relative).display()
                                    )));
                                };
                                let (identity, state) = self.inspect_named_existing_object(
                                    &parent,
                                    std::ffi::OsStr::new(component),
                                    kind,
                                    &self.display_root.join(&relative),
                                )?;
                                let object = PlannedExistingObject {
                                    relative: relative.clone(),
                                    kind,
                                    identity,
                                    state,
                                };
                                self.back_up_existing_object(
                                    transaction,
                                    &object,
                                    *next_object_backup,
                                )?;
                                *next_object_backup += 1;
                            }
                            Err(error) => {
                                return Err(KinError::io(self.display_root.join(&relative), error));
                            }
                        },
                    }
                };
            }
        }

        for components in paths {
            let parent = self.open_existing_parent(&components)?;
            let name = components[components.len() - 1];
            let relative = PathBuf::from(components.join("/"));
            match parent.symlink_metadata(name) {
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    backed_directories.push(self.back_up_directory(
                        transaction,
                        &relative,
                        backed_directories.len(),
                        false,
                        None,
                    )?);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(KinError::io(self.display_path(&components), error)),
            }
        }
        Ok(())
    }

    fn validate_reconciliation_targets(
        &self,
        entries: &[ValidatedSourceEntry<'_>],
        previous: &TrackedPathClassifier,
        removed: &TrackedPathClassifier,
    ) -> Result<()> {
        for entry in entries {
            let components = projection_path(entry.file_id).and_then(validate_source_path)?;
            let mut parent = self.clone_root()?;
            let mut relative = PathBuf::new();
            let mut ancestor_missing_or_authorized = false;

            for component in &components[..components.len() - 1] {
                relative.push(component);
                match parent.symlink_metadata(component) {
                    Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                        parent = self.open_existing_directory(
                            &parent,
                            std::ffi::OsStr::new(component),
                            &relative,
                        )?;
                    }
                    Ok(_) if removed.relation(&relative) == TrackedPathRelation::Exact => {
                        ancestor_missing_or_authorized = true;
                        break;
                    }
                    Ok(_) => {
                        return Err(KinError::untracked_path_blocks(format!(
                            "untracked working-copy path {} blocks exact workspace target {}",
                            self.display_root.join(&relative).display(),
                            entry.file_id
                        )));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ancestor_missing_or_authorized = true;
                        break;
                    }
                    Err(error) => {
                        return Err(KinError::io(self.display_root.join(&relative), error));
                    }
                }
            }

            if ancestor_missing_or_authorized {
                continue;
            }

            relative.push(components[components.len() - 1]);
            match parent.symlink_metadata(components[components.len() - 1]) {
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    if previous.relation(&relative) != TrackedPathRelation::Ancestor
                        || removed.relation(&relative) != TrackedPathRelation::Ancestor
                    {
                        return Err(KinError::projection_conflict(format!(
                            "untracked working-copy directory {} conflicts with exact workspace target {}",
                            self.display_root.join(&relative).display(),
                            entry.file_id
                        )));
                    }
                    let directory = self.open_existing_directory(
                        &parent,
                        std::ffi::OsStr::new(components[components.len() - 1]),
                        &relative,
                    )?;
                    self.validate_removable_directory_contents(&directory, &relative, removed)?;
                }
                Ok(_) if previous.relation(&relative) == TrackedPathRelation::Exact => {}
                Ok(_) => {
                    return Err(KinError::untracked_path_blocks(format!(
                        "untracked working-copy path {} conflicts with exact workspace target {}",
                        self.display_root.join(&relative).display(),
                        entry.file_id
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(KinError::io(self.display_root.join(&relative), error));
                }
            }
        }
        Ok(())
    }

    fn validate_removable_directory_contents(
        &self,
        directory: &cap_std::fs::Dir,
        relative_directory: &Path,
        removed: &TrackedPathClassifier,
    ) -> Result<()> {
        let entries = directory
            .entries()
            .map_err(|error| KinError::io(self.display_root.join(relative_directory), error))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| KinError::io(self.display_root.join(relative_directory), error))?;
            let name = entry.file_name();
            let relative = relative_directory.join(&name);
            let metadata = directory
                .symlink_metadata(&name)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?;
            if metadata.is_dir() && !metadata_is_reparse(&metadata) {
                if removed.relation(&relative) != TrackedPathRelation::Ancestor {
                    return Err(KinError::projection_conflict(format!(
                        "untracked working-copy directory {} blocks exact workspace reconciliation",
                        self.display_root.join(&relative).display()
                    )));
                }
                let child = self.open_existing_directory(directory, &name, &relative)?;
                self.validate_removable_directory_contents(&child, &relative, removed)?;
            } else if removed.relation(&relative) != TrackedPathRelation::Exact {
                return Err(KinError::untracked_path_blocks(format!(
                    "untracked working-copy path {} blocks exact workspace reconciliation",
                    self.display_root.join(&relative).display()
                )));
            }
        }
        Ok(())
    }

    fn validate_tracked_entries_unchanged(
        &self,
        entries: &[&ValidatedSourceEntry<'_>],
    ) -> Result<Vec<TrackedEntryIdentity>> {
        entries
            .iter()
            .map(|entry| self.validate_tracked_entry_unchanged(entry))
            .collect()
    }

    fn inspect_checkout_previous_entry(
        &self,
        file_id: &RepoPath,
    ) -> Result<PreviousProjectionState> {
        let path = projection_path(file_id)?;
        let components = validate_source_path(path)?;
        let mut parent = self.clone_root()?;
        let mut relative = PathBuf::new();
        for component in &components[..components.len() - 1] {
            relative.push(component);
            match parent.symlink_metadata(component) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(PreviousProjectionState::CheckoutAbsent);
                }
                Err(error) => {
                    return Err(KinError::io(self.display_root.join(&relative), error));
                }
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    parent = self.open_existing_directory(
                        &parent,
                        std::ffi::OsStr::new(*component),
                        &relative,
                    )?;
                }
                Ok(_) => {
                    return Err(KinError::projection_conflict(format!(
                        "selected checkout path {} is blocked by a non-directory working-copy ancestor {}; select that ancestor explicitly",
                        file_id,
                        self.display_root.join(&relative).display()
                    )));
                }
            }
        }

        relative.push(components[components.len() - 1]);
        let name = std::ffi::OsStr::new(components[components.len() - 1]);
        let metadata = match parent.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PreviousProjectionState::CheckoutAbsent);
            }
            Err(error) => return Err(KinError::io(self.display_root.join(&relative), error)),
            Ok(metadata) => metadata,
        };
        if metadata.is_dir() && !metadata_is_reparse(&metadata) {
            return Err(KinError::projection_conflict(format!(
                "selected tracked checkout path {} became a real directory; refusing to remove possibly untracked descendants",
                self.display_root.join(&relative).display()
            )));
        }
        let kind = if metadata_is_reparse(&metadata) {
            ExistingObjectKind::Symlink
        } else if metadata.is_file() {
            ExistingObjectKind::File
        } else {
            return Err(KinError::projection_conflict(format!(
                "selected checkout path {} has an unsupported working-copy object kind",
                self.display_root.join(&relative).display()
            )));
        };
        let (identity, state) = self.inspect_named_existing_object(
            &parent,
            name,
            kind,
            &self.display_root.join(&relative),
        )?;
        Ok(PreviousProjectionState::CheckoutObject {
            relative,
            kind,
            identity,
            state,
        })
    }

    fn revalidate_checkout_previous_entry(
        &self,
        file_id: &RepoPath,
        expected: &PreviousProjectionState,
    ) -> Result<()> {
        match expected {
            PreviousProjectionState::Exact { .. } => Err(KinError::Other(
                "selected checkout path was paired with an exact-only preflight".to_string(),
            )),
            PreviousProjectionState::CheckoutAbsent => {
                let path = projection_path(file_id)?;
                let components = validate_source_path(path)?;
                let mut parent = self.clone_root()?;
                let mut relative = PathBuf::new();
                for component in &components[..components.len() - 1] {
                    relative.push(component);
                    match parent.symlink_metadata(component) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                        Err(error) => {
                            return Err(KinError::io(self.display_root.join(&relative), error));
                        }
                        Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                            parent = self.open_existing_directory(
                                &parent,
                                std::ffi::OsStr::new(*component),
                                &relative,
                            )?;
                        }
                        Ok(_) => {
                            return Err(KinError::projection_conflict(format!(
                                "working-copy ancestor {} appeared after selected checkout preflight",
                                self.display_root.join(&relative).display()
                            )));
                        }
                    }
                }
                let name = std::ffi::OsStr::new(components[components.len() - 1]);
                match parent.symlink_metadata(name) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(KinError::io(self.display_root.join(path), error)),
                    Ok(_) => Err(KinError::projection_conflict(format!(
                        "working-copy path {} appeared after selected checkout preflight",
                        self.display_root.join(path).display()
                    ))),
                }
            }
            PreviousProjectionState::CheckoutObject {
                relative,
                kind,
                identity,
                state,
            } => {
                let path = relative.to_str().ok_or_else(|| {
                    KinError::Other(format!("selected checkout path is not UTF-8: {relative:?}"))
                })?;
                let components = validate_source_path(path)?;
                let parent = self.open_existing_parent(&components)?;
                let name = std::ffi::OsStr::new(components[components.len() - 1]);
                let (actual_identity, actual_state) = self.inspect_named_existing_object(
                    &parent,
                    name,
                    *kind,
                    &self.display_root.join(relative),
                )?;
                if actual_identity != *identity || actual_state != *state {
                    return Err(KinError::projection_conflict(format!(
                        "selected working-copy path {} changed after exact checkout preflight",
                        self.display_root.join(relative).display()
                    )));
                }
                Ok(())
            }
        }
    }

    fn revalidate_tracked_entries_unchanged(
        &self,
        entries: &[&ValidatedSourceEntry<'_>],
        expected_identities: &[TrackedEntryIdentity],
    ) -> Result<()> {
        if entries.len() != expected_identities.len() {
            return Err(KinError::Other(
                "exact workspace reconciliation identity preflight is inconsistent".to_string(),
            ));
        }
        for (entry, expected_identity) in entries.iter().zip(expected_identities) {
            let actual_identity = self.validate_tracked_entry_unchanged(entry)?;
            if actual_identity != *expected_identity {
                return Err(KinError::projection_conflict(format!(
                    "tracked working-copy path {} changed object identity after exact workspace preflight; reconciliation refused",
                    self.display_root
                        .join(projection_path(entry.file_id)?)
                        .display()
                )));
            }
        }
        Ok(())
    }

    fn validate_frozen_entries_unchanged(
        &self,
        entries: &[&ValidatedSourceEntry<'_>],
    ) -> Result<Vec<TrackedEntryIdentity>> {
        entries
            .iter()
            .map(|entry| self.validate_frozen_entry_unchanged(entry))
            .collect()
    }

    fn revalidate_frozen_entries_unchanged(
        &self,
        entries: &[&ValidatedSourceEntry<'_>],
        expected_identities: &[TrackedEntryIdentity],
    ) -> Result<()> {
        if entries.len() != expected_identities.len() {
            return Err(KinError::Other(
                "exact projection verification identity preflight is inconsistent".to_string(),
            ));
        }
        for (entry, expected_identity) in entries.iter().zip(expected_identities) {
            let actual_identity = self.validate_frozen_entry_unchanged(entry)?;
            if actual_identity != *expected_identity {
                let path = validate_projection_proof_path(entry.file_id)?;
                return Err(KinError::projection_conflict(format!(
                    "tracked working-copy path {} changed object identity after exact projection verification",
                    self.display_root.join(path.relative).display()
                )));
            }
        }
        Ok(())
    }

    fn validate_named_source_entry(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        entry: &ValidatedSourceEntry<'_>,
        display: &Path,
    ) -> Result<TrackedEntryIdentity> {
        match entry.kind {
            TreeEntry::Blob { executable, .. } => {
                #[cfg(unix)]
                let mut file = rustix::fs::openat(
                    parent,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map(std::fs::File::from)
                .map_err(|error| KinError::io(display, error.into()))?;
                #[cfg(windows)]
                let mut file = {
                    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

                    let mut options = cap_std::fs::OpenOptions::new();
                    options.read(true).follow(FollowSymlinks::No);
                    parent
                        .open_with(name, &options)
                        .map_err(|error| KinError::io(display, error))?
                };
                let metadata = file
                    .metadata()
                    .map_err(|error| KinError::io(display, error))?;
                if !metadata.is_file() {
                    return Err(KinError::projection_conflict(format!(
                        "exact-source object {} changed kind",
                        display.display()
                    )));
                }
                #[cfg(windows)]
                if metadata_is_reparse(&metadata) {
                    return Err(KinError::projection_conflict(format!(
                        "exact-source object {} became a reparse point",
                        display.display()
                    )));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    if (metadata.permissions().mode() & 0o111 != 0) != executable {
                        return Err(KinError::projection_conflict(format!(
                            "exact-source object {} changed executable mode",
                            display.display()
                        )));
                    }
                }
                #[cfg(windows)]
                let _ = executable;
                if !reader_matches_bytes(&mut file, entry.content)
                    .map_err(|error| KinError::io(display, error))?
                {
                    return Err(KinError::projection_conflict(format!(
                        "exact-source object {} changed content",
                        display.display()
                    )));
                }
                #[cfg(unix)]
                {
                    Ok(tracked_open_file_identity(&metadata))
                }
                #[cfg(windows)]
                {
                    tracked_open_file_identity(&file).map_err(|error| KinError::io(display, error))
                }
            }
            TreeEntry::Symlink { .. } => {
                #[cfg(unix)]
                {
                    let metadata = parent
                        .symlink_metadata(name)
                        .map_err(|error| KinError::io(display, error))?;
                    if !metadata_is_reparse(&metadata) {
                        return Err(KinError::projection_conflict(format!(
                            "exact-source object {} changed kind",
                            display.display()
                        )));
                    }
                    let target = rustix::fs::readlinkat(parent, name, Vec::new())
                        .map_err(|error| KinError::io(display, error.into()))?;
                    if target.as_bytes() != entry.content {
                        return Err(KinError::projection_conflict(format!(
                            "exact-source symbolic link {} changed target",
                            display.display()
                        )));
                    }
                    Ok(tracked_entry_identity(&metadata))
                }
                #[cfg(windows)]
                {
                    Err(KinError::Other(
                        "safe exact symbolic-link checkout is unsupported on Windows".to_string(),
                    ))
                }
            }
            TreeEntry::Gitlink { .. } => Err(KinError::Other(format!(
                "gitlink {} cannot be validated as a repository-owned source object",
                entry.file_id
            ))),
        }
    }

    #[cfg(unix)]
    fn open_optional_retained_git_entry(
        &self,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<Option<RetainedGitEntry>> {
        let metadata = match self.root.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(display, error)),
        };
        if metadata_is_reparse(&metadata) {
            return Err(KinError::Other(format!(
                "existing Git entry {} is a symbolic link; exact eject accepts only a regular file or real directory",
                display.display()
            )));
        }
        if metadata.is_dir() {
            let directory = open_directory_nofollow_for_removal(&self.root, name)
                .map_err(|error| KinError::io(display, error))?;
            let identity = tracked_open_directory_identity(&directory)
                .map_err(|error| KinError::io(display, error))?;
            if identity != tracked_entry_identity(&metadata) {
                return Err(KinError::Other(format!(
                    "existing Git directory {} changed identity while being retained",
                    display.display()
                )));
            }
            let seal = seal_exact_git_directory(&directory, display)?;
            return Ok(Some(RetainedGitEntry::Directory {
                directory,
                identity,
                seal,
            }));
        }
        if metadata.is_file() {
            let (identity, state) = self.inspect_named_existing_object(
                &self.root,
                name,
                ExistingObjectKind::File,
                display,
            )?;
            let file = open_regular_file_nofollow_for_removal(&self.root, name)
                .map_err(|error| KinError::io(display, error))?;
            if tracked_cap_file_identity(&file).map_err(|error| KinError::io(display, error))?
                != identity
            {
                return Err(KinError::Other(format!(
                    "existing Git file {} changed identity while being retained",
                    display.display()
                )));
            }
            return Ok(Some(RetainedGitEntry::File {
                file,
                identity,
                state,
            }));
        }
        Err(KinError::Other(format!(
            "existing Git entry {} is neither a regular file nor a real directory",
            display.display()
        )))
    }

    #[cfg(unix)]
    fn validate_retained_git_entry_at(
        &self,
        entry: &RetainedGitEntry,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<()> {
        match entry {
            RetainedGitEntry::File {
                file,
                identity,
                state,
            } => {
                if tracked_cap_file_identity(file).map_err(|error| KinError::io(display, error))?
                    != *identity
                {
                    return Err(KinError::Other(format!(
                        "retained Git file {} changed identity",
                        display.display()
                    )));
                }
                let (named_identity, named_state) = self.inspect_named_existing_object(
                    parent,
                    name,
                    ExistingObjectKind::File,
                    display,
                )?;
                if named_identity != *identity || named_state != *state {
                    return Err(KinError::Other(format!(
                        "Git file {} changed identity, bytes, or mode while retained",
                        display.display()
                    )));
                }
            }
            RetainedGitEntry::Directory {
                directory,
                identity,
                seal,
            } => {
                if tracked_open_directory_identity(directory)
                    .map_err(|error| KinError::io(display, error))?
                    != *identity
                {
                    return Err(KinError::Other(format!(
                        "retained Git directory {} changed identity",
                        display.display()
                    )));
                }
                let named = open_directory_nofollow(parent, name)
                    .map_err(|error| KinError::io(display, error))?;
                if tracked_open_directory_identity(&named)
                    .map_err(|error| KinError::io(display, error))?
                    != *identity
                {
                    return Err(KinError::Other(format!(
                        "Git directory {} was replaced while retained",
                        display.display()
                    )));
                }
                if seal_exact_git_directory(directory, display)? != *seal {
                    return Err(KinError::Other(format!(
                        "Git directory {} changed descendants while retained",
                        display.display()
                    )));
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn locate_retained_regular_file(
        &self,
        parent: &cap_std::fs::Dir,
        identity: TrackedEntryIdentity,
        display: &Path,
    ) -> Result<OsString> {
        let mut located = None;
        for entry in parent
            .entries()
            .map_err(|error| KinError::io(display, error))?
        {
            let entry = entry.map_err(|error| KinError::io(display, error))?;
            let name = entry.file_name();
            let metadata = match parent.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(KinError::io(display, error)),
            };
            if metadata.is_file()
                && !metadata_is_reparse(&metadata)
                && tracked_entry_identity(&metadata) == identity
            {
                if located.is_some() {
                    return Err(KinError::Other(format!(
                        "retained Git file {} has multiple names in one namespace parent",
                        display.display()
                    )));
                }
                located = Some(name);
            }
        }
        located.ok_or_else(|| {
            KinError::Other(format!(
                "retained Git file {} is no longer linked from its expected namespace parent",
                display.display()
            ))
        })
    }

    #[cfg(unix)]
    fn move_retained_git_entry_exact(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        entry: &RetainedGitEntry,
        display: &Path,
    ) -> Result<()> {
        if let RetainedGitEntry::Directory {
            directory,
            identity,
            ..
        } = entry
        {
            return self.move_open_directory_from_expected_source_exact(
                source,
                destination,
                directory,
                *identity,
                display,
            );
        }

        self.validate_retained_git_entry_at(entry, source.parent, source.name, display)?;
        rustix::fs::renameat_with(
            source.parent,
            source.name,
            destination.parent,
            destination.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| KinError::io(display, error.into()))?;
        let post_move = sync_namespace_parents(source.parent, display, destination.parent, display)
            .and_then(|()| {
                self.validate_retained_git_entry_at(
                    entry,
                    destination.parent,
                    destination.name,
                    display,
                )
            });
        if let Err(error) = post_move {
            let actual_name =
                self.locate_retained_regular_file(destination.parent, entry.identity(), display);
            let restoration = actual_name.and_then(|actual_name| {
                rustix::fs::renameat_with(
                    destination.parent,
                    &actual_name,
                    source.parent,
                    source.name,
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(|restore_error| KinError::io(display, restore_error.into()))?;
                sync_namespace_parents(destination.parent, display, source.parent, display)
            });
            return match restoration {
                Ok(()) => Err(error),
                Err(restore_error) => Err(KinError::Other(format!(
                    "{error}; retained Git file restoration also failed for {}: {restore_error}",
                    display.display()
                ))),
            };
        }
        Ok(())
    }

    #[cfg(unix)]
    fn move_named_entry_noreplace(
        &self,
        source_parent: &cap_std::fs::Dir,
        source_name: &std::ffi::OsStr,
        destination_parent: &cap_std::fs::Dir,
        destination_name: &std::ffi::OsStr,
    ) -> std::io::Result<()> {
        rustix::fs::renameat_with(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }

    #[cfg(windows)]
    fn move_named_entry_noreplace(
        &self,
        source_parent: &cap_std::fs::Dir,
        source_name: &std::ffi::OsStr,
        destination_parent: &cap_std::fs::Dir,
        destination_name: &std::ffi::OsStr,
    ) -> std::io::Result<()> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let mut options = cap_std::fs::OpenOptions::new();
        options
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .follow(FollowSymlinks::No);
        let source = source_parent.open_with(source_name, &options)?;
        let metadata = source.metadata()?;
        if metadata_is_reparse(&metadata) || !metadata.is_file() {
            return Err(std::io::Error::other(
                "exact-source displacement target changed kind",
            ));
        }
        replace_windows_file_handle_exact(&source, destination_parent, destination_name, false)
    }

    #[cfg(unix)]
    fn locate_open_directory(
        &self,
        directory: &cap_std::fs::Dir,
        expected_identity: TrackedEntryIdentity,
        display: &Path,
    ) -> Result<(cap_std::fs::Dir, OsString)> {
        let parent_fd = rustix::fs::openat(
            directory,
            std::path::Component::ParentDir.as_os_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|error| KinError::io(display, error.into()))?;
        let parent = cap_std::fs::Dir::from_std_file(parent_fd);
        let entries = parent
            .entries()
            .map_err(|error| KinError::io(display, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| KinError::io(display, error))?;
            let name = entry.file_name();
            let metadata = match parent.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(KinError::io(display, error)),
            };
            if metadata.is_dir()
                && !metadata_is_reparse(&metadata)
                && tracked_entry_identity(&metadata) == expected_identity
            {
                return Ok((parent, name));
            }
        }
        Err(KinError::Other(format!(
            "retained exact-source directory {} is no longer linked from its actual parent",
            display.display()
        )))
    }

    fn move_open_directory_exact(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        directory: &cap_std::fs::Dir,
        expected_identity: TrackedEntryIdentity,
        display: &Path,
    ) -> Result<()> {
        self.move_open_directory_exact_with_source_policy(
            source,
            destination,
            directory,
            expected_identity,
            display,
            false,
        )
    }

    fn move_open_directory_from_expected_source_exact(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        directory: &cap_std::fs::Dir,
        expected_identity: TrackedEntryIdentity,
        display: &Path,
    ) -> Result<()> {
        self.move_open_directory_exact_with_source_policy(
            source,
            destination,
            directory,
            expected_identity,
            display,
            true,
        )
    }

    fn move_open_directory_exact_with_source_policy(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        directory: &cap_std::fs::Dir,
        expected_identity: TrackedEntryIdentity,
        display: &Path,
        require_expected_source: bool,
    ) -> Result<()> {
        let retained_identity = tracked_open_directory_identity(directory)
            .map_err(|error| KinError::io(display, error))?;
        if retained_identity != expected_identity {
            return Err(KinError::Other(format!(
                "retained exact-source directory identity changed for {}",
                display.display()
            )));
        }

        #[cfg(unix)]
        let (restore_parent, restore_name) =
            self.locate_open_directory(directory, expected_identity, display)?;
        #[cfg(unix)]
        if require_expected_source {
            let located_parent_identity = tracked_open_directory_identity(&restore_parent)
                .map_err(|error| KinError::io(display, error))?;
            let expected_parent_identity = tracked_open_directory_identity(source.parent)
                .map_err(|error| KinError::io(display, error))?;
            if located_parent_identity != expected_parent_identity
                || restore_name.as_os_str() != source.name
            {
                return Err(KinError::Other(format!(
                    "retained exact-source directory {} moved away from its expected source name before namespace mutation",
                    display.display()
                )));
            }
        }
        #[cfg(windows)]
        if require_expected_source {
            let named = open_directory_nofollow(source.parent, source.name)
                .map_err(|error| KinError::io(display, error))?;
            if tracked_open_directory_identity(&named)
                .map_err(|error| KinError::io(display, error))?
                != expected_identity
            {
                return Err(KinError::Other(format!(
                    "retained exact-source directory {} moved away from its expected source name before namespace mutation",
                    display.display()
                )));
            }
        }
        #[cfg(windows)]
        let (restore_parent, restore_name) = (
            source
                .parent
                .try_clone()
                .map_err(|error| KinError::io(display, error))?,
            source.name.to_os_string(),
        );

        #[cfg(unix)]
        rustix::fs::renameat_with(
            &restore_parent,
            &restore_name,
            destination.parent,
            destination.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| KinError::io(display, error.into()))?;
        #[cfg(windows)]
        replace_windows_directory_handle_exact(
            directory,
            destination.parent,
            destination.name,
            false,
        )
        .map_err(|error| KinError::io(display, error))?;

        let post_move = (|| {
            // Read-only identity check: `named` only reads its identity for the
            // comparison below and is dropped, so DELETE access is unnecessary.
            let named = open_directory_nofollow(destination.parent, destination.name)
                .map_err(|error| KinError::io(display, error))?;
            let actual = tracked_open_directory_identity(&named)
                .map_err(|error| KinError::io(display, error))?;
            if actual != expected_identity {
                return Err(KinError::Other(format!(
                    "exact-source directory destination {} changed identity during publication",
                    display.display()
                )));
            }
            sync_namespace_parents(&restore_parent, display, destination.parent, display)
        })();
        if let Err(error) = post_move {
            #[cfg(unix)]
            let restoration = self
                .locate_open_directory(directory, expected_identity, display)
                .and_then(|(actual_parent, actual_name)| {
                    rustix::fs::renameat_with(
                        &actual_parent,
                        &actual_name,
                        &restore_parent,
                        &restore_name,
                        rustix::fs::RenameFlags::NOREPLACE,
                    )
                    .map_err(|restore_error| KinError::io(display, restore_error.into()))?;
                    sync_namespace_parents(&actual_parent, display, &restore_parent, display)
                });
            #[cfg(windows)]
            let restoration = replace_windows_directory_handle_exact(
                directory,
                &restore_parent,
                &restore_name,
                false,
            )
            .map_err(|restore_error| KinError::io(display, restore_error))
            .and_then(|()| {
                sync_namespace_parents(destination.parent, display, &restore_parent, display)
            });
            return match restoration {
                Ok(()) => Err(error),
                Err(restore_error) => Err(KinError::Other(format!(
                    "{error}; exact-source directory restoration also failed for {}: {restore_error}",
                    display.display()
                ))),
            };
        }
        Ok(())
    }

    fn stage_and_publish_directory(
        &self,
        transaction: &mut ReconciliationTransaction,
        destination_parent: &cap_std::fs::Dir,
        destination_name: &std::ffi::OsStr,
        relative: &Path,
        name_index: usize,
    ) -> Result<PublishedDirectory> {
        let stage_name = OsString::from(format!("created-dir-{name_index}"));
        transaction
            .directory
            .create_dir(&stage_name)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        let directory = self.open_existing_directory_for_removal(
            &transaction.directory,
            &stage_name,
            Path::new(&stage_name),
        )?;
        let identity = tracked_open_directory_identity(&directory)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        self.record_reconciliation_action(
            transaction,
            ReconciliationRecoveryAction::PublishDirectory {
                relative: relative.to_path_buf(),
                identity,
                slot: stage_name.to_string_lossy().into_owned(),
            },
        )?;
        let publication = self.move_open_directory_exact(
            NamedEntryLocation {
                parent: &transaction.directory,
                name: &stage_name,
            },
            NamedEntryLocation {
                parent: destination_parent,
                name: destination_name,
            },
            &directory,
            identity,
            &self.display_root.join(relative),
        );
        publication?;
        Ok(PublishedDirectory {
            relative: relative.to_path_buf(),
            identity,
            #[cfg(all(test, unix))]
            name_index,
            directory,
        })
    }

    fn relative_directory_is_empty(&self, relative: &Path) -> Result<bool> {
        let path = relative.to_str().ok_or_else(|| {
            KinError::Other(format!("graph-owned path is not UTF-8: {relative:?}"))
        })?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let name = std::ffi::OsStr::new(components[components.len() - 1]);
        let metadata = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(KinError::io(self.display_root.join(relative), error)),
        };
        if !metadata.is_dir() || metadata_is_reparse(&metadata) {
            return Ok(false);
        }
        let directory = self.open_existing_directory_for_removal(&parent, name, relative)?;
        self.open_directory_is_empty(&directory, relative)
    }

    fn relative_directory_identity(&self, relative: &Path) -> Result<Option<TrackedEntryIdentity>> {
        let path = relative.to_str().ok_or_else(|| {
            KinError::Other(format!("graph-owned path is not UTF-8: {relative:?}"))
        })?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let name = std::ffi::OsStr::new(components[components.len() - 1]);
        let metadata = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(KinError::io(self.display_root.join(relative), error)),
        };
        if !metadata.is_dir() || metadata_is_reparse(&metadata) {
            return Ok(None);
        }
        let directory = self.open_existing_directory_for_removal(&parent, name, relative)?;
        tracked_open_directory_identity(&directory)
            .map(Some)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))
    }

    fn open_directory_is_empty(
        &self,
        directory: &cap_std::fs::Dir,
        relative: &Path,
    ) -> Result<bool> {
        let mut entries = directory
            .entries()
            .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        match entries.next() {
            None => Ok(true),
            Some(Ok(_)) => Ok(false),
            Some(Err(error)) => Err(KinError::io(self.display_root.join(relative), error)),
        }
    }

    fn back_up_planned_empty_directory(
        &self,
        transaction: &mut ReconciliationTransaction,
        relative: &Path,
        expected_identity: TrackedEntryIdentity,
        name_index: usize,
    ) -> Result<BackedUpDirectory> {
        self.back_up_directory(
            transaction,
            relative,
            name_index,
            true,
            Some(expected_identity),
        )
    }

    fn back_up_directory(
        &self,
        transaction: &mut ReconciliationTransaction,
        relative: &Path,
        name_index: usize,
        require_empty: bool,
        expected_identity: Option<TrackedEntryIdentity>,
    ) -> Result<BackedUpDirectory> {
        let path = relative.to_str().ok_or_else(|| {
            KinError::Other(format!("graph-owned path is not UTF-8: {relative:?}"))
        })?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let directory = self.open_existing_directory_for_removal(&parent, source_name, relative)?;
        if require_empty && !self.open_directory_is_empty(&directory, relative)? {
            return Err(KinError::Other(format!(
                "graph-owned directory transition target {} was not empty at displacement",
                self.display_root.join(relative).display()
            )));
        }
        let identity = tracked_open_directory_identity(&directory)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        if expected_identity.is_some_and(|expected| expected != identity) {
            return Err(KinError::Other(format!(
                "working-copy directory {} changed identity after exact-source preflight",
                self.display_root.join(relative).display()
            )));
        }
        let backup_name = OsString::from(format!("directory-backup-{name_index}"));
        self.record_reconciliation_action(
            transaction,
            ReconciliationRecoveryAction::BackupDirectory {
                relative: relative.to_path_buf(),
                identity,
                slot: backup_name.to_string_lossy().into_owned(),
            },
        )?;
        self.move_open_directory_exact(
            NamedEntryLocation {
                parent: &parent,
                name: source_name,
            },
            NamedEntryLocation {
                parent: &transaction.directory,
                name: &backup_name,
            },
            &directory,
            identity,
            &self.display_root.join(relative),
        )?;
        if require_empty && !self.open_directory_is_empty(&directory, relative)? {
            let restoration = self.move_open_directory_exact(
                NamedEntryLocation {
                    parent: &transaction.directory,
                    name: &backup_name,
                },
                NamedEntryLocation {
                    parent: &parent,
                    name: source_name,
                },
                &directory,
                identity,
                &self.display_root.join(relative),
            );
            return match restoration {
                Ok(()) => Err(KinError::Other(format!(
                    "graph-owned directory {} changed contents during exact displacement",
                    self.display_root.join(relative).display()
                ))),
                Err(restore_error) => Err(KinError::Other(format!(
                    "graph-owned directory {} changed contents during exact displacement; restoration failed: {restore_error}",
                    self.display_root.join(relative).display()
                ))),
            };
        }
        Ok(BackedUpDirectory {
            _directory: directory,
        })
    }

    fn move_named_entry_exact(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        entry: &ValidatedSourceEntry<'_>,
        expected_identity: TrackedEntryIdentity,
        expected_state: TrackedObjectState,
        display: &Path,
    ) -> Result<()> {
        let kind = match entry.kind {
            TreeEntry::Blob { .. } => ExistingObjectKind::File,
            TreeEntry::Symlink { .. } => ExistingObjectKind::Symlink,
            TreeEntry::Gitlink { .. } => {
                return Err(KinError::Other(format!(
                    "gitlink {} cannot be displaced through the source projection",
                    entry.file_id
                )));
            }
        };
        let (inspected_identity, inspected_state) =
            self.inspect_named_existing_object(source.parent, source.name, kind, display)?;
        if inspected_identity != expected_identity || inspected_state != expected_state {
            return Err(KinError::Other(format!(
                "tracked working-copy path {} changed object identity, content, or mode before exact displacement; reconciliation refused",
                display.display()
            )));
        }
        self.move_named_entry_noreplace(
            source.parent,
            source.name,
            destination.parent,
            destination.name,
        )
        .map_err(|error| KinError::io(display, error))?;
        sync_namespace_parents(source.parent, display, destination.parent, display)?;

        let validation = self
            .validate_named_source_entry(destination.parent, destination.name, entry, display)
            .and_then(|actual_identity| {
                let (_, actual_state) = self.inspect_named_existing_object(
                    destination.parent,
                    destination.name,
                    kind,
                    display,
                )?;
                if actual_identity != expected_identity || actual_state != expected_state {
                    Err(KinError::Other(format!(
                        "tracked working-copy path {} changed object identity, content, or mode during exact displacement; reconciliation refused",
                        display.display()
                    )))
                } else {
                    Ok(())
                }
            });
        if let Err(error) = validation {
            let restored = self.move_named_entry_noreplace(
                destination.parent,
                destination.name,
                source.parent,
                source.name,
            );
            return match restored.and_then(|()| {
                sync_namespace_parents(destination.parent, display, source.parent, display)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            }) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(KinError::Other(format!(
                    "{error}; exact-source namespace restoration also failed for {}: {restore_error}",
                    display.display()
                ))),
            };
        }
        Ok(())
    }

    fn inspect_named_existing_object(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        expected_kind: ExistingObjectKind,
        display: &Path,
    ) -> Result<(TrackedEntryIdentity, TrackedObjectState)> {
        fn hash_reader(mut reader: impl Read) -> std::io::Result<[u8; 32]> {
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(hasher.finalize().into())
        }

        fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
            use sha2::{Digest, Sha256};

            Sha256::digest(bytes).into()
        }

        #[cfg(unix)]
        {
            let metadata = parent
                .symlink_metadata(name)
                .map_err(|error| KinError::io(display, error))?;
            let actual_kind = if metadata_is_reparse(&metadata) {
                ExistingObjectKind::Symlink
            } else if metadata.is_file() {
                ExistingObjectKind::File
            } else {
                return Err(KinError::Other(format!(
                    "working-copy object {} changed into an unsupported kind",
                    display.display()
                )));
            };
            if actual_kind != expected_kind {
                return Err(KinError::Other(format!(
                    "working-copy object {} changed kind after exact-source preflight",
                    display.display()
                )));
            }
            match actual_kind {
                ExistingObjectKind::File => {
                    use std::os::unix::fs::MetadataExt;

                    let file = rustix::fs::openat(
                        parent,
                        name,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map(std::fs::File::from)
                    .map_err(|error| KinError::io(display, error.into()))?;
                    let opened = file
                        .metadata()
                        .map_err(|error| KinError::io(display, error))?;
                    let identity = tracked_open_file_identity(&opened);
                    let state = TrackedObjectState {
                        content_sha256: hash_reader(file)
                            .map_err(|error| KinError::io(display, error))?,
                        mode: opened.mode() & 0o7777,
                    };
                    Ok((identity, state))
                }
                ExistingObjectKind::Symlink => {
                    use cap_std::fs::MetadataExt;

                    let target = rustix::fs::readlinkat(parent, name, Vec::new())
                        .map_err(|error| KinError::io(display, error.into()))?;
                    let after = parent
                        .symlink_metadata(name)
                        .map_err(|error| KinError::io(display, error))?;
                    let before_identity = tracked_entry_identity(&metadata);
                    let after_identity = tracked_entry_identity(&after);
                    if before_identity != after_identity || !metadata_is_reparse(&after) {
                        return Err(KinError::Other(format!(
                            "working-copy symbolic link {} changed while inspecting recovery state",
                            display.display()
                        )));
                    }
                    Ok((
                        after_identity,
                        TrackedObjectState {
                            content_sha256: hash_bytes(target.as_bytes()),
                            mode: after.mode() & 0o7777,
                        },
                    ))
                }
            }
        }
        #[cfg(windows)]
        {
            let mut file = self.open_windows_existing_object(parent, name, display)?;
            let metadata = file
                .metadata()
                .map_err(|error| KinError::io(display, error))?;
            let actual_kind = if metadata_is_reparse(&metadata) {
                ExistingObjectKind::Symlink
            } else if metadata.is_file() {
                ExistingObjectKind::File
            } else {
                return Err(KinError::Other(format!(
                    "working-copy object {} changed into an unsupported kind",
                    display.display()
                )));
            };
            if actual_kind != expected_kind {
                return Err(KinError::Other(format!(
                    "working-copy object {} changed kind after exact-source preflight",
                    display.display()
                )));
            }
            let identity =
                tracked_open_file_identity(&file).map_err(|error| KinError::io(display, error))?;
            let content_sha256 = match actual_kind {
                ExistingObjectKind::File => {
                    hash_reader(&mut file).map_err(|error| KinError::io(display, error))?
                }
                ExistingObjectKind::Symlink => {
                    use std::os::windows::ffi::OsStrExt;

                    let target = parent
                        .read_link(name)
                        .map_err(|error| KinError::io(display, error))?;
                    let wide = target
                        .as_os_str()
                        .encode_wide()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>();
                    hash_bytes(&wide)
                }
            };
            Ok((
                identity,
                TrackedObjectState {
                    content_sha256,
                    mode: 0,
                },
            ))
        }
    }

    #[cfg(windows)]
    fn open_windows_existing_object(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<cap_std::fs::File> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let mut options = cap_std::fs::OpenOptions::new();
        options
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .follow(FollowSymlinks::No);
        parent
            .open_with(name, &options)
            .map_err(|error| KinError::io(display, error))
    }

    fn move_existing_object_exact(
        &self,
        source: NamedEntryLocation<'_>,
        destination: NamedEntryLocation<'_>,
        kind: ExistingObjectKind,
        expected_identity: TrackedEntryIdentity,
        expected_state: TrackedObjectState,
        display: &Path,
    ) -> Result<()> {
        let (actual_identity, actual_state) =
            self.inspect_named_existing_object(source.parent, source.name, kind, display)?;
        if actual_identity != expected_identity {
            return Err(KinError::Other(format!(
                "working-copy object {} changed identity after exact-source preflight",
                display.display()
            )));
        }
        if actual_state != expected_state {
            return Err(KinError::Other(format!(
                "working-copy object {} changed content or mode after exact-source preflight",
                display.display()
            )));
        }

        #[cfg(unix)]
        rustix::fs::renameat_with(
            source.parent,
            source.name,
            destination.parent,
            destination.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| KinError::io(display, error.into()))?;
        #[cfg(windows)]
        let retained = self.open_windows_existing_object(source.parent, source.name, display)?;
        #[cfg(windows)]
        {
            let retained_identity = tracked_open_file_identity(&retained)
                .map_err(|error| KinError::io(display, error))?;
            if retained_identity != expected_identity {
                return Err(KinError::Other(format!(
                    "working-copy object {} changed identity while opening for exact displacement",
                    display.display()
                )));
            }
            replace_windows_file_handle_exact(
                &retained,
                destination.parent,
                destination.name,
                false,
            )
            .map_err(|error| KinError::io(display, error))?;
        }
        sync_namespace_parents(source.parent, display, destination.parent, display)?;

        let validation = self
            .inspect_named_existing_object(destination.parent, destination.name, kind, display)
            .and_then(|(actual_identity, actual_state)| {
                if actual_identity == expected_identity && actual_state == expected_state {
                    Ok(())
                } else {
                    Err(KinError::Other(format!(
                        "working-copy object {} changed identity, content, or mode during exact displacement",
                        display.display()
                    )))
                }
            });
        if let Err(error) = validation {
            #[cfg(unix)]
            let restoration = rustix::fs::renameat_with(
                destination.parent,
                destination.name,
                source.parent,
                source.name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|restore_error| KinError::io(display, restore_error.into()))
            .and_then(|()| {
                sync_namespace_parents(destination.parent, display, source.parent, display)
            });
            #[cfg(windows)]
            let restoration =
                replace_windows_file_handle_exact(&retained, source.parent, source.name, false)
                    .map_err(|restore_error| KinError::io(display, restore_error))
                    .and_then(|()| {
                        sync_namespace_parents(destination.parent, display, source.parent, display)
                    });
            return match restoration {
                Ok(()) => Err(error),
                Err(restore_error) => Err(KinError::Other(format!(
                    "{error}; exact-source object restoration also failed for {}: {restore_error}",
                    display.display()
                ))),
            };
        }
        Ok(())
    }

    fn back_up_existing_object(
        &self,
        transaction: &mut ReconciliationTransaction,
        object: &PlannedExistingObject,
        name_index: usize,
    ) -> Result<()> {
        let path = object.relative.to_str().ok_or_else(|| {
            KinError::Other(format!(
                "working-copy path is not UTF-8: {:?}",
                object.relative
            ))
        })?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let backup_name = OsString::from(format!("existing-backup-{name_index}"));
        self.record_reconciliation_action(
            transaction,
            ReconciliationRecoveryAction::BackupObject {
                relative: object.relative.clone(),
                kind: object.kind,
                identity: object.identity,
                state: object.state,
                slot: backup_name.to_string_lossy().into_owned(),
            },
        )?;
        self.move_existing_object_exact(
            NamedEntryLocation {
                parent: &parent,
                name: source_name,
            },
            NamedEntryLocation {
                parent: &transaction.directory,
                name: &backup_name,
            },
            object.kind,
            object.identity,
            object.state,
            &self.display_root.join(&object.relative),
        )
    }

    fn displace_previous_entry<'a>(
        &self,
        transaction: &mut ReconciliationTransaction,
        entry: ValidatedSourceEntry<'a>,
        expected_identity: TrackedEntryIdentity,
        name_index: usize,
    ) -> Result<()> {
        let path = projection_path(entry.file_id)?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let backup_name = format!("backup-{name_index}");
        let display = self.display_path(&components);
        let kind = match entry.kind {
            TreeEntry::Blob { .. } => ExistingObjectKind::File,
            TreeEntry::Symlink { .. } => ExistingObjectKind::Symlink,
            TreeEntry::Gitlink { .. } => {
                return Err(KinError::Other(format!(
                    "gitlink {} cannot be displaced through the source projection",
                    entry.file_id
                )));
            }
        };
        let (actual_identity, state) =
            self.inspect_named_existing_object(&parent, source_name, kind, &display)?;
        if actual_identity != expected_identity {
            return Err(KinError::Other(format!(
                "tracked working-copy path {} changed object identity before exact displacement",
                display.display()
            )));
        }
        self.record_reconciliation_action(
            transaction,
            ReconciliationRecoveryAction::BackupObject {
                relative: PathBuf::from(path),
                kind,
                identity: expected_identity,
                state,
                slot: backup_name.clone(),
            },
        )?;
        self.move_named_entry_exact(
            NamedEntryLocation {
                parent: &parent,
                name: source_name,
            },
            NamedEntryLocation {
                parent: &transaction.directory,
                name: std::ffi::OsStr::new(&backup_name),
            },
            &entry,
            expected_identity,
            state,
            &display,
        )
    }

    fn publish_staged_entry(
        &self,
        transaction: &mut ReconciliationTransaction,
        staged: &StagedReconciliationEntry<'_>,
    ) -> Result<()> {
        let path = projection_path(staged.entry.file_id)?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let destination_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let stage_name = format!("stage-{}", staged.name_index);
        let display = self.display_path(&components);
        let kind = match staged.entry.kind {
            TreeEntry::Blob { .. } => ExistingObjectKind::File,
            TreeEntry::Symlink { .. } => ExistingObjectKind::Symlink,
            TreeEntry::Gitlink { .. } => {
                return Err(KinError::Other(format!(
                    "gitlink {} cannot be published through the source projection",
                    staged.entry.file_id
                )));
            }
        };
        self.record_reconciliation_action(
            transaction,
            ReconciliationRecoveryAction::PublishObject {
                relative: PathBuf::from(path),
                kind,
                identity: staged.identity,
                state: staged.state,
                slot: stage_name.clone(),
            },
        )?;
        fail_publication_if_injected()?;
        self.move_named_entry_exact(
            NamedEntryLocation {
                parent: &transaction.directory,
                name: std::ffi::OsStr::new(&stage_name),
            },
            NamedEntryLocation {
                parent: &parent,
                name: destination_name,
            },
            &staged.entry,
            staged.identity,
            staged.state,
            &display,
        )
    }

    #[cfg(all(test, unix))]
    fn move_published_directory_back(
        &self,
        transaction: &cap_std::fs::Dir,
        published: &PublishedDirectory,
    ) -> Result<()> {
        let path = published.relative.to_str().ok_or_else(|| {
            KinError::Other(format!(
                "graph-owned path is not UTF-8: {:?}",
                published.relative
            ))
        })?;
        let components = validate_source_path(path)?;
        let parent = self.open_existing_parent(&components)?;
        let source_name = std::ffi::OsStr::new(components[components.len() - 1]);
        let discard_name = OsString::from(format!("discard-created-dir-{}", published.name_index));
        self.move_open_directory_exact(
            NamedEntryLocation {
                parent: &parent,
                name: source_name,
            },
            NamedEntryLocation {
                parent: transaction,
                name: &discard_name,
            },
            &published.directory,
            published.identity,
            &self.display_root.join(&published.relative),
        )
    }

    fn validate_tracked_entry_unchanged(
        &self,
        entry: &ValidatedSourceEntry<'_>,
    ) -> Result<TrackedEntryIdentity> {
        let components =
            validate_source_entry_components(entry.file_id, entry.kind, entry.content)?;
        let mut relative = PathBuf::new();
        let components = components
            .into_iter()
            .map(|component| {
                relative.push(component);
                OsString::from(component)
            })
            .collect();
        self.validate_tracked_entry_unchanged_at_path(
            entry,
            &ValidatedProjectionPath {
                components,
                relative,
            },
        )
    }

    fn validate_frozen_entry_unchanged(
        &self,
        entry: &ValidatedSourceEntry<'_>,
    ) -> Result<TrackedEntryIdentity> {
        let path = validate_projection_proof_entry_path(entry.file_id, entry.kind)?;
        self.validate_tracked_entry_unchanged_at_path(entry, &path)
    }

    fn verify_frozen_graph_only(
        &self,
        file_id: &RepoPath,
        disposition: SourceProjectionDisposition,
    ) -> Result<ExactProjectionEntryProof> {
        // A Gitlink can itself have a byte path this host cannot name. Keep
        // the repository kind in `disposition`, but bind the host proof to
        // non-materialization instead of trying to manufacture a lossy path
        // merely to apply Gitlink directory policy.
        let materializable_path = materializable_projection_proof_path(file_id)?;
        if materializable_path.is_none() {
            return Ok(ExactProjectionEntryProof::HostUnrepresentableAbsent);
        }
        match disposition {
            SourceProjectionDisposition::GraphOnlyGitlink => self.verify_frozen_gitlink(file_id),
            SourceProjectionDisposition::GraphOnlyHostUnrepresentable => {
                self.verify_frozen_path_absent(
                    file_id,
                    materializable_path
                        .as_ref()
                        .expect("host-materializable graph-only path"),
                )?;
                Ok(ExactProjectionEntryProof::HostUnrepresentableAbsent)
            }
            SourceProjectionDisposition::Materialized => Err(KinError::Other(format!(
                "materialized repository member {file_id} was supplied to graph-only verification"
            ))),
        }
    }

    fn revalidate_frozen_graph_only(
        &self,
        file_id: &RepoPath,
        disposition: SourceProjectionDisposition,
        expected: &ExactProjectionEntryProof,
    ) -> Result<()> {
        let materializable_path = materializable_projection_proof_path(file_id)?;
        if materializable_path.is_none() {
            return match expected {
                ExactProjectionEntryProof::HostUnrepresentableAbsent => Ok(()),
                _ => Err(KinError::Other(
                    "host-unrepresentable repository path was paired with a materialized host proof"
                        .to_string(),
                )),
            };
        }
        match (disposition, expected) {
            (
                SourceProjectionDisposition::GraphOnlyGitlink,
                ExactProjectionEntryProof::GitlinkAbsent
                | ExactProjectionEntryProof::GitlinkDirectory { .. },
            ) => self.revalidate_frozen_gitlink(file_id, expected),
            (
                SourceProjectionDisposition::GraphOnlyHostUnrepresentable,
                ExactProjectionEntryProof::HostUnrepresentableAbsent,
            ) => {
                self.verify_frozen_path_absent(
                    file_id,
                    materializable_path
                        .as_ref()
                        .expect("host-materializable graph-only path"),
                )?;
                Ok(())
            }
            _ => Err(KinError::Other(
                "graph-only projection proof does not match its host disposition".to_string(),
            )),
        }
    }

    fn verify_frozen_path_absent(
        &self,
        file_id: &RepoPath,
        path: &ValidatedProjectionPath,
    ) -> Result<()> {
        let display = self.display_root.join(&path.relative);
        let mut parent = self.clone_root()?;
        let mut relative = PathBuf::new();
        for component in &path.components[..path.components.len() - 1] {
            relative.push(component);
            let metadata = match parent.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(KinError::io(self.display_root.join(&relative), error)),
            };
            if !metadata.is_dir() || metadata_is_reparse(&metadata) {
                return Err(KinError::Other(format!(
                    "host-unrepresentable graph-only path {file_id} is blocked by a non-directory or followed-link ancestor {}",
                    self.display_root.join(&relative).display()
                )));
            }
            let child = open_directory_nofollow(&parent, component)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?;
            if !opened_directory_matches_entry(&child, &metadata)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?
            {
                return Err(KinError::Other(format!(
                    "host-unrepresentable graph-only path {file_id} changed ancestor identity during verification"
                )));
            }
            parent = child;
        }
        let name = path.components[path.components.len() - 1].as_os_str();
        match parent.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KinError::io(&display, error)),
            Ok(_) => Err(KinError::Other(format!(
                "host-unrepresentable graph-only path {file_id} has a conflicting working-copy object at {}",
                display.display()
            ))),
        }
    }

    fn verify_frozen_gitlink(&self, file_id: &RepoPath) -> Result<ExactProjectionEntryProof> {
        let path = validate_projection_proof_path(file_id)?;
        let display = self.display_root.join(&path.relative);
        let conflict = |reason: &str| {
            KinError::Other(format!(
                "graph-only gitlink path {} is neither absent nor a no-follow real directory ({reason})",
                display.display()
            ))
        };
        let mut parent = self.clone_root()?;
        let mut relative = PathBuf::new();
        for component in &path.components[..path.components.len() - 1] {
            relative.push(component);
            let metadata = match parent.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(ExactProjectionEntryProof::GitlinkAbsent);
                }
                Err(error) => {
                    return Err(KinError::io(self.display_root.join(&relative), error));
                }
            };
            if !metadata.is_dir() || metadata_is_reparse(&metadata) {
                return Err(conflict("an ancestor is not a no-follow real directory"));
            }
            let child = open_directory_nofollow(&parent, component)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?;
            if !opened_directory_matches_entry(&child, &metadata)
                .map_err(|error| KinError::io(self.display_root.join(&relative), error))?
            {
                return Err(conflict(
                    "an ancestor changed identity while being retained",
                ));
            }
            parent = child;
        }

        let name = path.components[path.components.len() - 1].as_os_str();
        let metadata = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ExactProjectionEntryProof::GitlinkAbsent);
            }
            Err(error) => return Err(KinError::io(&display, error)),
        };
        if !metadata.is_dir() || metadata_is_reparse(&metadata) {
            return Err(conflict(
                "the named entry is a file, symbolic link, reparse point, or special object",
            ));
        }
        let directory = open_directory_nofollow(&parent, name)
            .map_err(|error| KinError::io(&display, error))?;
        let identity = tracked_open_directory_identity(&directory)
            .map_err(|error| KinError::io(&display, error))?;
        if !opened_directory_matches_entry(&directory, &metadata)
            .map_err(|error| KinError::io(&display, error))?
        {
            return Err(conflict(
                "the named directory changed identity while being retained",
            ));
        }
        Ok(ExactProjectionEntryProof::GitlinkDirectory {
            directory,
            identity,
        })
    }

    fn revalidate_frozen_gitlink(
        &self,
        file_id: &RepoPath,
        expected: &ExactProjectionEntryProof,
    ) -> Result<()> {
        let actual = self.verify_frozen_gitlink(file_id)?;
        let display = self
            .display_root
            .join(validate_projection_proof_path(file_id)?.relative);
        match (expected, actual) {
            (ExactProjectionEntryProof::GitlinkAbsent, ExactProjectionEntryProof::GitlinkAbsent) => {
                Ok(())
            }
            (
                ExactProjectionEntryProof::GitlinkDirectory {
                    directory,
                    identity,
                },
                ExactProjectionEntryProof::GitlinkDirectory {
                    identity: actual_identity,
                    ..
                },
            ) => {
                let retained_identity = tracked_open_directory_identity(directory)
                    .map_err(|error| KinError::io(&display, error))?;
                if retained_identity != *identity || actual_identity != *identity {
                    return Err(KinError::Other(format!(
                        "graph-only gitlink directory {} changed identity after exact projection verification",
                        display.display()
                    )));
                }
                Ok(())
            }
            (ExactProjectionEntryProof::GitlinkAbsent, _) => Err(KinError::Other(format!(
                "graph-only gitlink path {} materialized after exact projection verification",
                display.display()
            ))),
            (ExactProjectionEntryProof::GitlinkDirectory { .. }, _) => {
                Err(KinError::Other(format!(
                    "graph-only gitlink directory {} disappeared or changed kind after exact projection verification",
                    display.display()
                )))
            }
            (ExactProjectionEntryProof::HostUnrepresentableAbsent, _) => Err(KinError::Other(
                "host-unrepresentable proof was supplied for a materializable gitlink".to_string(),
            )),
            (ExactProjectionEntryProof::Materialized { .. }, _) => Err(KinError::Other(
                "materialized source proof was supplied for a graph-only gitlink".to_string(),
            )),
        }
    }

    fn validate_tracked_entry_unchanged_at_path(
        &self,
        entry: &ValidatedSourceEntry<'_>,
        path: &ValidatedProjectionPath,
    ) -> Result<TrackedEntryIdentity> {
        let display = self.display_root.join(&path.relative);
        let conflict = |reason: &str| {
            KinError::tracked_projection_drift(format!(
                "tracked working-copy path {} differs from prior workspace source ({reason}); exact workspace reconciliation refused",
                display.display()
            ))
        };
        let mut parent = self.clone_root()?;
        let mut relative = PathBuf::new();
        for component in &path.components[..path.components.len() - 1] {
            relative.push(component);
            let metadata = match parent.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(conflict("a parent directory is missing"));
                }
                Err(error) => {
                    return Err(KinError::io(self.display_root.join(&relative), error));
                }
            };
            if !metadata.is_dir() || metadata_is_reparse(&metadata) {
                return Err(conflict("a parent path is not the expected directory"));
            }
            parent = self.open_existing_directory(&parent, component, &relative)?;
        }

        let name = path.components[path.components.len() - 1].as_os_str();
        let metadata = match parent.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(conflict("the tracked path is missing"));
            }
            Err(error) => return Err(KinError::io(&display, error)),
        };
        let identity = match entry.kind {
            TreeEntry::Blob { executable, .. } => {
                if !metadata.is_file() || metadata_is_reparse(&metadata) {
                    return Err(conflict("the tracked path kind changed"));
                }

                #[cfg(unix)]
                let mut file = rustix::fs::openat(
                    &parent,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map(std::fs::File::from)
                .map_err(|error| KinError::io(&display, error.into()))?;
                #[cfg(windows)]
                let mut file = {
                    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

                    let mut options = cap_std::fs::OpenOptions::new();
                    options.read(true).follow(FollowSymlinks::No);
                    parent
                        .open_with(name, &options)
                        .map_err(|error| KinError::io(&display, error))?
                };
                let opened_metadata = file
                    .metadata()
                    .map_err(|error| KinError::io(&display, error))?;
                if !opened_metadata.is_file() {
                    return Err(conflict("the tracked path kind changed while opening"));
                }
                #[cfg(windows)]
                let _ = executable;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    let actual_executable = opened_metadata.permissions().mode() & 0o111 != 0;
                    if actual_executable != executable {
                        return Err(conflict("the executable bit changed"));
                    }
                }
                #[cfg(windows)]
                if metadata_is_reparse(&opened_metadata) {
                    return Err(conflict("the tracked path kind changed while opening"));
                }
                if !reader_matches_bytes(&mut file, entry.content)
                    .map_err(|error| KinError::io(&display, error))?
                {
                    return Err(conflict("the file content changed"));
                }
                #[cfg(unix)]
                {
                    tracked_open_file_identity(&opened_metadata)
                }
                #[cfg(windows)]
                {
                    tracked_open_file_identity(&file)
                        .map_err(|error| KinError::io(&display, error))?
                }
            }
            TreeEntry::Symlink { .. } => {
                #[cfg(windows)]
                return Err(KinError::Other(
                    "safe exact symbolic-link checkout is unsupported on Windows".to_string(),
                ));
                #[cfg(unix)]
                {
                    if !metadata_is_reparse(&metadata) {
                        return Err(conflict("the tracked path kind changed"));
                    }
                    let target = rustix::fs::readlinkat(&parent, name, Vec::new())
                        .map_err(|error| KinError::io(&display, error.into()))?;
                    if target.as_bytes() != entry.content {
                        return Err(conflict("the symbolic-link target changed"));
                    }
                    let revalidated = parent
                        .symlink_metadata(name)
                        .map_err(|error| KinError::io(&display, error))?;
                    if !metadata_is_reparse(&revalidated)
                        || tracked_entry_identity(&revalidated) != tracked_entry_identity(&metadata)
                    {
                        return Err(conflict(
                            "the symbolic-link identity changed while reading its target",
                        ));
                    }
                    tracked_entry_identity(&revalidated)
                }
            }
            TreeEntry::Gitlink { .. } => {
                return Err(KinError::Other(format!(
                    "gitlink {} cannot be validated as a repository-owned source object",
                    entry.file_id
                )));
            }
        };
        Ok(identity)
    }

    fn open_existing_parent(&self, components: &[&str]) -> Result<cap_std::fs::Dir> {
        let mut parent = self.clone_root()?;
        let mut relative = PathBuf::new();
        for component in &components[..components.len() - 1] {
            relative.push(component);
            parent =
                self.open_existing_directory(&parent, std::ffi::OsStr::new(*component), &relative)?;
        }
        Ok(parent)
    }

    fn open_or_create_directory(
        &self,
        parent: &cap_std::fs::Dir,
        component: &str,
    ) -> Result<cap_std::fs::Dir> {
        for _ in 0..8 {
            if let Ok(directory) = open_directory_nofollow(parent, std::ffi::OsStr::new(component))
            {
                return Ok(directory);
            }
            match parent.symlink_metadata(component) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match create_capability_directory(parent, std::ffi::OsStr::new(component)) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(KinError::io(self.display_root.join(component), error));
                        }
                    }
                }
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => {
                    return open_directory_nofollow(parent, std::ffi::OsStr::new(component))
                        .map_err(|error| KinError::io(self.display_root.join(component), error));
                }
                Ok(_) => {
                    match remove_capability_file_or_symlink(parent, std::ffi::OsStr::new(component))
                    {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(KinError::io(self.display_root.join(component), error));
                        }
                    }
                }
                Err(error) => {
                    return Err(KinError::io(self.display_root.join(component), error));
                }
            }
        }
        Err(KinError::Other(format!(
            "projection parent changed repeatedly during checkout: {}",
            self.display_root.join(component).display()
        )))
    }

    fn open_existing_directory(
        &self,
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        relative: &Path,
    ) -> Result<cap_std::fs::Dir> {
        open_directory_nofollow(parent, component)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))
    }

    fn open_existing_directory_for_removal(
        &self,
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        relative: &Path,
    ) -> Result<cap_std::fs::Dir> {
        open_directory_nofollow_for_removal(parent, component)
            .map_err(|error| KinError::io(self.display_root.join(relative), error))
    }

    fn remove_directory_tree(
        &self,
        parent: &cap_std::fs::Dir,
        name: &std::ffi::OsStr,
        relative: &Path,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            // cap-std 4.0.2's Unix implementation performs a no-follow stat,
            // opens the directory no-follow, then recursively removes through
            // held child directory descriptors.
            parent
                .remove_dir_all(name)
                .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        }
        #[cfg(windows)]
        {
            let directory = self.open_existing_directory_for_removal(parent, name, relative)?;
            self.remove_windows_directory_contents(&directory, relative)?;
            mark_windows_directory_for_deletion(directory)
                .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn remove_windows_directory_contents(
        &self,
        directory: &cap_std::fs::Dir,
        relative: &Path,
    ) -> Result<()> {
        let entries = directory
            .entries()
            .map_err(|error| KinError::io(self.display_root.join(relative), error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| KinError::io(self.display_root.join(relative), error))?;
            let name = entry.file_name();
            let child_relative = relative.join(&name);
            let metadata = directory
                .symlink_metadata(&name)
                .map_err(|error| KinError::io(self.display_root.join(&child_relative), error))?;
            if metadata.is_dir() && !metadata_is_reparse(&metadata) {
                let child =
                    self.open_existing_directory_for_removal(directory, &name, &child_relative)?;
                self.remove_windows_directory_contents(&child, &child_relative)?;
                mark_windows_directory_for_deletion(child).map_err(|error| {
                    KinError::io(self.display_root.join(&child_relative), error)
                })?;
            } else {
                remove_capability_file_or_symlink(directory, &name).map_err(|error| {
                    KinError::io(self.display_root.join(&child_relative), error)
                })?;
            }
        }
        Ok(())
    }

    fn clone_root(&self) -> Result<cap_std::fs::Dir> {
        self.root
            .try_clone()
            .map_err(|error| KinError::io(&self.display_root, error))
    }

    fn display_path(&self, components: &[&str]) -> PathBuf {
        self.display_root.join(components.join("/"))
    }
}

#[cfg(unix)]
fn open_projection_root_nofollow(path: &Path) -> Result<cap_std::fs::Dir> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map(cap_std::fs::Dir::from_std_file)
    .map_err(|error| KinError::io(path, std::io::Error::from(error)))
}

#[cfg(windows)]
fn open_projection_root_nofollow(path: &Path) -> Result<cap_std::fs::Dir> {
    open_windows_projection_root(path).map_err(|error| KinError::io(path, error))
}

#[cfg(unix)]
fn open_directory_nofollow(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    rustix::fs::openat(
        parent,
        component,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(|fd| cap_std::fs::Dir::from_std_file(fd.into()))
    .map_err(Into::into)
}

#[cfg(any(unix, windows))]
fn reader_matches_bytes(reader: &mut impl Read, expected: &[u8]) -> std::io::Result<bool> {
    let mut offset = 0;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(offset == expected.len());
        }
        let Some(end) = offset.checked_add(read) else {
            return Ok(false);
        };
        if end > expected.len() || buffer[..read] != expected[offset..end] {
            return Ok(false);
        }
        offset = end;
    }
}

#[cfg(unix)]
fn open_directory_nofollow_for_removal(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    open_directory_nofollow(parent, component)
}

#[cfg(unix)]
fn create_capability_directory(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<()> {
    rustix::fs::mkdirat(parent, component, rustix::fs::Mode::from_raw_mode(0o755))
        .map_err(Into::into)
}

#[cfg(unix)]
fn remove_capability_file_or_symlink(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<()> {
    rustix::fs::unlinkat(parent, component, rustix::fs::AtFlags::empty()).map_err(Into::into)
}

#[cfg(unix)]
fn metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn open_directory_nofollow(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    // cap-std opens directories without FILE_SHARE_DELETE, which collides on
    // Windows with a peer that holds a concurrent handle under `.kin` (for
    // example the graph store's own snapshot/index). Share read/write/delete so
    // the projection can open a control-plane directory alongside those handles;
    // POSIX permits this implicitly.
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = parent.open_with(component, &options)?;
    let metadata = file.metadata()?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "projection directory component is a reparse point or non-directory: {}",
            component.to_string_lossy()
        )));
    }
    Ok(cap_std::fs::Dir::from_std_file(file.into_std()))
}

#[cfg(windows)]
fn open_directory_nofollow_for_removal(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    // Request DELETE access to remove the directory, and share read/write/delete
    // so the open does not collide on Windows with a peer holding a concurrent
    // handle under `.kin`. cap-std's directory default omits FILE_SHARE_DELETE,
    // which raises a sharing violation here even though POSIX allows the same
    // unlink-while-open pattern.
    options
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = parent.open_with(component, &options)?;
    let metadata = file.metadata()?;
    if metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "projection removal target is a reparse point or non-directory: {}",
            component.to_string_lossy()
        )));
    }
    Ok(cap_std::fs::Dir::from_std_file(file.into_std()))
}

#[cfg(windows)]
fn create_capability_directory(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<()> {
    parent.create_dir(component)
}

#[cfg(windows)]
fn remove_capability_file_or_symlink(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use cap_fs_ext::DirExt;

    parent.remove_file_or_symlink(component)
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    cap_fs_ext::OsMetadataExt::file_attributes(metadata) & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn replace_windows_file_handle_exact(
    source: &cap_std::fs::File,
    destination_parent: &cap_std::fs::Dir,
    destination_name: &std::ffi::OsStr,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    replace_windows_handle_exact(
        source.as_raw_handle().cast(),
        destination_parent,
        destination_name,
        replace_existing,
    )
}

#[cfg(windows)]
fn replace_windows_directory_handle_exact(
    source: &cap_std::fs::Dir,
    destination_parent: &cap_std::fs::Dir,
    destination_name: &std::ffi::OsStr,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    replace_windows_handle_exact(
        source.as_raw_handle().cast(),
        destination_parent,
        destination_name,
        replace_existing,
    )
}

/// Resolve an open directory/file handle to its fully-qualified verbatim `\\?\`
/// final path. Grows the buffer until `GetFinalPathNameByHandleW` reports the
/// full length, mirroring the proven managed-config resolution idiom.
#[cfg(windows)]
fn read_windows_final_path(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<Vec<u16>> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let mut capacity = 256_usize;
    loop {
        let mut buffer = vec![0_u16; capacity];
        let length = u32::try_from(buffer.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exact-source destination path buffer exceeds the Windows length limit",
            )
        })?;
        let written =
            unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), length, flags) };
        if written == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let written = written as usize;
        if written >= buffer.len() {
            // The buffer was too small; the return value is the required length
            // including the terminating NUL. Grow past it and retry.
            capacity = written.checked_add(1).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "exact-source destination path length overflow",
                )
            })?;
            continue;
        }
        buffer.truncate(written);
        return Ok(buffer);
    }
}

#[cfg(windows)]
fn replace_windows_handle_exact(
    source: windows_sys::Win32::Foundation::HANDLE,
    destination_parent: &cap_std::fs::Dir,
    destination_name: &std::ffi::OsStr,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };

    let mut components = Path::new(destination_name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(name)) if name == destination_name)
        || components.next().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "exact-source destination must be one normal path component",
        ));
    }
    let name_wide = destination_name.encode_wide().collect::<Vec<_>>();
    if name_wide.is_empty() || name_wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "exact-source destination is empty or contains an interior NUL",
        ));
    }
    // SetFileInformationByHandle's FileRenameInfo requires RootDirectory to be NULL
    // and FileName to carry the fully-qualified destination; passing a directory
    // handle in RootDirectory is rejected with ERROR_INVALID_PARAMETER (only the NT
    // NtSetInformationFile path honors a relative name against a root handle).
    // Resolve the parent's verbatim `\\?\` final path from its handle and append the
    // validated single-component leaf.
    //
    // A full-path destination is re-resolved from the volume root, so unlike a
    // parent-handle-relative rename it does not by itself pin the destination against
    // an ancestor swap. Callers bound that window: control renames hold the projection
    // lock, working-copy displacement re-validates post-rename identity/state and rolls
    // back on mismatch, and new destinations pass replace_existing = false so a raced
    // destination fails closed rather than being overwritten.
    let mut destination_wide = read_windows_final_path(destination_parent.as_raw_handle().cast())?;
    destination_wide.push(u16::from(b'\\'));
    destination_wide.extend_from_slice(&name_wide);
    let name_bytes = destination_wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exact-source destination length overflow",
            )
        })?;
    let buffer_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u16>()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exact-source rename buffer length overflow",
            )
        })?;
    let file_name_length = u32::try_from(name_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "exact-source destination exceeds the Windows length limit",
        )
    })?;
    let buffer_length = u32::try_from(buffer_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "exact-source rename buffer exceeds the Windows length limit",
        )
    })?;
    let mut storage = vec![0_usize; buffer_bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        // FileRenameInfo reads this union field as ReplaceIfExists: a nonzero low
        // byte replaces an existing destination. New workspace-only paths pass 0 so a
        // raced untracked destination fails closed rather than being overwritten;
        // previously-tracked paths pass 1 to replace. FileRenameInfo (not the Ex
        // class) is used because FileRenameInfoEx raises ERROR_INVALID_PARAMETER
        // where its POSIX-semantics extension is unavailable, and no POSIX flag is
        // needed here.
        (*info).Anonymous.Flags = u32::from(replace_existing);
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = file_name_length;
        std::ptr::copy_nonoverlapping(
            destination_wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            destination_wide.len(),
        );
        *std::ptr::addr_of_mut!((*info).FileName)
            .cast::<u16>()
            .add(destination_wide.len()) = 0;
    }
    if unsafe { SetFileInformationByHandle(source, FileRenameInfo, info.cast(), buffer_length) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn mark_windows_directory_for_deletion(directory: cap_std::fs::Dir) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let directory = directory.into_std_file();
    mark_windows_handle_for_deletion(directory.as_raw_handle().cast())?;
    drop(directory);
    Ok(())
}

#[cfg(windows)]
fn mark_windows_handle_for_deletion(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let removed = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_projection_root(root: &Path) -> std::io::Result<cap_std::fs::Dir> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    if absolute
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "projection root may not contain parent traversal",
        ));
    }
    let ambient_root = absolute
        .ancestors()
        .last()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "projection root has no filesystem root",
            )
        })?;
    let relative = absolute.strip_prefix(ambient_root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "projection root is not beneath its filesystem root",
        )
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "projection root contains an unsupported component",
        ));
    }

    let mut current =
        cap_std::fs::Dir::open_ambient_dir(ambient_root, cap_std::ambient_authority())?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            unreachable!("projection root was validated as normal components")
        };
        current = open_directory_nofollow(&current, name)?;
    }
    Ok(current)
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackedPathRelation {
    Exact,
    Ancestor,
    Descendant,
    Unrelated,
}

#[cfg(any(unix, windows))]
struct TrackedPathClassifier {
    /// Complete graph-owned leaf keys.
    exact: HashSet<Vec<OsString>>,
    /// Strict prefixes of graph-owned leaves. A filesystem directory whose key
    /// is in this set must be traversed because it contains a tracked leaf.
    ancestors: HashSet<Vec<OsString>>,
}

#[cfg(any(unix, windows))]
impl TrackedPathClassifier {
    fn new<'a>(tracked: impl IntoIterator<Item = &'a RepoPath>) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut ancestors = HashSet::new();
        for file_id in tracked {
            let key = projection_path_key(Path::new(projection_path(file_id)?));
            for prefix_len in 1..key.len() {
                ancestors.insert(key[..prefix_len].to_vec());
            }
            exact.insert(key);
        }
        Ok(Self { exact, ancestors })
    }

    fn relation(&self, relative: &Path) -> TrackedPathRelation {
        self.relation_with_probe_count(relative).0
    }

    /// Classify one filesystem path with a number of hash probes bounded by
    /// path depth, independent of the number of graph-owned files. Returning
    /// the probe count keeps the complexity contract directly testable without
    /// a timing-sensitive benchmark.
    fn relation_with_probe_count(&self, relative: &Path) -> (TrackedPathRelation, usize) {
        let key = projection_path_key(relative);
        let mut probes = 1;
        if self.exact.contains(key.as_slice()) {
            return (TrackedPathRelation::Exact, probes);
        }
        probes += 1;
        if self.ancestors.contains(key.as_slice()) {
            return (TrackedPathRelation::Ancestor, probes);
        }
        for prefix_len in 1..key.len() {
            probes += 1;
            if self.exact.contains(&key[..prefix_len]) {
                return (TrackedPathRelation::Descendant, probes);
            }
        }
        (TrackedPathRelation::Unrelated, probes)
    }
}

#[cfg(any(unix, windows))]
fn projection_path_key(path: &Path) -> Vec<OsString> {
    path.components()
        .map(|component| match component {
            std::path::Component::Normal(component) => {
                #[cfg(any(windows, target_os = "macos"))]
                if let Some(component) = component.to_str() {
                    return OsString::from(projection_component_comparison_key(component));
                }
                component.to_os_string()
            }
            other => other.as_os_str().to_os_string(),
        })
        .collect()
}

#[cfg(any(unix, windows))]
fn projection_control_names_match(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    match (left.to_str(), right.to_str()) {
        (Some(left), Some(right)) => {
            projection_component_comparison_key(left) == projection_component_comparison_key(right)
        }
        _ => left == right,
    }
}

fn is_reserved_source_component(component: &str) -> bool {
    if component.eq_ignore_ascii_case(".git")
        || component.eq_ignore_ascii_case(".kin")
        || component.eq_ignore_ascii_case(".kin-session")
    {
        return true;
    }

    let key = projection_component_comparison_key(component);
    matches!(key.as_str(), ".git" | ".kin" | ".kin-session")
}

fn validate_portable_source_path(path: &str) -> Result<Vec<&str>> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\0', '\\'])
    {
        return Err(KinError::Other(format!(
            "unsafe graph-owned source path {path:?}"
        )));
    }
    let components: Vec<_> = path.split('/').collect();
    if components.iter().any(|component| {
        component.is_empty()
            || component.len() > 255
            || matches!(*component, "." | "..")
            || is_reserved_source_component(component)
            || !is_safe_windows_source_component(component)
    }) {
        return Err(KinError::Other(format!(
            "unsafe graph-owned source path {path:?}"
        )));
    }
    Ok(components)
}

fn validate_source_path(path: &str) -> Result<Vec<&str>> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\0', '\\'])
    {
        return Err(KinError::Other(format!(
            "unsafe graph-owned source path {path:?}"
        )));
    }
    let components: Vec<_> = path.split('/').collect();
    if components.iter().any(|component| {
        component.is_empty()
            || component.len() > 255
            || matches!(*component, "." | "..")
            || is_reserved_source_component(component)
            || cfg!(windows) && !is_safe_windows_source_component(component)
    }) {
        return Err(KinError::Other(format!(
            "unsafe graph-owned source path {path:?}"
        )));
    }
    Ok(components)
}

fn is_safe_windows_source_component(component: &str) -> bool {
    if component.encode_utf16().count() > 255
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{1f}' || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
    {
        return false;
    }

    // Mirror cap-primitives' Windows open guard: take the file prefix before
    // the first non-leading dot, trim trailing whitespace from that prefix,
    // then apply Unicode uppercase. A looser check can pass global preflight
    // and fail only after destructive tree preparation has begun.
    let bytes = component.as_bytes();
    let stem_end = bytes
        .get(1..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'.'))
        .map_or(bytes.len(), |index| index + 1);
    let stem = component[..stem_end].trim_end().to_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    ) {
        return false;
    }
    true
}

fn validate_source_symlink_target(path: &[&str], target: &str) -> Result<()> {
    validate_source_symlink_target_with_windows_rules(path, target, cfg!(windows))
}

fn validate_source_symlink_target_with_windows_rules(
    path: &[&str],
    target: &str,
    enforce_windows_components: bool,
) -> Result<()> {
    if target.is_empty()
        || target.len() > 4096
        || target.starts_with('/')
        || target.contains(['\0', '\\'])
    {
        return Err(KinError::Other(format!(
            "source symlink has unsafe target {target:?}"
        )));
    }
    let mut resolved: Vec<&str> = path[..path.len().saturating_sub(1)].to_vec();
    for component in target.split('/') {
        match component {
            "" => {
                return Err(KinError::Other(format!(
                    "source symlink has unsafe target {target:?}"
                )))
            }
            "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    return Err(KinError::Other(format!(
                        "source symlink target escapes projection root: {target:?}"
                    )));
                }
            }
            component if is_reserved_source_component(component) => {
                return Err(KinError::Other(format!(
                    "source symlink targets reserved control-plane path {target:?}"
                )))
            }
            component
                if component.len() > 255
                    || enforce_windows_components
                        && !is_safe_windows_source_component(component) =>
            {
                return Err(KinError::Other(format!(
                    "source symlink has unmaterializable target component {component:?}"
                )))
            }
            component => resolved.push(component),
        }
    }
    if resolved
        .iter()
        .any(|component| is_reserved_source_component(component))
    {
        return Err(KinError::Other(format!(
            "source symlink targets reserved control-plane path {target:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, AuthorId, DefaultRefExpectation, DefaultRefMutation, GitObjectId, Hash256,
        RefName, ResolvedArtifact, SharedAdmissionPolicy, WorkspaceExpectation, WorkspaceMutation,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    fn repo_path(path: impl Into<String>) -> RepoPath {
        RepoPath::from_utf8(path).expect("test repository path must be valid")
    }

    fn regular() -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false)
    }

    #[cfg(unix)]
    fn executable() -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes([0x22; 32]), true)
    }

    fn symlink() -> TreeEntry {
        TreeEntry::symlink(Hash256::from_bytes([0x33; 32]))
    }

    fn exact_blob(content: &[u8], executable: bool) -> TreeEntry {
        TreeEntry::blob(kin_blobs::digest(content), executable)
    }

    fn exact_tree(path: &RepoPath, entry: TreeEntry) -> ResolvedTree {
        ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            path.clone(),
            entry,
        )])
        .unwrap()
    }

    fn exact_tree_entries(
        entries: impl IntoIterator<Item = (RepoPath, TreeEntry)>,
    ) -> ResolvedTree {
        ResolvedTree::from_artifacts(
            entries
                .into_iter()
                .map(|(path, entry)| ResolvedArtifact::new(ArtifactId::new(), path, entry)),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn copy_test_directory(source: &Path, destination: &Path) {
        std::fs::create_dir(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                copy_test_directory(&source_path, &destination_path);
            } else if file_type.is_file() {
                std::fs::copy(&source_path, &destination_path).unwrap();
            } else {
                panic!(
                    "authority-copy fixture does not support special member {}",
                    source_path.display()
                );
            }
        }
        std::fs::set_permissions(
            destination,
            std::fs::metadata(source).unwrap().permissions(),
        )
        .unwrap();
    }

    #[test]
    fn local_generation_cas_miss_is_definitely_prepublication() {
        let conflict = kin_db::KinDbError::StorageError(
            "generation mismatch for repo repository: expected 7, found 8 (another writer committed since last load)"
                .to_string(),
        );
        assert!(repository_commit_error_is_definitely_prepublication(
            &conflict
        ));
        assert!(!repository_commit_error_is_definitely_prepublication(
            &kin_db::KinDbError::StorageError("disk synchronization failed".to_string())
        ));
    }

    #[test]
    fn authority_freeze_classifier_preserves_conflict_and_internal_boundaries() {
        let conflict = classify_repository_authority_freeze_error(
            "freeze fixture",
            kin_db::KinDbError::Model(kin_model::ModelError::Conflict(
                "authority moved".to_string(),
            )),
        );
        assert!(matches!(conflict, KinError::RepositoryConflict(_)));

        let replacement = classify_repository_authority_freeze_error(
            "freeze fixture",
            kin_db::KinDbError::StorageError(
                "local storage root changed since this backend opened".to_string(),
            ),
        );
        assert!(matches!(replacement, KinError::Other(_)));
    }

    #[cfg(unix)]
    enum ExistingGitFixture {
        None,
        File,
        Directory,
    }

    #[cfg(unix)]
    struct ExactEjectFixture {
        _outer: tempfile::TempDir,
        root: PathBuf,
        archive: PathBuf,
        stage_parent: PathBuf,
        staged_git: PathBuf,
        displaced_root: PathBuf,
        displaced_archive: PathBuf,
        displaced_stage_parent: PathBuf,
        tree: ResolvedTree,
        blobs: kin_blobs::BlobStore,
    }

    #[cfg(unix)]
    fn exact_eject_fixture(existing_git: ExistingGitFixture) -> ExactEjectFixture {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let stage_parent = outer.path().join("stage-parent");
        let staged_git = stage_parent.join("staged-git");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();
        std::fs::create_dir(&stage_parent).unwrap();
        std::fs::create_dir(&staged_git).unwrap();
        std::fs::write(staged_git.join("stage-marker"), b"prepared Git").unwrap();

        let tracked_path = repo_path("compose.yaml");
        let content = b"services:\n  api:\n    image: scratch\n";
        let tracked_entry = exact_blob(content, false);
        let tree = exact_tree(&tracked_path, tracked_entry);
        materialize_source_tree(&root, [(&tracked_path, tracked_entry, content.as_slice())])
            .unwrap();
        match existing_git {
            ExistingGitFixture::None => {}
            ExistingGitFixture::File => {
                std::fs::write(root.join(".git"), b"gitdir: ../legacy.git\n").unwrap();
            }
            ExistingGitFixture::Directory => {
                std::fs::create_dir(root.join(".git")).unwrap();
                std::fs::write(root.join(".git/legacy-marker"), b"legacy Git").unwrap();
            }
        }
        let blobs =
            kin_blobs::BlobStore::new(outer.path().join("proof-blobs").to_path_buf()).unwrap();
        assert_eq!(
            blobs.write(content).unwrap().as_bytes(),
            tracked_entry.blob_identity().unwrap().as_bytes()
        );

        ExactEjectFixture {
            displaced_root: outer.path().join("repository.displaced"),
            displaced_archive: outer.path().join("archive.displaced"),
            displaced_stage_parent: outer.path().join("stage-parent.displaced"),
            _outer: outer,
            root,
            archive,
            stage_parent,
            staged_git,
            tree,
            blobs,
        }
    }

    #[test]
    fn materialization_rejects_unsafe_source_paths() {
        let root = tempfile::tempdir().unwrap();
        for path in ["", "/absolute", "../escape", "src/../escape"] {
            assert!(
                RepoPath::from_utf8(path).is_err(),
                "invalid repository path was accepted: {path:?}"
            );
        }
        for path in [
            ".kin/config",
            ".KIN/config",
            ".git/config",
            ".GiT/config",
            ".kin-session/base.json",
            "src/.KIN-SESSION/base.json",
            "src\\escape",
        ] {
            let path = repo_path(path);
            let result = materialize_source_entry(root.path(), &path, regular(), b"blocked");
            assert!(result.is_err(), "unsafe path was accepted: {path:?}");
        }
    }

    #[test]
    fn byte_exact_non_utf8_path_fails_at_the_projection_boundary() {
        let path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        let error = validate_source_entry(&path, regular(), b"opaque bytes").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot be projected by this UTF-8 filesystem boundary"),
            "unexpected projection error: {error}"
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn exact_projection_freeze_verifies_a_non_utf8_unix_path() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("assets")).unwrap();
        let mut projected = root.path().join("assets");
        projected.push(std::ffi::OsStr::from_bytes(b"icon-\xff.bin"));
        let content = b"opaque bytes";
        std::fs::write(&projected, content).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());

        let path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
        let verification = freeze
            .verify_resolved_tree(&tree, [(&path, entry, content.as_slice())])
            .unwrap();
        freeze
            .revalidate_resolved_tree(&verification, &tree, [(&path, entry, content.as_slice())])
            .unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exact_projection_host_unrepresentable_path_remains_graph_only_during_detach() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let blobs_directory = outer.path().join("blobs");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();
        drop(ProjectionRoot::open(&root).unwrap());

        let path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        let content = b"opaque graph bytes";
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        let blobs = kin_blobs::BlobStore::new(blobs_directory).unwrap();

        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .expect("a host-unrepresentable path must remain graph-only");
        freeze
            .revalidate_resolved_tree_from_blobs(&verification, &tree, &blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        freeze
            .detach_verified_to_from_blobs(
                &verification,
                &tree,
                &blobs,
                &target,
                std::ffi::OsStr::new("kin"),
            )
            .unwrap();

        assert!(!root.join(".kin").exists());
        assert!(archive.join("kin/reconciliation/projection.lock").is_file());
        assert!(
            blobs.read(&kin_blobs::digest(content)).is_err(),
            "workspace proof must not require a physical CAS body for a host-unrepresentable path"
        );
    }

    #[test]
    fn gitlink_fails_loud_instead_of_becoming_a_blob() {
        let path = repo_path("vendor/runtime");
        let error = validate_source_entry(
            &path,
            TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])),
            b"",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repository history, not a repository-owned source blob"),
            "unexpected gitlink projection error: {error}"
        );
    }

    #[test]
    fn repository_projection_covers_materializable_entries_and_preserves_gitlinks() {
        let source_path = repo_path("compose.yaml");
        let source_body = b"services: {}\n";
        let source_entry = exact_blob(source_body, false);
        let gitlink_path = repo_path("vendor/runtime");
        let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x44; 20]));
        let source_artifact =
            ResolvedArtifact::new(ArtifactId::new(), source_path.clone(), source_entry);
        let gitlink_artifact =
            ResolvedArtifact::new(ArtifactId::new(), gitlink_path, gitlink_entry);
        let tree = ResolvedTree::from_artifacts([source_artifact, gitlink_artifact]).unwrap();
        let entries =
            validated_source_entries([(&source_path, source_entry, source_body.as_slice())])
                .unwrap();

        validate_unchanged_graph_only_entries(&tree, &tree).unwrap();
        validate_repository_projection_entries_match_tree("target", &tree, &entries).unwrap();
    }

    #[test]
    fn repository_projection_rejects_gitlink_transition_before_namespace_mutation() {
        let path = repo_path("vendor/runtime");
        let artifact_id = ArtifactId::new();
        let previous = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            path.clone(),
            TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])),
        )])
        .unwrap();
        let target = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            path,
            TreeEntry::gitlink(GitObjectId::sha1([0x55; 20])),
        )])
        .unwrap();

        let error = validate_unchanged_graph_only_entries(&previous, &target).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("dedicated graph-native operation"),
            "unexpected graph-only transition error: {error}"
        );
    }

    #[test]
    fn repository_workspace_transition_binds_the_supplied_prior_tree_hash() {
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let manager = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let workspace = lease.metadata().workspaces.first().unwrap().clone();
        drop(lease);
        assert!(workspace.tree.is_empty());

        let path = repo_path("compose.yaml");
        let body = b"services: {}\n";
        let target_entry = exact_blob(body, false);
        let target_tree = exact_tree(&path, target_entry);
        let target_hash = compute_resolved_tree_hash(&target_tree).unwrap();
        let target_entries =
            validated_source_entries([(&path, target_entry, body.as_slice())]).unwrap();
        let previous_entries: Vec<ValidatedSourceEntry<'_>> = Vec::new();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: initialized.repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("prior-tree-binding-test"),
            reason: "reject mismatched prior workspace tree".to_string(),
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
                    tree_hash: target_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head,
                new_base_target: workspace.base_target,
                new_base_tree_hash: Some(target_hash),
                tree_deltas: crate::exact_tree_correction(&workspace.tree, &target_tree).unwrap(),
                new_tree_hash: target_hash,
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: SharedAdmissionPolicy::empty(0),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };

        let error = validate_repository_projection_transaction(
            &workspace.tree,
            &target_tree,
            &previous_entries,
            &target_entries,
            &transaction,
            GraphOnlyTransitionPolicy::AllowExactMetadataTransition,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("expects prior tree"),
            "unexpected prior-tree binding error: {error}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_workspace_transition_allows_exact_gitlink_add_retarget_and_remove() {
        let root = tempfile::tempdir().unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());
        let path = repo_path("vendor/runtime");
        let first = exact_tree(&path, TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])));
        let second = exact_tree(&path, TreeEntry::gitlink(GitObjectId::sha1([0x55; 20])));
        let empty = ResolvedTree::default();
        let no_entries: Vec<ValidatedSourceEntry<'_>> = Vec::new();

        for (previous, target) in [(&empty, &first), (&first, &second), (&second, &empty)] {
            let result = project_reconciled_source_tree_and_commit(
                root.path(),
                &no_entries,
                &no_entries,
                &should_preserve_checkout_path,
                ReconciledProjectionOptions {
                    open_mode: ProjectionOpenMode::ExistingFrozen,
                    graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                        previous_tree: previous,
                        target_tree: target,
                        scope: None,
                    }),
                    checkout_scope: None,
                    checkout_projection_authority: None,
                    checkout_projection_freeze: None,
                },
                || {},
                || {},
                || {},
                None,
                None,
                || ProjectionAuthorityCommit::Committed(()),
            )
            .unwrap();
            assert_eq!(result, (0, ()));
            assert!(
                !root.path().join("vendor/runtime").exists(),
                "graph-only transitions must not invent a Gitlink body or directory"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_workspace_transition_retains_gitlink_directory_without_traversing_it() {
        let root = tempfile::tempdir().unwrap();
        let dependency = root.path().join("vendor/runtime");
        std::fs::create_dir_all(dependency.join("nested")).unwrap();
        std::fs::write(dependency.join("nested/owned.bin"), [0_u8, 0xff, 0x44]).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());
        let path = repo_path("vendor/runtime");
        let first = exact_tree(&path, TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])));
        let second = exact_tree(&path, TreeEntry::gitlink(GitObjectId::sha1([0x55; 20])));
        let empty = ResolvedTree::default();
        let no_entries: Vec<ValidatedSourceEntry<'_>> = Vec::new();

        for (previous, target) in [(&first, &second), (&second, &empty)] {
            project_reconciled_source_tree_and_commit(
                root.path(),
                &no_entries,
                &no_entries,
                &should_preserve_checkout_path,
                ReconciledProjectionOptions {
                    open_mode: ProjectionOpenMode::ExistingFrozen,
                    graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                        previous_tree: previous,
                        target_tree: target,
                        scope: None,
                    }),
                    checkout_scope: None,
                    checkout_projection_authority: None,
                    checkout_projection_freeze: None,
                },
                || {},
                || {},
                || {},
                None,
                None,
                || ProjectionAuthorityCommit::Committed(()),
            )
            .unwrap();
            assert_eq!(
                std::fs::read(dependency.join("nested/owned.bin")).unwrap(),
                [0_u8, 0xff, 0x44]
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_workspace_transition_rejects_gitlink_race_before_mutation() {
        use std::cell::Cell;

        let root = tempfile::tempdir().unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());
        let path = repo_path("vendor/runtime");
        let target = exact_tree(&path, TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])));
        let empty = ResolvedTree::default();
        let no_entries: Vec<ValidatedSourceEntry<'_>> = Vec::new();
        let committed = Cell::new(false);

        let error = project_reconciled_source_tree_and_commit(
            root.path(),
            &no_entries,
            &no_entries,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions {
                open_mode: ProjectionOpenMode::ExistingFrozen,
                graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                    previous_tree: &empty,
                    target_tree: &target,
                    scope: None,
                }),
                checkout_scope: None,
                checkout_projection_authority: None,
                checkout_projection_freeze: None,
            },
            || {
                std::fs::create_dir(root.path().join("vendor")).unwrap();
                std::fs::write(root.path().join("vendor/runtime"), b"raced object").unwrap();
            },
            || {},
            || {},
            None,
            None,
            || {
                committed.set(true);
                ProjectionAuthorityCommit::Committed(())
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("neither absent nor a no-follow real directory"),
            "unexpected Gitlink race error: {error}"
        );
        assert!(!committed.get(), "authority commit ran after Gitlink race");
        assert_eq!(
            std::fs::read(root.path().join("vendor/runtime")).unwrap(),
            b"raced object"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn graph_only_boundary_directory_must_be_created_without_replacement() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let gitlink_path = repo_path("vendor/runtime");
        let previous = exact_tree(
            &gitlink_path,
            TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])),
        );
        let target_path = repo_path("vendor/runtime/src/lib.rs");
        let target = exact_tree(&target_path, exact_blob(b"target\n", false));
        let verification =
            GraphOnlyWorkspaceTransitionVerification::verify(&projection, &previous, &target, None)
                .unwrap();
        assert!(verification
            .must_create_directories
            .contains(Path::new("vendor/runtime")));
        verification
            .revalidate_before_mutation(&projection)
            .unwrap();

        std::fs::create_dir_all(root.path().join("vendor/runtime")).unwrap();
        std::fs::write(root.path().join("vendor/runtime/foreign.bin"), b"foreign").unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let mut created = Vec::new();
        let error = projection
            .prepare_without_replacement_transactional(
                &mut transaction,
                &[&target_path],
                &mut created,
                &verification.must_create_directories,
            )
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("expected-absent graph-only boundary"),
            "unexpected no-replace error: {error}"
        );
        assert_eq!(
            std::fs::read(root.path().join("vendor/runtime/foreign.bin")).unwrap(),
            b"foreign"
        );
        projection
            .cleanup_reconciliation_transaction(transaction)
            .unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn graph_only_boundary_rollback_never_deletes_injected_foreign_content() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let gitlink_path = repo_path("vendor/runtime");
        let previous = exact_tree(
            &gitlink_path,
            TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])),
        );
        let target_path = repo_path("vendor/runtime/src/lib.rs");
        let target = exact_tree(&target_path, exact_blob(b"target\n", false));
        let verification =
            GraphOnlyWorkspaceTransitionVerification::verify(&projection, &previous, &target, None)
                .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        let mut created = Vec::new();
        projection
            .prepare_without_replacement_transactional(
                &mut transaction,
                &[&target_path],
                &mut created,
                &verification.must_create_directories,
            )
            .unwrap();
        std::fs::write(root.path().join("vendor/runtime/foreign.bin"), b"foreign").unwrap();

        let error = projection
            .rollback_reconciliation_manifest(&transaction)
            .unwrap_err();
        assert!(
            error.to_string().contains("unexpected object"),
            "unexpected rollback error: {error}"
        );
        assert_eq!(
            std::fs::read(root.path().join("vendor/runtime/foreign.bin")).unwrap(),
            b"foreign"
        );
        assert!(
            transaction_path.is_dir(),
            "failed safe rollback must retain its authenticated WAL"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn non_utf8_repository_path_is_graph_only_when_macos_cannot_materialize_it() {
        let path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        assert_eq!(
            source_projection_disposition(&path, regular()).unwrap(),
            SourceProjectionDisposition::GraphOnlyHostUnrepresentable
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn non_utf8_gitlink_uses_host_unrepresentable_absence_proof() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let path = RepoPath::from_bytes(b"vendor/runtime-\xff".to_vec()).unwrap();
        let disposition =
            source_projection_disposition(&path, TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])))
                .unwrap();
        assert_eq!(disposition, SourceProjectionDisposition::GraphOnlyGitlink);

        let proof = projection
            .verify_frozen_graph_only(&path, disposition)
            .unwrap();
        assert!(matches!(
            proof,
            ExactProjectionEntryProof::HostUnrepresentableAbsent
        ));
        projection
            .revalidate_frozen_graph_only(&path, disposition, &proof)
            .unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authority_owned_session_creates_runs_then_stages_and_publishes() {
        let repository = tempfile::tempdir().unwrap();
        let initialized = crate::init(repository.path()).unwrap();
        std::fs::remove_dir(initialized.layout.runs_dir()).unwrap();
        let path = repo_path("compose.yaml");
        let body = b"services: {}\n";
        let entry = TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest_bytes(body)), false);
        let freeze =
            ExactProjectionFreeze::acquire_existing(initialized.layout.working_dir()).unwrap();

        let (session, count) = freeze
            .materialize_session_source_tree(
                "session-capability",
                br#"{"schema":1}"#,
                [(&path, entry, body.as_slice())],
            )
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(
            session.root(),
            initialized.layout.runs_dir().join("session-capability")
        );
        assert_eq!(
            std::fs::read(session.root().join("compose.yaml")).unwrap(),
            body
        );
        assert!(
            std::fs::read_dir(initialized.layout.runs_dir())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(SESSION_STAGING_DIRECTORY_PREFIX)),
            "successful publication must not leave a staging child"
        );
        session.revalidate().unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authority_owned_session_rejects_a_replaced_runs_directory_before_mutation() {
        let repository = tempfile::tempdir().unwrap();
        let initialized = crate::init(repository.path()).unwrap();
        let path = repo_path("compose.yaml");
        let body = b"services: {}\n";
        let entry = TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest_bytes(body)), false);
        let entries =
            validated_session_source_entries(br#"{"schema":1}"#, [(&path, entry, body.as_slice())])
                .unwrap();
        let runs = initialized.layout.runs_dir();
        let displaced = initialized.layout.root().join("runs-displaced");
        let freeze =
            ExactProjectionFreeze::acquire_existing(initialized.layout.working_dir()).unwrap();

        let error = freeze
            .materialize_validated_session_source_tree(
                "session-raced",
                br#"{"schema":1}"#,
                &entries,
                || {
                    std::fs::rename(&runs, &displaced).unwrap();
                    std::fs::create_dir(&runs).unwrap();
                },
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("session root") && error.to_string().contains("replaced"),
            "unexpected replaced-runs error: {error}"
        );
        assert!(!runs.join("session-raced").exists());
        assert!(!displaced.join("session-raced").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authority_owned_session_refuses_an_existing_final_child_without_reuse() {
        let repository = tempfile::tempdir().unwrap();
        let initialized = crate::init(repository.path()).unwrap();
        let existing = initialized.layout.runs_dir().join("session-existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("owner-marker"), b"pre-existing").unwrap();
        let path = repo_path("compose.yaml");
        let body = b"services: {}\n";
        let entry = TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest_bytes(body)), false);
        let freeze =
            ExactProjectionFreeze::acquire_existing(initialized.layout.working_dir()).unwrap();

        let error = freeze
            .materialize_session_source_tree(
                "session-existing",
                br#"{"schema":1}"#,
                [(&path, entry, body.as_slice())],
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("already exists")
                && error.to_string().contains("never reuses"),
            "unexpected existing-session error: {error}"
        );
        assert_eq!(
            std::fs::read(existing.join("owner-marker")).unwrap(),
            b"pre-existing"
        );
        assert!(!existing.join("compose.yaml").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn blocked_session_writer_rejects_a_replaced_repository_epoch() {
        let repository = tempfile::tempdir().unwrap();
        let initialized = crate::init(repository.path()).unwrap();
        let working_dir = initialized.layout.working_dir().to_path_buf();
        let detached_kin = working_dir.join(".kin-detached");
        let freeze = ExactProjectionFreeze::acquire_existing(&working_dir).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let worker_root = working_dir.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let path = repo_path("compose.yaml");
            let body = b"services: {}\n";
            let entry = TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest_bytes(body)), false);
            let result = ExactProjectionFreeze::acquire_existing(&worker_root).and_then(|freeze| {
                freeze
                    .materialize_session_source_tree(
                        "session-stale",
                        br#"{"schema":1}"#,
                        [(&path, entry, body.as_slice())],
                    )
                    .map(|_| ())
            });
            finished_tx.send(()).unwrap();
            result
        });

        started_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "writer unexpectedly escaped the held repository projection lock"
        );
        std::fs::rename(initialized.layout.root(), &detached_kin).unwrap();
        let replacement = crate::init(&working_dir).unwrap();
        drop(freeze);

        let error = worker
            .join()
            .unwrap()
            .expect_err("writer blocked on the detached epoch must fail closed");
        assert!(
            error.to_string().contains("replaced")
                || error.to_string().contains("changed identity")
                || error.to_string().contains("unavailable"),
            "unexpected stale-epoch error: {error}"
        );
        assert!(!detached_kin.join("runs/session-stale").exists());
        assert!(!replacement.layout.runs_dir().join("session-stale").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn session_projection_keeps_repository_discovery_control_separate() {
        let root = tempfile::tempdir().unwrap();
        let compose = repo_path("compose.yaml");
        let executable = repo_path("bin/run");
        let metadata = br#"{"schema":1,"tree":"exact"}"#;
        let compose_body = b"services:\n  app:\n    image: kin\n";
        let executable_body = b"#!/bin/sh\nexit 0\n";

        let count = materialize_session_source_tree(
            root.path(),
            metadata,
            [
                (
                    &compose,
                    TreeEntry::blob(
                        Hash256::from_bytes(kin_blobs::digest_bytes(compose_body)),
                        false,
                    ),
                    compose_body.as_slice(),
                ),
                (
                    &executable,
                    TreeEntry::blob(
                        Hash256::from_bytes(kin_blobs::digest_bytes(executable_body)),
                        true,
                    ),
                    executable_body.as_slice(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  app:\n    image: kin\n"
        );
        assert_eq!(
            std::fs::read(root.path().join(".kin-session/base.json")).unwrap(),
            metadata
        );
        assert!(root.path().join(".kin-session/reconciliation").is_dir());
        assert!(
            !root.path().join(".kin").exists(),
            "a session projection must not shadow owning-repository discovery"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_ne!(
                std::fs::metadata(root.path().join("bin/run"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn session_projection_preserves_symbolic_link_identity() {
        let root = tempfile::tempdir().unwrap();
        let target = repo_path("config/app.toml");
        let link = repo_path("current-config");
        let target_body = b"enabled = true\n";
        let link_body = b"config/app.toml";

        materialize_session_source_tree(
            root.path(),
            br#"{"schema":1}"#,
            [
                (
                    &target,
                    TreeEntry::blob(
                        Hash256::from_bytes(kin_blobs::digest_bytes(target_body)),
                        false,
                    ),
                    target_body.as_slice(),
                ),
                (
                    &link,
                    TreeEntry::symlink(Hash256::from_bytes(kin_blobs::digest_bytes(link_body))),
                    link_body.as_slice(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            std::fs::read_link(root.path().join("current-config")).unwrap(),
            PathBuf::from("config/app.toml")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn session_projection_rejects_mislabeled_source_bytes_before_mutation() {
        let root = tempfile::tempdir().unwrap();
        let path = repo_path("compose.yaml");
        let error = materialize_session_source_tree(
            root.path(),
            br#"{"schema":1}"#,
            [(
                &path,
                TreeEntry::blob(Hash256::from_bytes([0x61; 32]), false),
                b"services: {}\n".as_slice(),
            )],
        )
        .unwrap_err();

        assert!(error.to_string().contains("not tree identity"), "{error}");
        assert!(
            !root.path().join(".kin-session").exists(),
            "hash mismatch must fail before creating session control state"
        );
        assert!(
            !root.path().join("compose.yaml").exists(),
            "hash mismatch must fail before materializing source bytes"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn session_projection_preserves_casefolded_control_aliases() {
        let root = tempfile::tempdir().unwrap();
        let alias = root.path().join(".KIN-SESSION");
        std::fs::create_dir(&alias).unwrap();
        std::fs::write(alias.join("keep"), b"control alias").unwrap();
        let path = repo_path("compose.yaml");
        let body = b"services: {}\n";

        materialize_session_source_tree(
            root.path(),
            br#"{"schema":1}"#,
            [(
                &path,
                TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest_bytes(body)), false),
                body.as_slice(),
            )],
        )
        .unwrap();

        assert_eq!(
            std::fs::read(alias.join("keep")).unwrap(),
            b"control alias",
            "control aliases must never be planned as unrelated removable content"
        );
    }

    #[test]
    fn unicode_case_aliases_cannot_target_reserved_control_plane_paths() {
        for component in [".g\u{131}t", ".\u{212a}in", ".\u{212a}in-session"] {
            assert!(
                is_reserved_source_component(component),
                "Unicode alias of a reserved component was accepted: {component:?}"
            );
        }
    }

    #[test]
    fn portable_source_paths_reject_windows_names_and_cross_platform_aliases() {
        for path in [
            "NUL",
            "src/COM1.rs",
            "src/trailing.",
            "src/alternate:stream",
        ] {
            assert!(
                validate_portable_source_paths(std::iter::once(path)).is_err(),
                "unportable path was accepted: {path:?}"
            );
        }
        for paths in [
            ["src/Foo.rs", "src/foo.rs"],
            ["src/caf\u{e9}.rs", "src/cafe\u{301}.rs"],
        ] {
            assert!(
                validate_portable_source_paths(paths).is_err(),
                "cross-platform aliases were accepted: {paths:?}"
            );
        }
    }

    #[test]
    fn windows_source_component_validation_rejects_aliasing_names() {
        for component in [
            "CON",
            "con.txt",
            "PRN",
            "AUX.log",
            "NUL",
            "NUL .log",
            "COM0",
            "COM0.rs",
            "COM1.rs",
            "COM1 .txt",
            "com9",
            "COM¹",
            "com².rs",
            "COM³ .txt",
            "LPT0",
            "LPT1",
            "lpt9.txt",
            "LPT¹",
            "lpt².rs",
            "LPT³ .txt",
            "CONIN$",
            "CONOUT$",
            "alternate:stream",
            "trailing.",
            "trailing ",
            "wild*card",
            "question?mark",
        ] {
            assert!(
                !is_safe_windows_source_component(component),
                "unsafe Windows component was accepted: {component:?}"
            );
        }
        for component in [
            "console.rs",
            "com10",
            "lpt10",
            "normal.name",
            "space inside",
        ] {
            assert!(
                is_safe_windows_source_component(component),
                "ordinary Windows component was rejected: {component:?}"
            );
        }
    }

    #[test]
    fn windows_symlink_target_components_reject_unmaterializable_names() {
        let link_path = ["dir", "link"];
        let overlong = "x".repeat(256);
        for target in [
            "CON/file".to_string(),
            "nested/aux.txt".to_string(),
            "alternate:stream".to_string(),
            "trailing.".to_string(),
            "wild*card".to_string(),
            overlong,
        ] {
            let error =
                validate_source_symlink_target_with_windows_rules(&link_path, &target, true)
                    .expect_err("Windows-invalid link target component must fail preflight");
            assert!(
                error
                    .to_string()
                    .contains("unmaterializable target component"),
                "unexpected error for {target:?}: {error}"
            );
        }

        validate_source_symlink_target_with_windows_rules(
            &link_path,
            "../ordinary/target.rs",
            true,
        )
        .expect("ordinary relative target should remain valid");
    }

    #[cfg(windows)]
    #[test]
    fn windows_symlink_entry_validates_target_before_reporting_unsupported_publication() {
        let error =
            validate_source_entry(&repo_path("dir/link".to_string()), symlink(), b"CON/file")
                .expect_err("Windows-invalid target must fail before publication");

        assert!(error
            .to_string()
            .contains("unmaterializable target component"));
    }

    #[test]
    fn materialization_rejects_escaping_or_reserved_symlink_targets() {
        let root = tempfile::tempdir().unwrap();
        for target in [
            "../../escape",
            "/absolute",
            ".kin/config",
            "../.git/config",
            "../.kin-session/base.json",
        ] {
            let result = materialize_source_entry(
                root.path(),
                &repo_path("dir/link".to_string()),
                symlink(),
                target.as_bytes(),
            );
            assert!(
                result.is_err(),
                "unsafe link target was accepted: {target:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn reserved_control_plane_path_fails_before_destructive_transition() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a-parent"), b"old complete bytes").unwrap();
        let transition = repo_path("a-parent/child.txt".to_string());
        let reserved = repo_path("z/.KIN-SESSION/base.json".to_string());

        let error = replace_source_tree(
            root.path(),
            [
                (&transition, regular(), b"new child".as_slice()),
                (&reserved, regular(), b"forbidden".as_slice()),
            ],
            |_| false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsafe graph-owned source path"));
        assert_eq!(
            std::fs::read(root.path().join("a-parent")).unwrap(),
            b"old complete bytes"
        );
        assert!(!root.path().join("a-parent/child.txt").exists());
        assert!(!root.path().join("z").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn overlong_component_fails_before_destructive_transition() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a-parent"), b"old complete bytes").unwrap();
        let transition = repo_path("a-parent/child.txt".to_string());
        let overlong = repo_path(format!("z/{}", "x".repeat(256)));

        let error = replace_source_tree(
            root.path(),
            [
                (&transition, regular(), b"new child".as_slice()),
                (&overlong, regular(), b"forbidden".as_slice()),
            ],
            |_| false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsafe graph-owned source path"));
        assert_eq!(
            std::fs::read(root.path().join("a-parent")).unwrap(),
            b"old complete bytes"
        );
        assert!(!root.path().join("a-parent/child.txt").exists());
        assert!(!root.path().join("z").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn targeted_reconciliation_rejects_untracked_collision_before_removal() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("old-tracked.rs"), b"old tracked bytes").unwrap();
        std::fs::write(root.path().join("new-target.rs"), b"untracked user bytes").unwrap();
        let old = repo_path("old-tracked.rs".to_string());
        let target = repo_path("new-target.rs".to_string());

        let error = reconcile_source_tree(
            root.path(),
            [(&old, regular(), b"old tracked bytes".as_slice())],
            [(&target, regular(), b"target bytes".as_slice())],
            should_preserve_checkout_path,
        )
        .unwrap_err();

        assert!(error.to_string().contains("untracked working-copy path"));
        assert_eq!(
            std::fs::read(root.path().join("old-tracked.rs")).unwrap(),
            b"old tracked bytes"
        );
        assert_eq!(
            std::fs::read(root.path().join("new-target.rs")).unwrap(),
            b"untracked user bytes"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_commit_failure_rolls_projection_back_exactly() {
        let root = tempfile::tempdir().unwrap();
        let owned = repo_path("compose.yaml");
        std::fs::write(root.path().join("compose.yaml"), b"services:\n  old: {}\n").unwrap();
        let previous =
            validated_source_entries([(&owned, regular(), b"services:\n  old: {}\n".as_slice())])
                .unwrap();
        let target = validated_source_entries([(
            &owned,
            regular(),
            b"services:\n  target: {}\n".as_slice(),
        )])
        .unwrap();

        let error = project_reconciled_source_tree_and_commit(
            root.path(),
            &previous,
            &target,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions::default(),
            || {},
            || {},
            || {},
            None,
            None,
            || {
                ProjectionAuthorityCommit::<()>::DefinitelyNotCommitted(KinError::Other(
                    "injected repository authority conflict".to_string(),
                ))
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected repository authority conflict"));
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  old: {}\n"
        );
        assert!(std::fs::read_dir(root.path().join(".kin/reconciliation"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("tx-")));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_projection_tamper_after_publication_fails_before_authority_commit() {
        use std::cell::Cell;

        let root = tempfile::tempdir().unwrap();
        let path = repo_path("compose.yaml");
        let previous_body = b"services:\n  old: {}\n";
        let target_body = b"services:\n  target: {}\n";
        let previous_entry = exact_blob(previous_body, false);
        let target_entry = exact_blob(target_body, false);
        std::fs::write(root.path().join("compose.yaml"), previous_body).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());
        let previous_tree = exact_tree(&path, previous_entry);
        let target_tree = exact_tree(&path, target_entry);
        let previous =
            validated_source_entries([(&path, previous_entry, previous_body.as_slice())]).unwrap();
        let target =
            validated_source_entries([(&path, target_entry, target_body.as_slice())]).unwrap();
        let marker = ReconciliationAuthorityCommit {
            repository_id: RepositoryId::new("repository-projection-tamper").unwrap(),
            operation_id: OperationId::new(),
            transaction_hash: Hash256::from_bytes([0x77; 32]),
        };
        let committed = Cell::new(false);

        let error = project_reconciled_source_tree_and_commit(
            root.path(),
            &previous,
            &target,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions {
                open_mode: ProjectionOpenMode::ExistingFrozen,
                graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                    previous_tree: &previous_tree,
                    target_tree: &target_tree,
                    scope: None,
                }),
                checkout_scope: None,
                checkout_projection_authority: None,
                checkout_projection_freeze: None,
            },
            || {},
            || {},
            || {
                std::fs::write(root.path().join("compose.yaml"), b"raced target bytes\n").unwrap();
            },
            Some(marker),
            None,
            || {
                committed.set(true);
                ProjectionAuthorityCommit::Committed(())
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("differs from prior workspace source")
                || error.to_string().contains("retained recovery transaction"),
            "unexpected post-publication tamper error: {error}"
        );
        assert!(
            !committed.get(),
            "authority commit ran after target projection tamper"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn indeterminate_repository_commit_retains_projection_and_authenticated_wal() {
        let root = tempfile::tempdir().unwrap();
        let path = repo_path("compose.yaml");
        let previous_body = b"services:\n  old: {}\n";
        let target_body = b"services:\n  target: {}\n";
        let previous_entry = exact_blob(previous_body, false);
        let target_entry = exact_blob(target_body, false);
        std::fs::write(root.path().join("compose.yaml"), previous_body).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());
        let previous_tree = exact_tree(&path, previous_entry);
        let target_tree = exact_tree(&path, target_entry);
        let previous =
            validated_source_entries([(&path, previous_entry, previous_body.as_slice())]).unwrap();
        let target =
            validated_source_entries([(&path, target_entry, target_body.as_slice())]).unwrap();
        let marker = ReconciliationAuthorityCommit {
            repository_id: RepositoryId::new("repository-projection-uncertain").unwrap(),
            operation_id: OperationId::new(),
            transaction_hash: Hash256::from_bytes([0x88; 32]),
        };

        let error = project_reconciled_source_tree_and_commit(
            root.path(),
            &previous,
            &target,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions {
                open_mode: ProjectionOpenMode::ExistingFrozen,
                graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                    previous_tree: &previous_tree,
                    target_tree: &target_tree,
                    scope: None,
                }),
                checkout_scope: None,
                checkout_projection_authority: None,
                checkout_projection_freeze: None,
            },
            || {},
            || {},
            || {},
            Some(marker),
            None,
            || {
                ProjectionAuthorityCommit::<()>::Indeterminate(KinError::Other(
                    "injected indeterminate authority outcome".to_string(),
                ))
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected indeterminate authority outcome"));
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            target_body
        );
        assert!(
            std::fs::read_dir(root.path().join(".kin/reconciliation"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("tx-")),
            "uncertain authority outcome must retain its authenticated recovery WAL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_transition_recovery_rejects_identical_replacement_authority_root() {
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let canonical_kindb = initialized.layout.kindb_dir();
        let detached_kindb = root.path().join("detached-kindb");
        let replacement_kindb = root.path().join("replacement-kindb");
        let retained = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(&canonical_kindb)),
        )
        .unwrap();
        let lease = retained.read_authority();
        let roots_before = lease.roots().clone();
        let default_ref = lease.metadata().ref_state.default_ref.clone().unwrap();
        drop(lease);
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: initialized.repository_id.clone(),
            expected_generation: roots_before.generation,
            expected_roots: roots_before.clone(),
            actor: AuthorId::new("retained-recovery-root-test"),
            reason: "discriminate retained authority during WAL recovery".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustEqual { name: default_ref },
                new_default: Some(RefName::branch(b"replacement-only").unwrap()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let marker = ReconciliationAuthorityCommit {
            repository_id: transaction.repository_id.clone(),
            operation_id: transaction.operation_id,
            transaction_hash: transaction.transaction_hash().unwrap(),
        };
        let path = repo_path("compose.yaml");
        let previous_body = b"services:\n  old: {}\n";
        let target_body = b"services:\n  replacement-only: {}\n";
        std::fs::write(root.path().join("compose.yaml"), previous_body).unwrap();
        let previous =
            validated_source_entries([(&path, regular(), previous_body.as_slice())]).unwrap();
        let target =
            validated_source_entries([(&path, regular(), target_body.as_slice())]).unwrap();

        let error = project_reconciled_source_tree_and_commit(
            root.path(),
            &previous,
            &target,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions::default(),
            || {},
            || {},
            || {},
            Some(marker),
            None,
            || {
                ProjectionAuthorityCommit::<()>::Indeterminate(KinError::Other(
                    "retain authenticated WAL for replacement-root test".to_string(),
                ))
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("retain authenticated WAL for replacement-root test"));
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            target_body
        );

        copy_test_directory(&canonical_kindb, &replacement_kindb);
        let replacement = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(&replacement_kindb)),
        )
        .unwrap();
        let replacement_receipt = replacement
            .commit_repository_transaction(transaction.clone())
            .unwrap();
        drop(replacement);
        std::fs::rename(&canonical_kindb, &detached_kindb).unwrap();
        std::fs::rename(&replacement_kindb, &canonical_kindb).unwrap();

        let recovery_error = ExactProjectionFreeze::acquire_existing_for_repository_transition(
            root.path(),
            &retained,
        )
        .unwrap_err();
        let target_after_rejection = std::fs::read(root.path().join("compose.yaml")).unwrap();
        let wal_retained = std::fs::read_dir(root.path().join(".kin/reconciliation"))
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("tx-")
            });
        let detached = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(&detached_kindb)),
        )
        .unwrap();
        let detached_roots = detached.read_authority().roots().clone();
        let installed = RepositoryAuthorityManager::open(
            initialized.repository_id,
            Arc::new(LocalFileBackend::new(&canonical_kindb)),
        )
        .unwrap();
        let installed_roots = installed.read_authority().roots().clone();
        drop(installed);
        drop(detached);
        std::fs::rename(&canonical_kindb, &replacement_kindb).unwrap();
        std::fs::rename(&detached_kindb, &canonical_kindb).unwrap();

        assert!(
            recovery_error
                .to_string()
                .contains("changed since this backend opened"),
            "{recovery_error}"
        );
        assert_eq!(target_after_rejection, target_body);
        assert!(
            wal_retained,
            "rejected recovery must leave the WAL untouched"
        );
        assert_eq!(detached_roots, roots_before);
        assert_eq!(installed_roots, replacement_receipt.roots_after);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn replay_recovers_committed_projection_in_projection_then_authority_order() {
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let manager = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let default_ref = lease.metadata().ref_state.default_ref.clone().unwrap();
        drop(lease);
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: initialized.repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("projection-crash-test"),
            reason: "commit exact projection recovery fixture".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustEqual { name: default_ref },
                new_default: Some(RefName::branch(b"alternate").unwrap()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let marker = ReconciliationAuthorityCommit {
            repository_id: transaction.repository_id.clone(),
            operation_id: transaction.operation_id,
            transaction_hash: transaction.transaction_hash().unwrap(),
        };
        let replay_transaction = transaction.clone();
        let owned = repo_path("compose.yaml");
        std::fs::write(root.path().join("compose.yaml"), b"services:\n  old: {}\n").unwrap();
        let previous =
            validated_source_entries([(&owned, regular(), b"services:\n  old: {}\n".as_slice())])
                .unwrap();
        let target = validated_source_entries([(
            &owned,
            regular(),
            b"services:\n  target: {}\n".as_slice(),
        )])
        .unwrap();

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(usize, ())> = project_reconciled_source_tree_and_commit(
                root.path(),
                &previous,
                &target,
                &should_preserve_checkout_path,
                ReconciledProjectionOptions::default(),
                || {},
                || {},
                || {},
                Some(marker),
                None,
                || {
                    manager.commit_repository_transaction(transaction).unwrap();
                    panic!("simulated process crash after authority commit");
                },
            );
        }));
        assert!(crashed.is_err());
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  target: {}\n"
        );
        assert!(std::fs::read_dir(root.path().join(".kin/reconciliation"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("tx-")));

        let acquisition_order = std::cell::RefCell::new(Vec::new());
        let (receipt, authority_freeze) =
            replay_repository_workspace_transaction_and_recover_projection_with_hooks(
                root.path(),
                &manager,
                replay_transaction,
                || acquisition_order.borrow_mut().push("projection"),
                || acquisition_order.borrow_mut().push("authority"),
            )
            .unwrap();
        assert_eq!(acquisition_order.into_inner(), ["projection", "authority"]);
        assert!(matches!(
            receipt.outcome,
            RepositoryCommitOutcome::IdempotentReplay
        ));
        assert_eq!(authority_freeze.roots(), &receipt.roots_after);

        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  target: {}\n"
        );
        assert!(std::fs::read_dir(root.path().join(".kin/reconciliation"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("tx-")));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_workspace_transition_returns_freeze_that_blocks_competing_writer() {
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let manager = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let workspace = lease.metadata().workspaces.first().unwrap().clone();
        drop(lease);
        assert!(workspace.tree.is_empty());

        let path = repo_path("compose.yaml");
        let body = b"services:\n  api:\n    image: scratch\n";
        let entry = exact_blob(body, false);
        let target_tree = exact_tree(&path, entry);
        let target_hash = compute_resolved_tree_hash(&target_tree).unwrap();
        manager
            .save_source_blob(entry.blob_identity().unwrap(), body)
            .unwrap();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: initialized.repository_id.clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("workspace-transition-freeze-test"),
            reason: "install exact workspace tree while retaining authority".to_string(),
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
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head.clone(),
                new_base_target: workspace.base_target.clone(),
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: crate::exact_tree_correction(&workspace.tree, &target_tree).unwrap(),
                new_tree_hash: target_hash,
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let competing_transaction = RepositoryTransaction {
            operation_id: OperationId::new(),
            actor: AuthorId::new("competing-workspace-writer"),
            reason: "compete with retained workspace transition authority".to_string(),
            ..transaction.clone()
        };
        let competing = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();

        let (materialized, receipt, authority_freeze) =
            transition_repository_workspace_tree_and_commit_repository_transaction(
                root.path(),
                &workspace.tree,
                &target_tree,
                &manager,
                transaction,
            )
            .unwrap();
        assert_eq!(materialized, 1);
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            body
        );
        assert_eq!(authority_freeze.roots(), &receipt.roots_after);
        assert_eq!(authority_freeze.authority().roots(), &receipt.roots_after);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(competing.commit_repository_transaction(competing_transaction))
                .unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "a competing repository writer must remain blocked while the returned freeze lives"
        );

        drop(authority_freeze);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("the competing writer must resume after the transition freeze is dropped")
            .expect_err("the stale competing writer must lose the successor compare-and-swap");
        writer.join().unwrap();

        let reopened = RepositoryAuthorityManager::open(
            initialized.repository_id,
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        assert_eq!(reopened.read_authority().roots(), &receipt.roots_after);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn targeted_reconciliation_removes_clean_tracked_generated_path_only() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("target/debug")).unwrap();
        std::fs::write(root.path().join("target/tracked.bin"), b"graph-owned bytes").unwrap();
        std::fs::write(
            root.path().join("target/debug/untracked-cache"),
            b"generated bytes",
        )
        .unwrap();
        let old = repo_path("target/tracked.bin".to_string());

        reconcile_source_tree(
            root.path(),
            [(&old, regular(), b"graph-owned bytes".as_slice())],
            std::iter::empty::<(&RepoPath, TreeEntry, &[u8])>(),
            should_preserve_checkout_path,
        )
        .unwrap();

        assert!(!root.path().join("target/tracked.bin").exists());
        assert_eq!(
            std::fs::read(root.path().join("target/debug/untracked-cache")).unwrap(),
            b"generated bytes"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn graph_owned_generated_directory_can_transition_to_file() {
        for generated in ["target", "vendor", "dist", "build", "node_modules"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join(generated).join("nested/deeper")).unwrap();
            std::fs::write(
                root.path()
                    .join(generated)
                    .join("nested/deeper/tracked.old"),
                b"old graph bytes",
            )
            .unwrap();
            std::fs::create_dir_all(root.path().join(".next/cache")).unwrap();
            std::fs::write(root.path().join(".next/cache/untracked"), b"cache bytes").unwrap();
            let old = repo_path(format!("{generated}/nested/deeper/tracked.old"));
            let target = repo_path(generated.to_string());

            reconcile_source_tree(
                root.path(),
                [(&old, regular(), b"old graph bytes".as_slice())],
                [(&target, regular(), b"new graph file".as_slice())],
                should_preserve_checkout_path,
            )
            .unwrap();

            assert_eq!(
                std::fs::read(root.path().join(generated)).unwrap(),
                b"new graph file",
                "graph-owned {generated} directory must transition to a file"
            );
            assert_eq!(
                std::fs::read(root.path().join(".next/cache/untracked")).unwrap(),
                b"cache bytes",
                "unrelated generated content must survive {generated} transition"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn generated_directory_transition_rejects_unrelated_child_before_mutation() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("target")).unwrap();
        std::fs::write(root.path().join("target/tracked.old"), b"old graph bytes").unwrap();
        std::fs::write(root.path().join("target/editor-cache"), b"editor bytes").unwrap();
        let old = repo_path("target/tracked.old".to_string());
        let target = repo_path("target".to_string());

        let error = reconcile_source_tree(
            root.path(),
            [(&old, regular(), b"old graph bytes".as_slice())],
            [(&target, regular(), b"new graph file".as_slice())],
            should_preserve_checkout_path,
        )
        .unwrap_err();

        assert!(error.to_string().contains("untracked working-copy path"));
        assert_eq!(
            std::fs::read(root.path().join("target/tracked.old")).unwrap(),
            b"old graph bytes"
        );
        assert_eq!(
            std::fs::read(root.path().join("target/editor-cache")).unwrap(),
            b"editor bytes"
        );
        assert!(root.path().join("target").is_dir());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn post_preflight_editor_replacement_blocks_overwrite_and_preserves_bytes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        let path = root.path().join("src/owned.rs");
        std::fs::write(&path, b"old graph bytes").unwrap();
        let owned = repo_path("src/owned.rs".to_string());

        let error = reconcile_source_tree_with_pre_mutation_hook(
            root.path(),
            [(&owned, regular(), b"old graph bytes".as_slice())],
            [(&owned, regular(), b"new branch bytes".as_slice())],
            should_preserve_checkout_path,
            || {
                let replacement = root.path().join("src/editor.tmp");
                std::fs::write(&replacement, b"editor bytes").unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::rename(replacement, &path).unwrap();
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("differs from prior workspace source"));
        assert_eq!(std::fs::read(&path).unwrap(), b"editor bytes");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn post_preflight_editor_replacement_blocks_removal_and_preserves_bytes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        let path = root.path().join("src/removed.rs");
        std::fs::write(&path, b"old graph bytes").unwrap();
        let removed = repo_path("src/removed.rs".to_string());

        let error = reconcile_source_tree_with_pre_mutation_hook(
            root.path(),
            [(&removed, regular(), b"old graph bytes".as_slice())],
            std::iter::empty::<(&RepoPath, TreeEntry, &[u8])>(),
            should_preserve_checkout_path,
            || {
                let replacement = root.path().join("src/editor.tmp");
                std::fs::write(&replacement, b"editor bytes").unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::rename(replacement, &path).unwrap();
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("differs from prior workspace source"));
        assert_eq!(std::fs::read(&path).unwrap(), b"editor bytes");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn projection_root_kernel_lock_serializes_cross_process_authority() {
        let root = tempfile::tempdir().unwrap();
        let first = ProjectionRoot::open(root.path()).unwrap();

        let started = std::time::Instant::now();
        let error = match ProjectionRoot::open_with_projection_lock_deadline(
            root.path(),
            std::time::Duration::from_millis(200),
        ) {
            Ok(_) => panic!("a second projection authority entered while the lock was held"),
            Err(error) => error,
        };
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "the contender must wait out the deadline before failing"
        );
        assert!(
            error
                .to_string()
                .contains("another exact-source projection is active after waiting"),
            "unexpected lock refusal: {error}"
        );
        assert!(
            error.to_string().contains("pid="),
            "timeout error should name the recorded holder: {error}"
        );

        drop(first);
        ProjectionRoot::open(root.path())
            .expect("dropping the retained capability must release the kernel lock");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn projection_lock_waits_out_a_short_lived_holder() {
        let root = tempfile::tempdir().unwrap();
        let first = ProjectionRoot::open(root.path()).unwrap();

        let contender_root = root.path().to_path_buf();
        // Unbounded, so the send never blocks the contender and cannot inflate
        // the wait it is about to measure. The stamp precedes the send, which is
        // what puts the contender's clock ahead of the hold rather than after
        // however long the OS took to schedule the thread.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let contender = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            ready_tx.send(()).unwrap();
            let opened = ProjectionRoot::open_with_projection_lock_deadline(
                &contender_root,
                std::time::Duration::from_secs(60),
            );
            (opened.map(|_| ()), started.elapsed())
        });

        ready_rx.recv().unwrap();
        let hold_began = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let held_for = hold_began.elapsed();
        drop(first);

        let (opened, waited) = contender.join().unwrap();
        opened.expect("the contender must acquire once the holder releases");
        assert!(
            waited >= held_for,
            "the contender must wait out the whole hold, held {held_for:?} but waited {waited:?}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_freeze_does_not_create_missing_control_state() {
        let root = tempfile::tempdir().unwrap();

        let error = ExactProjectionFreeze::acquire_existing(root.path())
            .expect_err("freeze must not initialize a repository");

        assert!(
            error.to_string().contains(".kin"),
            "unexpected missing-control error: {error}"
        );
        assert!(
            !root.path().join(".kin").exists(),
            "existing-only freeze created repository control state"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_revalidation_rejects_same_byte_object_substitution() {
        let root = tempfile::tempdir().unwrap();
        let path = repo_path("compose.yaml");
        let content = b"services:\n  api:\n    image: example/api\n";
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        materialize_source_tree(root.path(), [(&path, entry, content.as_slice())]).unwrap();

        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
        let verification = freeze
            .verify_resolved_tree(&tree, [(&path, entry, content.as_slice())])
            .unwrap();

        let projected = root.path().join("compose.yaml");
        let displaced = root.path().join("compose.yaml.displaced");
        std::fs::rename(&projected, &displaced).unwrap();
        std::fs::write(&projected, content).unwrap();

        let error = freeze
            .revalidate_resolved_tree(&verification, &tree, [(&path, entry, content.as_slice())])
            .expect_err("same-byte inode substitution must invalidate the proof");
        assert!(
            error.to_string().contains("changed object identity"),
            "unexpected substitution error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_projection_freeze_never_follows_a_symlink_ancestor() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("nested")).unwrap();
        let content = b"outside bytes";
        std::fs::write(outside.path().join("nested/compose.yaml"), content).unwrap();
        symlink(outside.path().join("nested"), root.path().join("nested")).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());

        let path = repo_path("nested/compose.yaml");
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();

        let error = freeze
            .verify_resolved_tree(&tree, [(&path, entry, content.as_slice())])
            .expect_err("a matching body behind a symlink ancestor must be rejected");
        assert!(
            error
                .to_string()
                .contains("a parent path is not the expected directory"),
            "unexpected symlink-ancestor error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_projection_freeze_accepts_arbitrary_git_symlink_target_bytes() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let path = repo_path("external-link");
        let target = b"/absolute/\xff-target/outside/repository";
        let entry = TreeEntry::symlink(kin_blobs::digest(target));
        let tree = exact_tree(&path, entry);
        symlink(
            std::ffi::OsStr::from_bytes(target),
            root.path().join("external-link"),
        )
        .unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());

        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
        let verification = freeze
            .verify_resolved_tree(&tree, [(&path, entry, target.as_slice())])
            .expect("read-only eject proof must not apply checkout target policy");
        freeze
            .revalidate_resolved_tree(&verification, &tree, [(&path, entry, target.as_slice())])
            .unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_gitlink_absent_is_graph_only_and_target_bound() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let blobs_directory = outer.path().join("blobs");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();

        let readme_path = repo_path("README.md");
        let readme_body = b"exact repository\n";
        let readme_entry = exact_blob(readme_body, false);
        let readme_id = ArtifactId::new();
        let gitlink_path = repo_path("vendor/dependency");
        let gitlink_id = ArtifactId::new();
        let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x44; 20]));
        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(readme_id, readme_path.clone(), readme_entry),
            ResolvedArtifact::new(gitlink_id, gitlink_path.clone(), gitlink_entry),
        ])
        .unwrap();
        materialize_source_tree(
            &root,
            [(&readme_path, readme_entry, readme_body.as_slice())],
        )
        .unwrap();
        let blobs = kin_blobs::BlobStore::new(blobs_directory).unwrap();
        blobs.write(readme_body).unwrap();

        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();
        freeze
            .revalidate_resolved_tree_from_blobs(&verification, &tree, &blobs)
            .unwrap();

        let wrong_target_tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(readme_id, readme_path, readme_entry),
            ResolvedArtifact::new(
                gitlink_id,
                gitlink_path.clone(),
                TreeEntry::gitlink(GitObjectId::sha1([0x55; 20])),
            ),
        ])
        .unwrap();
        let error = freeze
            .revalidate_resolved_tree_from_blobs(&verification, &wrong_target_tree, &blobs)
            .expect_err("the exact Gitlink target must be part of the proof");
        assert!(
            error
                .to_string()
                .contains("resolved projection tree changed"),
            "unexpected Gitlink target error: {error}"
        );

        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        freeze
            .detach_verified_to_from_blobs(
                &verification,
                &tree,
                &blobs,
                &target,
                std::ffi::OsStr::new("kin"),
            )
            .unwrap();
        assert!(!root.join(".kin").exists());
        assert!(!root.join("vendor/dependency").exists());
        assert!(archive.join("kin/reconciliation/projection.lock").is_file());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_gitlink_directory_preserves_independently_owned_contents() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let dependency = root.join("vendor/dependency");
        std::fs::create_dir_all(dependency.join("nested")).unwrap();
        std::fs::create_dir(&archive).unwrap();
        std::fs::write(dependency.join("nested/owned.txt"), b"before").unwrap();
        drop(ProjectionRoot::open(&root).unwrap());

        let gitlink_path = repo_path("vendor/dependency");
        let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x66; 20]));
        let tree = exact_tree_entries([(gitlink_path, gitlink_entry)]);
        let blobs = kin_blobs::BlobStore::new(outer.path().join("blobs")).unwrap();
        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();

        std::fs::write(dependency.join("nested/owned.txt"), b"after").unwrap();
        std::fs::write(dependency.join("new-untracked.txt"), b"independent").unwrap();
        freeze
            .revalidate_resolved_tree_from_blobs(&verification, &tree, &blobs)
            .expect("Gitlink proof must not traverse independently owned contents");

        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        freeze
            .detach_verified_to_from_blobs(
                &verification,
                &tree,
                &blobs,
                &target,
                std::ffi::OsStr::new("kin"),
            )
            .unwrap();

        assert_eq!(
            std::fs::read(dependency.join("nested/owned.txt")).unwrap(),
            b"after"
        );
        assert_eq!(
            std::fs::read(dependency.join("new-untracked.txt")).unwrap(),
            b"independent"
        );
        assert!(!root.join(".kin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_projection_gitlink_directory_replacement_invalidates_the_proof() {
        let root = tempfile::tempdir().unwrap();
        let dependency = root.path().join("vendor/dependency");
        let displaced = root.path().join("vendor/dependency.displaced");
        std::fs::create_dir_all(&dependency).unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());

        let gitlink_path = repo_path("vendor/dependency");
        let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x77; 20]));
        let tree = exact_tree_entries([(gitlink_path, gitlink_entry)]);
        let blobs = kin_blobs::BlobStore::new(root.path().join("blobs")).unwrap();
        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();

        std::fs::rename(&dependency, &displaced).unwrap();
        std::fs::create_dir(&dependency).unwrap();
        let error = freeze
            .revalidate_resolved_tree_from_blobs(&verification, &tree, &blobs)
            .expect_err("same-name Gitlink directory replacement must invalidate the proof");
        assert!(
            error.to_string().contains("changed identity"),
            "unexpected Gitlink replacement error: {error}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_gitlink_absent_cannot_materialize_after_verification() {
        let root = tempfile::tempdir().unwrap();
        drop(ProjectionRoot::open(root.path()).unwrap());

        let gitlink_path = repo_path("vendor/dependency");
        let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x88; 20]));
        let tree = exact_tree_entries([(gitlink_path, gitlink_entry)]);
        let blobs = kin_blobs::BlobStore::new(root.path().join("blobs")).unwrap();
        let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();

        std::fs::create_dir_all(root.path().join("vendor/dependency")).unwrap();
        let error = freeze
            .revalidate_resolved_tree_from_blobs(&verification, &tree, &blobs)
            .expect_err("an absent Gitlink may not materialize after verification");
        assert!(
            error.to_string().contains("materialized after"),
            "unexpected Gitlink materialization error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_projection_gitlink_rejects_files_and_symlinks_without_following() {
        use std::os::unix::fs::symlink;

        for replacement in ["file", "symlink"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("vendor")).unwrap();
            let dependency = root.path().join("vendor/dependency");
            match replacement {
                "file" => std::fs::write(&dependency, b"not a directory").unwrap(),
                "symlink" => symlink(root.path(), &dependency).unwrap(),
                _ => unreachable!(),
            }
            drop(ProjectionRoot::open(root.path()).unwrap());

            let gitlink_path = repo_path("vendor/dependency");
            let gitlink_entry = TreeEntry::gitlink(GitObjectId::sha1([0x99; 20]));
            let tree = exact_tree_entries([(gitlink_path, gitlink_entry)]);
            let blobs = kin_blobs::BlobStore::new(root.path().join("blobs")).unwrap();
            let freeze = ExactProjectionFreeze::acquire_existing(root.path()).unwrap();
            let error = freeze
                .verify_resolved_tree_from_blobs(&tree, &blobs)
                .expect_err("Gitlink proof must reject a file or no-follow symlink");
            assert!(
                error.to_string().contains("neither absent nor")
                    && error.to_string().contains("real directory"),
                "unexpected Gitlink {replacement} error: {error}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_detach_moves_the_retained_control_directory() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();
        let path = repo_path("Dockerfile");
        let content = b"FROM scratch\n";
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        materialize_source_tree(&root, [(&path, entry, content.as_slice())]).unwrap();
        let proof_directory = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(proof_directory.path().to_path_buf()).unwrap();
        assert_eq!(
            blobs.write(content).unwrap().as_bytes(),
            entry.blob_identity().unwrap().as_bytes()
        );

        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        freeze
            .detach_verified_to_from_blobs(
                &verification,
                &tree,
                &blobs,
                &target,
                std::ffi::OsStr::new("kin"),
            )
            .unwrap();

        assert!(!root.join(".kin").exists());
        assert!(archive.join("kin/reconciliation/projection.lock").is_file());
        assert_eq!(std::fs::read(root.join("Dockerfile")).unwrap(), content);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn exact_projection_detach_rejects_replaced_archive_target() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let displaced_archive = outer.path().join("archive.displaced");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();
        let path = repo_path("compose.yaml");
        let content = b"services: {}\n";
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        materialize_source_tree(&root, [(&path, entry, content.as_slice())]).unwrap();

        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree(&tree, [(&path, entry, content.as_slice())])
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        std::fs::rename(&archive, &displaced_archive).unwrap();
        std::fs::create_dir(&archive).unwrap();

        let error = freeze
            .detach_verified_to(
                &verification,
                &tree,
                [(&path, entry, content.as_slice())],
                &target,
                std::ffi::OsStr::new("kin"),
            )
            .expect_err("replaced archive target must block detach");
        assert!(
            error.to_string().contains("detach target") && error.to_string().contains("replaced"),
            "unexpected target-replacement error: {error}"
        );
        assert!(root.join(".kin").is_dir());
        assert!(!archive.join("kin").exists());
        assert!(!displaced_archive.join("kin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_projection_detach_rolls_back_post_move_archive_replacement() {
        let fixture = exact_eject_fixture(ExistingGitFixture::None);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let _verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();

        let error = freeze
            .detach_after_revalidation_with_hook(&target, std::ffi::OsStr::new("kin"), || {
                std::fs::rename(&fixture.archive, &fixture.displaced_archive).unwrap();
                std::fs::create_dir(&fixture.archive).unwrap();
                std::fs::write(fixture.archive.join("replacement-marker"), b"replacement").unwrap();
            })
            .expect_err("post-move archive replacement must roll detach back");

        assert!(error.to_string().contains("detach target"));
        assert!(fixture.root.join(".kin").is_dir());
        assert!(!fixture.displaced_archive.join("kin").exists());
        assert_eq!(
            std::fs::read(fixture.archive.join("replacement-marker")).unwrap(),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_replaces_git_and_archives_a_previous_git_file() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let outcome = freeze
            .replace_git_and_detach_verified_to_from_blobs(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
            )
            .unwrap();

        assert_eq!(
            outcome,
            ExactProjectionEjectOutcome {
                had_previous_git: true,
                retained_journal: None,
            }
        );
        assert!(
            !fixture
                .archive
                .join("kin/reconciliation/exact-eject-journal.json")
                .exists(),
            "a finished eject retires its journal from the archived .kin"
        );
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git"
        );
        assert_eq!(
            std::fs::read(fixture.archive.join("previous-git")).unwrap(),
            b"gitdir: ../legacy.git\n"
        );
        assert!(fixture
            .archive
            .join("kin/reconciliation/projection.lock")
            .is_file());
        assert!(!fixture.staged_git.exists());
        assert_eq!(
            std::fs::read(fixture.root.join("compose.yaml")).unwrap(),
            b"services:\n  api:\n    image: scratch\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_archives_a_previous_git_directory() {
        let fixture = exact_eject_fixture(ExistingGitFixture::Directory);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let outcome = freeze
            .replace_git_and_detach_verified_to_from_blobs(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
            )
            .unwrap();

        assert!(outcome.had_previous_git);
        assert!(outcome.retained_journal.is_none());
        assert_eq!(
            std::fs::read(fixture.archive.join("previous-git/legacy-marker")).unwrap(),
            b"legacy Git"
        );
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git"
        );
        assert!(
            !fixture
                .archive
                .join("kin/reconciliation/exact-eject-journal.json")
                .exists(),
            "a finished eject retires its journal from the archived .kin"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_without_previous_git_reports_that_exactly() {
        let fixture = exact_eject_fixture(ExistingGitFixture::None);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let outcome = freeze
            .replace_git_and_detach_verified_to_from_blobs(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
            )
            .unwrap();

        assert!(!outcome.had_previous_git);
        assert!(outcome.retained_journal.is_none());
        assert!(!fixture.archive.join("previous-git").exists());
        assert!(
            !fixture
                .archive
                .join("kin/reconciliation/exact-eject-journal.json")
                .exists(),
            "a finished eject retires its journal from the archived .kin"
        );
    }

    /// Copy a directory tree the way `cp -r` does: every entry gets an inode of
    /// its own.
    #[cfg(unix)]
    fn copy_directory_recursively(source: &Path, destination: &Path) {
        std::fs::create_dir(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory_recursively(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// Eject, put the journal back into the archive the way a 0.5.52 eject
    /// left it, then copy the archived `.kin` back to the root the way the
    /// rc0552n stranger did with `cp -r`.
    ///
    /// Returns the fixture, the carried journal's path under the root, and the
    /// archived journal's path. The journal bytes are the real ones: they are
    /// captured at the detach hook point, after `.kin` has moved and before a
    /// finished transaction retires them.
    #[cfg(unix)]
    fn eject_then_copy_back_a_journal_carrying_kin() -> (ExactEjectFixture, PathBuf, PathBuf) {
        let fixture = exact_eject_fixture(ExistingGitFixture::Directory);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();
        let archived_journal = fixture
            .archive
            .join("kin/reconciliation/exact-eject-journal.json");
        let mut leftover = Vec::new();
        freeze
            .replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterKinDetached {
                        leftover = std::fs::read(&archived_journal).unwrap();
                    }
                },
            )
            .unwrap();
        assert!(
            !leftover.is_empty(),
            "the detach hook point must see the journal in the archived .kin"
        );
        assert!(
            !archived_journal.exists(),
            "a finished eject retires its journal"
        );
        std::fs::write(&archived_journal, &leftover).unwrap();

        copy_directory_recursively(&fixture.archive.join("kin"), &fixture.root.join(".kin"));
        let carried = fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json");
        assert!(carried.is_file(), "the copy carries the journal along");
        (fixture, carried, archived_journal)
    }

    /// A `.kin` copied back out of an eject archive carries the journal of the
    /// eject that detached the original, and every projection open refused it
    /// as an invalid identity-bound descriptor: after
    /// `cp -r .kin-ejected-*/kin .kin`, every `kin commit` answered HTTP 500
    /// on 0.5.52 and the store was deleted to get out (FIR-2664). The archive
    /// still holds the original inode for inode, which proves the eject
    /// finished, so the copy's journal is retired on open and nothing in the
    /// namespace moves.
    #[cfg(unix)]
    #[test]
    fn a_journal_carried_by_a_copied_kin_is_retired_when_the_archive_proves_the_eject_finished() {
        let (fixture, carried, archived_journal) = eject_then_copy_back_a_journal_carrying_kin();

        drop(ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap());

        assert!(!carried.exists(), "the carried journal is retired on open");
        assert!(archived_journal.is_file(), "the archive is left as it was");
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git",
            "the installed Git stays installed"
        );
        assert!(fixture.archive.join("previous-git").is_dir());
        assert!(fixture.archive.join("kin").is_dir());
        assert!(fixture.root.join(".kin").is_dir());
    }

    /// The same carried journal with no archived `.kin` to prove anything
    /// against is refused, and the refusal names the file, the archive it
    /// expected and the way out, in a variant a daemon answers in words.
    #[cfg(unix)]
    #[test]
    fn a_journal_bound_elsewhere_is_refused_with_the_file_and_the_remedy_named() {
        let (fixture, carried, _archived_journal) = eject_then_copy_back_a_journal_carrying_kin();
        std::fs::remove_dir_all(fixture.archive.join("kin")).unwrap();

        let error = ExactProjectionFreeze::acquire_existing(&fixture.root)
            .expect_err("a journal that matches nothing must be refused");

        assert!(
            matches!(error, KinError::ProjectionBlocked(_)),
            "a person has to act on this, so it is a blocked projection: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&carried.display().to_string()),
            "{message}"
        );
        assert!(
            message.contains(&fixture.archive.display().to_string()),
            "{message}"
        );
        assert!(message.contains("remove the file and rerun"), "{message}");
        assert!(message.contains("kin init"), "{message}");
        assert!(
            !message.contains("invalid identity-bound descriptor"),
            "{message}"
        );
        assert!(
            carried.is_file(),
            "a refused journal is left for the person to act on"
        );
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git",
            "a refusal moves nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_recovers_after_process_death_with_previous_git_archived() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = freeze.replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterPreviousGitArchived {
                        panic!("simulated process death after previous Git archive");
                    }
                },
            );
        }));
        assert!(killed.is_err());
        assert!(!fixture.root.join(".git").exists());
        assert!(fixture.archive.join("previous-git").is_file());
        assert!(fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json")
            .is_file());

        drop(ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap());

        assert_eq!(
            std::fs::read(fixture.root.join(".git")).unwrap(),
            b"gitdir: ../legacy.git\n"
        );
        assert!(fixture.staged_git.is_dir());
        assert!(!fixture.archive.join("previous-git").exists());
        assert!(!fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_recovers_after_process_death_with_staged_git_installed() {
        let fixture = exact_eject_fixture(ExistingGitFixture::Directory);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = freeze.replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterStagedGitInstalled {
                        panic!("simulated process death after staged Git install");
                    }
                },
            );
        }));
        assert!(killed.is_err());
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git"
        );
        assert!(!fixture.staged_git.exists());
        assert!(fixture.archive.join("previous-git").is_dir());

        drop(ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap());

        assert_eq!(
            std::fs::read(fixture.root.join(".git/legacy-marker")).unwrap(),
            b"legacy Git"
        );
        assert!(fixture.staged_git.is_dir());
        assert!(!fixture.archive.join("previous-git").exists());
        assert!(!fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_recovery_rejects_an_authenticated_journal_tamper() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = freeze.replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterPreviousGitArchived {
                        panic!("simulated process death");
                    }
                },
            );
        }));
        let journal = fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json");
        let mut bytes = std::fs::read(&journal).unwrap();
        let byte = bytes
            .iter_mut()
            .find(|byte| byte.is_ascii_alphabetic())
            .unwrap();
        *byte ^= 1;
        std::fs::write(&journal, bytes).unwrap();

        let error = ExactProjectionFreeze::acquire_existing(&fixture.root)
            .expect_err("tampered recovery journal must fail closed");
        assert!(
            error.to_string().contains("decode") || error.to_string().contains("authentication"),
            "unexpected journal tamper error: {error}"
        );
        assert!(!fixture.root.join(".git").exists());
        assert!(fixture.archive.join("previous-git").is_file());
        assert!(fixture.staged_git.is_dir());
        assert!(journal.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_recovery_rejects_staged_git_descendant_tamper() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = freeze.replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterStagedGitInstalled {
                        panic!("simulated process death");
                    }
                },
            );
        }));
        std::fs::write(
            fixture.root.join(".git/stage-marker"),
            b"tampered staged Git",
        )
        .unwrap();

        let error = ExactProjectionFreeze::acquire_existing(&fixture.root)
            .expect_err("tampered staged Git must block journal recovery");
        assert!(
            error.to_string().contains("seal") || error.to_string().contains("changed"),
            "unexpected staged Git tamper error: {error}"
        );
        assert!(fixture.root.join(".git").is_dir());
        assert!(!fixture.staged_git.exists());
        assert!(fixture.archive.join("previous-git").is_file());
        assert!(fixture
            .root
            .join(".kin/reconciliation/exact-eject-journal.json")
            .is_file());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_process_death_after_kin_detach_is_a_committed_git_handoff() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = freeze.replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterKinDetached {
                        panic!("simulated process death after commit point");
                    }
                },
            );
        }));
        assert!(killed.is_err());
        assert!(!fixture.root.join(".kin").exists());
        assert_eq!(
            std::fs::read(fixture.root.join(".git/stage-marker")).unwrap(),
            b"prepared Git"
        );
        assert!(fixture
            .archive
            .join("kin/reconciliation/exact-eject-journal.json")
            .is_file());
        assert!(fixture.archive.join("previous-git").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_raced_archive_destination_fails_before_mutation() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::BeforeNamespaceMutation {
                        std::fs::write(fixture.archive.join("previous-git"), b"raced destination")
                            .unwrap();
                    }
                },
            )
            .expect_err("a raced archive destination must fail closed");

        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(
            std::fs::read(fixture.root.join(".git")).unwrap(),
            b"gitdir: ../legacy.git\n"
        );
        assert!(fixture.root.join(".kin").is_dir());
        assert!(fixture.staged_git.is_dir());
        assert_eq!(
            std::fs::read(fixture.archive.join("previous-git")).unwrap(),
            b"raced destination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_root_replacement_after_detach_rolls_back_retained_state() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterKinDetached {
                        std::fs::rename(&fixture.root, &fixture.displaced_root).unwrap();
                        std::fs::create_dir(&fixture.root).unwrap();
                        std::fs::write(fixture.root.join("replacement-marker"), b"replacement")
                            .unwrap();
                    }
                },
            )
            .expect_err("a replaced visible root must block success and roll back");

        assert!(error.to_string().contains("projection root"));
        assert_eq!(
            std::fs::read(fixture.root.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(!fixture.root.join(".git").exists());
        assert!(!fixture.root.join(".kin").exists());
        assert_eq!(
            std::fs::read(fixture.displaced_root.join(".git")).unwrap(),
            b"gitdir: ../legacy.git\n"
        );
        assert!(fixture.displaced_root.join(".kin").is_dir());
        assert!(fixture.staged_git.is_dir());
        assert!(!fixture.archive.join("kin").exists());
        assert!(!fixture.archive.join("previous-git").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_archive_replacement_after_detach_rolls_back_retained_state() {
        let fixture = exact_eject_fixture(ExistingGitFixture::Directory);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterKinDetached {
                        std::fs::rename(&fixture.archive, &fixture.displaced_archive).unwrap();
                        std::fs::create_dir(&fixture.archive).unwrap();
                        std::fs::write(fixture.archive.join("replacement-marker"), b"replacement")
                            .unwrap();
                    }
                },
            )
            .expect_err("a replaced visible archive must block success and roll back");

        assert!(error.to_string().contains("detach target"));
        assert_eq!(
            std::fs::read(fixture.archive.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(fixture.root.join(".kin").is_dir());
        assert_eq!(
            std::fs::read(fixture.root.join(".git/legacy-marker")).unwrap(),
            b"legacy Git"
        );
        assert!(fixture.staged_git.is_dir());
        assert!(!fixture.displaced_archive.join("kin").exists());
        assert!(!fixture.displaced_archive.join("previous-git").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_stage_parent_replacement_after_detach_rolls_back_retained_state() {
        let fixture = exact_eject_fixture(ExistingGitFixture::File);
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs_with_hook(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
                |point| {
                    if point == ExactProjectionEjectHookPoint::AfterKinDetached {
                        std::fs::rename(&fixture.stage_parent, &fixture.displaced_stage_parent)
                            .unwrap();
                        std::fs::create_dir(&fixture.stage_parent).unwrap();
                        std::fs::write(
                            fixture.stage_parent.join("replacement-marker"),
                            b"replacement",
                        )
                        .unwrap();
                    }
                },
            )
            .expect_err("a replaced visible stage parent must block success and roll back");

        assert!(error.to_string().contains("staged Git parent"));
        assert_eq!(
            std::fs::read(fixture.stage_parent.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(!fixture.staged_git.exists());
        assert!(fixture.displaced_stage_parent.join("staged-git").is_dir());
        assert!(fixture.root.join(".kin").is_dir());
        assert_eq!(
            std::fs::read(fixture.root.join(".git")).unwrap(),
            b"gitdir: ../legacy.git\n"
        );
        assert!(!fixture.archive.join("kin").exists());
        assert!(!fixture.archive.join("previous-git").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_eject_rejects_a_symbolic_link_git_entry_without_mutation() {
        use std::os::unix::fs::symlink;

        let fixture = exact_eject_fixture(ExistingGitFixture::None);
        std::fs::create_dir(fixture.root.join("external-git")).unwrap();
        symlink("external-git", fixture.root.join(".git")).unwrap();
        let freeze = ExactProjectionFreeze::acquire_existing(&fixture.root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&fixture.tree, &fixture.blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&fixture.archive).unwrap();
        let stage = ExactProjectionGitStage::open_existing_unverified_for_test(&fixture.staged_git)
            .unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs(
                &verification,
                &fixture.tree,
                &fixture.blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
            )
            .expect_err("a symbolic-link `.git` entry must fail closed");

        assert!(error.to_string().contains("symbolic link"));
        assert!(fixture.root.join(".kin").is_dir());
        assert!(fixture.root.join(".git").is_symlink());
        assert!(fixture.staged_git.is_dir());
        assert!(!fixture.archive.join("kin").exists());
    }

    #[cfg(windows)]
    #[test]
    fn exact_eject_fails_before_mutation_on_windows() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("repository");
        let archive = outer.path().join("archive");
        let stage_parent = outer.path().join("stage-parent");
        let staged_git = stage_parent.join("staged-git");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&archive).unwrap();
        std::fs::create_dir(&stage_parent).unwrap();
        std::fs::create_dir(&staged_git).unwrap();
        std::fs::write(staged_git.join("stage-marker"), b"prepared Git").unwrap();
        let path = repo_path("compose.yaml");
        let content = b"services: {}\n";
        let entry = exact_blob(content, false);
        let tree = exact_tree(&path, entry);
        materialize_source_tree(&root, [(&path, entry, content.as_slice())]).unwrap();
        std::fs::write(root.join(".git"), b"gitdir: ../legacy.git\r\n").unwrap();
        let blobs = kin_blobs::BlobStore::new(outer.path().join("proof-blobs")).unwrap();
        blobs.write(content).unwrap();
        let freeze = ExactProjectionFreeze::acquire_existing(&root).unwrap();
        let verification = freeze
            .verify_resolved_tree_from_blobs(&tree, &blobs)
            .unwrap();
        let target = ExactProjectionDetachTarget::open_existing(&archive).unwrap();
        let stage =
            ExactProjectionGitStage::open_existing_unverified_for_test(&staged_git).unwrap();

        let error = freeze
            .replace_git_and_detach_verified_to_from_blobs(
                &verification,
                &tree,
                &blobs,
                stage,
                &target,
                std::ffi::OsStr::new("kin"),
                std::ffi::OsStr::new("previous-git"),
            )
            .expect_err("Windows must fail before an under-specified namespace mutation");

        assert!(error.to_string().contains("unsupported on Windows"));
        assert!(root.join(".kin").is_dir());
        assert_eq!(
            std::fs::read(root.join(".git")).unwrap(),
            b"gitdir: ../legacy.git\r\n"
        );
        assert!(staged_git.is_dir());
        assert!(!archive.join("kin").exists());
        assert!(!archive.join("previous-git").exists());
    }

    #[cfg(unix)]
    #[test]
    fn post_preflight_control_directory_replacement_blocks_tree_mutation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned.rs");
        std::fs::write(&path, b"old graph bytes").unwrap();
        let owned = repo_path("owned.rs".to_string());

        let error = reconcile_source_tree_with_pre_mutation_hook(
            root.path(),
            [(&owned, regular(), b"old graph bytes".as_slice())],
            [(&owned, regular(), b"new graph bytes".as_slice())],
            should_preserve_checkout_path,
            || {
                std::fs::rename(root.path().join(".kin"), root.path().join(".kin-detached"))
                    .unwrap();
                std::fs::create_dir(root.path().join(".kin")).unwrap();
                std::fs::write(root.path().join(".kin/replacement-marker"), b"replacement")
                    .unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("repository control directory"));
        assert_eq!(std::fs::read(&path).unwrap(), b"old graph bytes");
        assert_eq!(
            std::fs::read(root.path().join(".kin/replacement-marker")).unwrap(),
            b"replacement"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn post_preflight_same_bytes_replacement_blocks_mutation_by_identity() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        let path = root.path().join("src/owned.rs");
        std::fs::write(&path, b"old graph bytes").unwrap();
        let owned = repo_path("src/owned.rs".to_string());

        let error = reconcile_source_tree_with_pre_mutation_hook(
            root.path(),
            [(&owned, regular(), b"old graph bytes".as_slice())],
            [(&owned, regular(), b"new branch bytes".as_slice())],
            should_preserve_checkout_path,
            || {
                let replacement = root.path().join("src/editor.tmp");
                std::fs::write(&replacement, b"old graph bytes").unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::rename(replacement, &path).unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed object identity"));
        assert_eq!(std::fs::read(&path).unwrap(), b"old graph bytes");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn post_identity_validation_replacement_is_restored_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        let path = root.path().join("src/owned.rs");
        std::fs::write(&path, b"old graph bytes").unwrap();
        let owned = repo_path("src/owned.rs".to_string());

        let error = reconcile_source_tree_with_mutation_hooks(
            root.path(),
            [(&owned, regular(), b"old graph bytes".as_slice())],
            [(&owned, regular(), b"new branch bytes".as_slice())],
            should_preserve_checkout_path,
            || {},
            || {
                let replacement = root.path().join("src/editor.tmp");
                std::fs::write(&replacement, b"old graph bytes").unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::rename(replacement, &path).unwrap();
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("changed object identity before exact displacement"));
        assert_eq!(std::fs::read(&path).unwrap(), b"old graph bytes");
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".kin-reconcile-")));
    }

    #[cfg(unix)]
    #[test]
    fn directory_identity_swap_is_rejected_even_when_leaf_identity_matches() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("pkg")).unwrap();
        std::fs::write(root.path().join("pkg/lib.rs"), b"old graph bytes").unwrap();
        let previous = repo_path("pkg/lib.rs".to_string());
        let target = repo_path("pkg".to_string());

        let error = reconcile_source_tree_with_pre_mutation_hook(
            root.path(),
            [(&previous, regular(), b"old graph bytes".as_slice())],
            [(&target, regular(), b"new graph file".as_slice())],
            should_preserve_checkout_path,
            || {
                std::fs::rename(root.path().join("pkg"), root.path().join("true-pkg")).unwrap();
                std::fs::create_dir(root.path().join("pkg")).unwrap();
                std::fs::hard_link(
                    root.path().join("true-pkg/lib.rs"),
                    root.path().join("pkg/lib.rs"),
                )
                .unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("directory"));
        assert!(error.to_string().contains("changed identity"));
        assert_eq!(
            std::fs::read(root.path().join("true-pkg/lib.rs")).unwrap(),
            b"old graph bytes"
        );
        assert_eq!(
            std::fs::read(root.path().join("pkg/lib.rs")).unwrap(),
            b"old graph bytes"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn generated_directory_publication_failure_restores_previous_tree() {
        for generated in ["target", "vendor", "dist", "build", "node_modules"] {
            let root = tempfile::tempdir().unwrap();
            let previous_path = root
                .path()
                .join(generated)
                .join("nested/deeper/tracked.old");
            std::fs::create_dir_all(previous_path.parent().unwrap()).unwrap();
            std::fs::write(&previous_path, b"old graph bytes").unwrap();
            let previous = repo_path(format!("{generated}/nested/deeper/tracked.old"));
            let target = repo_path(generated.to_string());

            inject_next_publication_failure();
            let error = reconcile_source_tree(
                root.path(),
                [(&previous, regular(), b"old graph bytes".as_slice())],
                [(&target, regular(), b"new graph file".as_slice())],
                should_preserve_checkout_path,
            )
            .unwrap_err();

            assert!(error
                .to_string()
                .contains("injected exact-source publication failure"));
            assert_eq!(std::fs::read(&previous_path).unwrap(), b"old graph bytes");
            assert!(root.path().join(generated).is_dir());
            assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".kin-reconcile-")));
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn partial_publication_failure_rolls_back_every_published_entry() {
        let root = tempfile::tempdir().unwrap();
        let first_path = root.path().join("first.txt");
        let second_path = root.path().join("second.txt");
        std::fs::write(&first_path, b"old first bytes").unwrap();
        std::fs::write(&second_path, b"old second bytes").unwrap();
        let first = repo_path("first.txt".to_string());
        let second = repo_path("second.txt".to_string());

        inject_publication_failure_after(1);
        let error = reconcile_source_tree(
            root.path(),
            [
                (&first, regular(), b"old first bytes".as_slice()),
                (&second, regular(), b"old second bytes".as_slice()),
            ],
            [
                (&first, regular(), b"new first bytes".as_slice()),
                (&second, regular(), b"new second bytes".as_slice()),
            ],
            should_preserve_checkout_path,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected exact-source publication failure"));
        assert_eq!(std::fs::read(&first_path).unwrap(), b"old first bytes");
        assert_eq!(std::fs::read(&second_path).unwrap(), b"old second bytes");
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".kin-reconcile-")));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn full_tree_partial_publication_failure_restores_exact_prior_tree() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("first.txt"), b"old first bytes").unwrap();
        std::fs::write(root.path().join("second.txt"), b"old second bytes").unwrap();
        std::fs::create_dir_all(root.path().join("untracked/nested")).unwrap();
        std::fs::write(
            root.path().join("untracked/nested/sentinel.txt"),
            b"untracked prior bytes",
        )
        .unwrap();
        let first = repo_path("first.txt".to_string());
        let second = repo_path("second.txt".to_string());

        inject_publication_failure_after(1);
        let error = replace_source_tree(
            root.path(),
            [
                (&first, regular(), b"new first bytes".as_slice()),
                (&second, regular(), b"new second bytes".as_slice()),
            ],
            |_| false,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected exact-source publication failure"));
        assert_eq!(
            std::fs::read(root.path().join("first.txt")).unwrap(),
            b"old first bytes"
        );
        assert_eq!(
            std::fs::read(root.path().join("second.txt")).unwrap(),
            b"old second bytes"
        );
        assert_eq!(
            std::fs::read(root.path().join("untracked/nested/sentinel.txt")).unwrap(),
            b"untracked prior bytes"
        );
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".kin-reconcile-")));
    }

    #[cfg(unix)]
    #[test]
    fn retained_transaction_cleanup_ignores_ambient_name_substitution() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let transaction = projection.create_reconciliation_transaction().unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        std::fs::write(
            transaction_path.join("true-backup"),
            b"true transaction bytes",
        )
        .unwrap();
        let renamed_transaction = projection
            .reconciliation_control_path()
            .join("renamed-true-transaction");
        std::fs::rename(&transaction_path, &renamed_transaction).unwrap();
        let substitute = transaction_path;
        std::fs::create_dir(&substitute).unwrap();
        std::fs::write(substitute.join("attacker-sentinel"), b"must survive").unwrap();

        projection
            .cleanup_reconciliation_transaction(transaction)
            .unwrap();

        assert!(!renamed_transaction.exists());
        assert_eq!(
            std::fs::read(substitute.join("attacker-sentinel")).unwrap(),
            b"must survive"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_recovers_identity_bound_full_tree_backup_transaction() {
        let root = tempfile::tempdir().unwrap();
        let prior = root.path().join("prior.txt");
        std::fs::write(&prior, b"exact prior bytes").unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let (identity, state) = projection
            .inspect_named_existing_object(
                &projection.root,
                std::ffi::OsStr::new("prior.txt"),
                ExistingObjectKind::File,
                &prior,
            )
            .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        projection
            .back_up_existing_object(
                &mut transaction,
                &PlannedExistingObject {
                    relative: PathBuf::from("prior.txt"),
                    kind: ExistingObjectKind::File,
                    identity,
                    state,
                },
                0,
            )
            .unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        assert!(!prior.exists());
        assert!(transaction_path.exists());
        drop(transaction);
        drop(projection);

        let reopened = ProjectionRoot::open(root.path()).unwrap();

        assert_eq!(std::fs::read(&prior).unwrap(), b"exact prior bytes");
        assert!(!transaction_path.exists());
        drop(reopened);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_rolls_back_crash_after_exact_target_publication() {
        let root = tempfile::tempdir().unwrap();
        let prior = root.path().join("owned.txt");
        std::fs::write(&prior, b"exact prior bytes").unwrap();
        let file_id = repo_path("owned.txt".to_string());
        let entry = ValidatedSourceEntry {
            file_id: &file_id,
            kind: regular(),
            content: b"published target bytes",
        };
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let (identity, state) = projection
            .inspect_named_existing_object(
                &projection.root,
                std::ffi::OsStr::new("owned.txt"),
                ExistingObjectKind::File,
                &prior,
            )
            .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let staged = projection
            .stage_reconciliation_entries(&transaction.directory, &[entry])
            .unwrap();
        projection
            .back_up_existing_object(
                &mut transaction,
                &PlannedExistingObject {
                    relative: PathBuf::from("owned.txt"),
                    kind: ExistingObjectKind::File,
                    identity,
                    state,
                },
                0,
            )
            .unwrap();
        projection
            .publish_staged_entry(&mut transaction, &staged[0])
            .unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        assert_eq!(std::fs::read(&prior).unwrap(), b"published target bytes");
        drop(transaction);
        drop(projection);

        ProjectionRoot::open(root.path()).unwrap();

        assert_eq!(std::fs::read(&prior).unwrap(), b"exact prior bytes");
        assert!(!transaction_path.exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_recovery_preserves_same_identity_post_crash_content_edit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned.txt");
        std::fs::write(&path, b"prior bytes").unwrap();
        let file_id = repo_path("owned.txt".to_string());
        let entry = ValidatedSourceEntry {
            file_id: &file_id,
            kind: regular(),
            content: b"published bytes",
        };
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let (identity, state) = projection
            .inspect_named_existing_object(
                &projection.root,
                std::ffi::OsStr::new("owned.txt"),
                ExistingObjectKind::File,
                &path,
            )
            .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let staged = projection
            .stage_reconciliation_entries(&transaction.directory, &[entry])
            .unwrap();
        projection
            .back_up_existing_object(
                &mut transaction,
                &PlannedExistingObject {
                    relative: PathBuf::from("owned.txt"),
                    kind: ExistingObjectKind::File,
                    identity,
                    state,
                },
                0,
            )
            .unwrap();
        projection
            .publish_staged_entry(&mut transaction, &staged[0])
            .unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        drop(transaction);
        drop(projection);

        // `write` truncates the existing published inode in place. Identity-
        // only recovery would delete this editor write and restore the backup.
        std::fs::write(&path, b"editor bytes after crash").unwrap();
        let error = match ProjectionRoot::open(root.path()) {
            Ok(_) => panic!("same-inode post-crash edit was overwritten by recovery"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("changed content or mode"));
        assert_eq!(std::fs::read(&path).unwrap(), b"editor bytes after crash");
        assert!(
            transaction_path.exists(),
            "failed-closed recovery must retain the authenticated transaction"
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_recovery_preserves_same_identity_post_crash_mode_edit() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned.sh");
        std::fs::write(&path, b"prior bytes").unwrap();
        let file_id = repo_path("owned.sh".to_string());
        let entry = ValidatedSourceEntry {
            file_id: &file_id,
            kind: regular(),
            content: b"published bytes",
        };
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let (identity, state) = projection
            .inspect_named_existing_object(
                &projection.root,
                std::ffi::OsStr::new("owned.sh"),
                ExistingObjectKind::File,
                &path,
            )
            .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let staged = projection
            .stage_reconciliation_entries(&transaction.directory, &[entry])
            .unwrap();
        projection
            .back_up_existing_object(
                &mut transaction,
                &PlannedExistingObject {
                    relative: PathBuf::from("owned.sh"),
                    kind: ExistingObjectKind::File,
                    identity,
                    state,
                },
                0,
            )
            .unwrap();
        projection
            .publish_staged_entry(&mut transaction, &staged[0])
            .unwrap();
        drop(transaction);
        drop(projection);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = match ProjectionRoot::open(root.path()) {
            Ok(_) => panic!("same-inode post-crash mode edit was overwritten by recovery"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("changed content or mode"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn recovery_actions_are_bounded_authenticated_wal_records() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let transaction_path = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        let manifest_path = transaction_path.join(RECONCILIATION_MANIFEST_FILE);
        let manifest_before = std::fs::read(&manifest_path).unwrap();
        let identity = tracked_open_directory_identity(&projection.root).unwrap();

        for index in 0..32 {
            projection
                .record_reconciliation_action(
                    &mut transaction,
                    ReconciliationRecoveryAction::PublishDirectory {
                        relative: PathBuf::from(format!("unused-{index}")),
                        identity,
                        slot: format!("unused-slot-{index}"),
                    },
                )
                .unwrap();
        }

        assert_eq!(
            std::fs::read(&manifest_path).unwrap(),
            manifest_before,
            "action growth must never rewrite the fixed transaction descriptor"
        );
        assert_eq!(transaction.manifest.actions.len(), 32);
        assert!(transaction.action_log_bytes < MAX_RECONCILIATION_ACTION_LOG_BYTES);
        assert_eq!(
            std::fs::read_dir(&transaction_path)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(RECONCILIATION_ACTION_FILE_PREFIX))
                .count(),
            32
        );
        projection
            .cleanup_reconciliation_transaction(transaction)
            .unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_rejects_tampered_recovery_action_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sentinel.txt"), b"must survive").unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let identity = tracked_open_directory_identity(&projection.root).unwrap();
        projection
            .record_reconciliation_action(
                &mut transaction,
                ReconciliationRecoveryAction::PublishDirectory {
                    relative: PathBuf::from("unused"),
                    identity,
                    slot: "unused-slot".to_string(),
                },
            )
            .unwrap();
        let action_path = projection
            .reconciliation_control_path()
            .join(&transaction.name)
            .join(format!("{RECONCILIATION_ACTION_FILE_PREFIX}{:020}.json", 0));
        let mut action: AuthenticatedReconciliationAction =
            serde_json::from_slice(&std::fs::read(&action_path).unwrap()).unwrap();
        action.authentication[0] ^= 1;
        std::fs::write(&action_path, serde_json::to_vec(&action).unwrap()).unwrap();
        drop(transaction);
        drop(projection);

        let error = match ProjectionRoot::open(root.path()) {
            Ok(_) => panic!("tampered recovery action unexpectedly recovered"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("failed authentication"));
        assert_eq!(
            std::fs::read(root.path().join("sentinel.txt")).unwrap(),
            b"must survive"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_rejects_tampered_recovery_manifest_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sentinel.txt"), b"must survive").unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let transaction = projection.create_reconciliation_transaction().unwrap();
        let manifest_path = projection
            .reconciliation_control_path()
            .join(&transaction.name)
            .join(RECONCILIATION_MANIFEST_FILE);
        let mut manifest: AuthenticatedReconciliationManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest.authentication[0] ^= 1;
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        drop(transaction);
        drop(projection);

        let error = match ProjectionRoot::open(root.path()) {
            Ok(_) => panic!("tampered manifest unexpectedly recovered"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("failed authentication"));
        assert_eq!(
            std::fs::read(root.path().join("sentinel.txt")).unwrap(),
            b"must survive"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn startup_cleans_pre_manifest_transaction_residue() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let residue = projection
            .reconciliation_control_path()
            .join(format!("tx-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&residue).unwrap();
        std::fs::write(residue.join("staged-only"), b"no root mutation").unwrap();
        drop(projection);

        ProjectionRoot::open(root.path()).unwrap();

        assert!(!residue.exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn graph_path_that_looks_like_legacy_transaction_name_is_materialized() {
        let root = tempfile::tempdir().unwrap();
        let target = repo_path(".kin-reconcile-user.tmp".to_string());

        replace_source_tree(
            root.path(),
            [(&target, regular(), b"graph-owned bytes".as_slice())],
            |_| false,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.path().join(".kin-reconcile-user.tmp")).unwrap(),
            b"graph-owned bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_rollback_moves_retained_object_not_substitute() {
        let root = tempfile::tempdir().unwrap();
        let projection = ProjectionRoot::open(root.path()).unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let published = projection
            .stage_and_publish_directory(
                &mut transaction,
                &projection.root,
                std::ffi::OsStr::new("created"),
                Path::new("created"),
                0,
            )
            .unwrap();
        let renamed_true_directory = root.path().join("renamed-true-created");
        std::fs::rename(root.path().join("created"), &renamed_true_directory).unwrap();
        std::fs::create_dir(root.path().join("created")).unwrap();
        std::fs::write(
            root.path().join("created/attacker-sentinel"),
            b"must survive",
        )
        .unwrap();

        projection
            .move_published_directory_back(&transaction.directory, &published)
            .unwrap();

        assert!(!renamed_true_directory.exists());
        assert_eq!(
            std::fs::read(root.path().join("created/attacker-sentinel")).unwrap(),
            b"must survive"
        );
        projection
            .cleanup_reconciliation_transaction(transaction)
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("created/attacker-sentinel")).unwrap(),
            b"must survive"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_reserved_component_fails_before_destructive_transition() {
        for unsafe_component in ["COM0.rs", "LPT¹.txt", "COM1 .txt", "NUL .log"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("a-parent"), b"old complete bytes").unwrap();
            let transition = repo_path("a-parent/child.txt".to_string());
            let reserved = repo_path(format!("z/{unsafe_component}"));

            let error = replace_source_tree(
                root.path(),
                [
                    (&transition, regular(), b"new child".as_slice()),
                    (&reserved, regular(), b"forbidden".as_slice()),
                ],
                |_| false,
            )
            .unwrap_err();

            assert!(error.to_string().contains("unsafe graph-owned source path"));
            assert_eq!(
                std::fs::read(root.path().join("a-parent")).unwrap(),
                b"old complete bytes"
            );
            assert!(!root.path().join("a-parent/child.txt").exists());
            assert!(!root.path().join("z").exists());
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn injected_publication_failure_preserves_existing_complete_destination() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("owned.txt");
        std::fs::write(&destination, b"old complete bytes").unwrap();
        let file_id = repo_path("owned.txt".to_string());

        inject_next_publication_failure();
        let error =
            materialize_source_entry(root.path(), &file_id, regular(), b"new bytes").unwrap_err();

        assert!(error
            .to_string()
            .contains("injected exact-source publication failure"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"old complete bytes");
        assert!(
            std::fs::read_dir(root.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".kin-checkout-")),
            "a failed exact-source publication must clean only its staged object"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialization_preserves_regular_executable_and_symlink_kinds() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        materialize_source_entry(
            root.path(),
            &repo_path("README.md".to_string()),
            regular(),
            b"read me\n",
        )
        .unwrap();
        materialize_source_entry(
            root.path(),
            &repo_path("bin/tool".to_string()),
            executable(),
            b"#!/bin/sh\n",
        )
        .unwrap();
        materialize_source_entry(
            root.path(),
            &repo_path("bin/readme".to_string()),
            symlink(),
            b"../README.md",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.path().join("README.md")).unwrap(),
            b"read me\n"
        );
        assert_eq!(
            std::fs::metadata(root.path().join("README.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(root.path().join("bin/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read_link(root.path().join("bin/readme")).unwrap(),
            Path::new("../README.md")
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialization_replaces_a_parent_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("redirect")).unwrap();

        materialize_source_entry(
            root.path(),
            &repo_path("redirect/owned".to_string()),
            regular(),
            b"must remain inside",
        )
        .unwrap();

        assert!(!outside.path().join("owned").exists());
        assert_eq!(
            std::fs::read(root.path().join("redirect/owned")).unwrap(),
            b"must remain inside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialization_replaces_a_destination_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("sentinel");
        std::fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside_file, root.path().join("victim")).unwrap();

        materialize_source_entry(
            root.path(),
            &repo_path("victim".to_string()),
            regular(),
            b"inside",
        )
        .unwrap();

        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");
        assert_eq!(
            std::fs::read(root.path().join("victim")).unwrap(),
            b"inside"
        );
        assert!(!std::fs::symlink_metadata(root.path().join("victim"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn source_tree_preparation_rejects_file_directory_prefix_conflicts() {
        let root = tempfile::tempdir().unwrap();
        let paths = [
            repo_path("same".to_string()),
            repo_path("same/child".to_string()),
        ];

        let error = prepare_source_tree(root.path(), paths.iter()).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting graph-owned source paths"));

        let duplicate = [
            repo_path("duplicate".to_string()),
            repo_path("duplicate".to_string()),
        ];
        let error = prepare_source_tree(root.path(), duplicate.iter()).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting graph-owned source paths"));

        #[cfg(any(windows, target_os = "macos"))]
        {
            let aliases = [
                repo_path("src/Owned.rs".to_string()),
                repo_path("SRC/owned.rs".to_string()),
            ];
            let error = prepare_source_tree(root.path(), aliases.iter()).unwrap_err();
            assert!(error
                .to_string()
                .contains("conflicting graph-owned source paths"));
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn source_tree_preparation_rejects_unicode_aliases() {
        let root = tempfile::tempdir().unwrap();
        for aliases in [
            ["src/caf\u{e9}.rs", "src/cafe\u{301}.rs"],
            ["src/\u{dc}ber.rs", "src/\u{fc}ber.rs"],
        ] {
            let paths = aliases.map(|path| repo_path(path.to_string()));
            let error = prepare_source_tree(root.path(), paths.iter()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("conflicting graph-owned source paths"),
                "Unicode aliases were not rejected: {aliases:?}"
            );
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn full_tree_cleanup_preserves_unicode_aliases_of_tracked_destinations() {
        for (ambient, tracked_path) in [
            ("src/caf\u{e9}.rs", "src/cafe\u{301}.rs"),
            ("src/\u{dc}ber.rs", "src/\u{fc}ber.rs"),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("src")).unwrap();
            std::fs::write(root.path().join(ambient), b"old bytes").unwrap();
            std::fs::write(root.path().join("untracked.txt"), b"remove me").unwrap();
            let tracked_id = repo_path(tracked_path.to_string());

            replace_source_tree(
                root.path(),
                [(&tracked_id, regular(), b"new complete bytes".as_slice())],
                |_| false,
            )
            .unwrap();

            // The Unicode alias of the tracked path is recognized as the tracked
            // destination and materialized, not deleted as a stale untracked file.
            assert_eq!(
                std::fs::read(root.path().join(tracked_path)).unwrap(),
                b"new complete bytes",
                "cleanup did not preserve the Unicode alias of tracked path {tracked_path:?}"
            );
            // A genuinely untracked file is still swept.
            assert!(
                !root.path().join("untracked.txt").exists(),
                "cleanup left an untracked file for tracked path {tracked_path:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn tracked_cleanup_classification_is_bounded_by_path_depth() {
        let tracked: Vec<_> = (0..20_000)
            .map(|index| repo_path(format!("src/generated/{index}/owned.rs")))
            .collect();
        let classifier = TrackedPathClassifier::new(tracked.iter()).unwrap();

        let (relation, probes) =
            classifier.relation_with_probe_count(Path::new("src/unrelated/leaf.rs"));
        assert_eq!(relation, TrackedPathRelation::Unrelated);
        assert!(
            probes <= 5,
            "classification used {probes} probes for a four-component path"
        );

        let (relation, probes) =
            classifier.relation_with_probe_count(Path::new("src/generated/19999/owned.rs/cache"));
        assert_eq!(relation, TrackedPathRelation::Descendant);
        assert!(
            probes <= 6,
            "descendant classification used {probes} probes for a five-component path"
        );
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn full_tree_cleanup_never_deletes_a_case_aliased_tracked_destination() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("SRC")).unwrap();
        std::fs::write(root.path().join("SRC/Owned.rs"), b"old bytes").unwrap();
        std::fs::write(root.path().join("untracked.txt"), b"remove me").unwrap();
        let file_id = repo_path("src/owned.rs".to_string());

        replace_source_tree(
            root.path(),
            [(&file_id, regular(), b"new complete bytes".as_slice())],
            |_| false,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.path().join("src/owned.rs")).unwrap(),
            b"new complete bytes"
        );
        assert!(!root.path().join("untracked.txt").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn source_tree_preparation_handles_both_file_directory_transitions() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file_to_dir"), b"old file").unwrap();
        std::fs::create_dir(root.path().join("dir_to_file")).unwrap();
        std::fs::write(root.path().join("dir_to_file/old"), b"old child").unwrap();
        let paths = [
            repo_path("file_to_dir/new".to_string()),
            repo_path("dir_to_file".to_string()),
        ];

        prepare_source_tree(root.path(), paths.iter()).unwrap();
        materialize_source_entry(root.path(), &paths[0], regular(), b"new child").unwrap();
        materialize_source_entry(root.path(), &paths[1], regular(), b"new file").unwrap();

        assert_eq!(
            std::fs::read(root.path().join("file_to_dir/new")).unwrap(),
            b"new child"
        );
        assert_eq!(
            std::fs::read(root.path().join("dir_to_file")).unwrap(),
            b"new file"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn full_tree_cleanup_does_not_retain_children_of_a_replaced_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("dir_to_file")).unwrap();
        std::fs::write(root.path().join("dir_to_file/old"), b"old child").unwrap();
        let file_id = repo_path("dir_to_file".to_string());

        replace_source_tree(
            root.path(),
            [(&file_id, regular(), b"new file".as_slice())],
            |_| false,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.path().join("dir_to_file")).unwrap(),
            b"new file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_root_capability_survives_ambient_root_swap_at_preflight_barrier() {
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Barrier};

        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let moved_root = sandbox.path().join("moved-root");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(root.join("old.txt"), b"remove me").unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();

        let ready = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let ready_worker = Arc::clone(&ready);
            let resume_worker = Arc::clone(&resume);
            let root_worker = root.clone();
            scope.spawn(move || {
                let file_id = repo_path("owned.txt".to_string());
                let entries =
                    validated_source_entries([(&file_id, regular(), b"inside".as_slice())])
                        .unwrap();
                project_validated_source_tree(&root_worker, &entries, Some(&|_| false), || {
                    ready_worker.wait();
                    resume_worker.wait();
                })
                .unwrap();
            });

            ready.wait();
            std::fs::rename(&root, &moved_root).unwrap();
            symlink(&outside, &root).unwrap();
            resume.wait();
        });

        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert!(!outside.join("owned.txt").exists());
        assert_eq!(
            std::fs::read(moved_root.join("owned.txt")).unwrap(),
            b"inside"
        );
        assert!(!moved_root.join("old.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn retained_root_capability_blocks_ambient_root_swap_at_preflight_barrier() {
        use std::sync::{Arc, Barrier};

        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let moved_root = sandbox.path().join("moved-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("old.txt"), b"remove me").unwrap();

        let ready = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let ready_worker = Arc::clone(&ready);
            let resume_worker = Arc::clone(&resume);
            let root_worker = root.clone();
            let worker = scope.spawn(move || {
                let file_id = repo_path("owned.txt".to_string());
                let entries =
                    validated_source_entries([(&file_id, regular(), b"inside".as_slice())])
                        .unwrap();
                project_validated_source_tree(&root_worker, &entries, Some(&|_| false), || {
                    ready_worker.wait();
                    resume_worker.wait();
                })
            });

            ready.wait();
            assert!(
                std::fs::rename(&root, &moved_root).is_err(),
                "a retained Windows directory capability must block root replacement"
            );
            resume.wait();
            worker.join().unwrap().unwrap();
        });

        assert_eq!(std::fs::read(root.join("owned.txt")).unwrap(), b"inside");
        assert!(!root.join("old.txt").exists());
        assert!(!moved_root.exists());
    }

    #[cfg(windows)]
    #[test]
    fn materialization_replaces_descendant_junction_without_following_it() {
        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("artifact"), b"outside").unwrap();

        let junction = root.join("junction");
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create test junction: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        materialize_source_entry(
            &root,
            &repo_path("junction/artifact".to_string()),
            regular(),
            b"inside",
        )
        .unwrap();

        assert_eq!(std::fs::read(outside.join("artifact")).unwrap(), b"outside");
        assert_eq!(std::fs::read(junction.join("artifact")).unwrap(), b"inside");
    }

    #[cfg(unix)]
    #[test]
    fn nested_parent_symlink_swap_at_preflight_barrier_cannot_escape() {
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Barrier};

        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside").unwrap();

        let ready = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let ready_worker = Arc::clone(&ready);
            let resume_worker = Arc::clone(&resume);
            let root_worker = root.clone();
            scope.spawn(move || {
                let file_id = repo_path("a/b/file".to_string());
                let entries =
                    validated_source_entries([(&file_id, regular(), b"inside".as_slice())])
                        .unwrap();
                project_validated_source_tree(&root_worker, &entries, None, || {
                    ready_worker.wait();
                    resume_worker.wait();
                })
                .unwrap();
            });

            ready.wait();
            std::fs::remove_dir_all(root.join("a")).unwrap();
            symlink(&outside, root.join("a")).unwrap();
            resume.wait();
        });

        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert!(!outside.join("b/file").exists());
        assert_eq!(std::fs::read(root.join("a/b/file")).unwrap(), b"inside");
        assert!(!std::fs::symlink_metadata(root.join("a"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn nested_cleanup_parent_swap_fails_without_touching_symlink_target() {
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Barrier};

        let sandbox = tempfile::tempdir().unwrap();
        let root = sandbox.path().join("root");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(root.join("a/delete.txt"), b"inside old tree").unwrap();
        std::fs::write(outside.join("delete.txt"), b"outside sentinel").unwrap();

        let ready = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let result = std::thread::scope(|scope| {
            let ready_worker = Arc::clone(&ready);
            let resume_worker = Arc::clone(&resume);
            let root_worker = root.clone();
            let handle = scope.spawn(move || {
                let file_id = repo_path("tracked.txt".to_string());
                let entries =
                    validated_source_entries([(&file_id, regular(), b"tracked".as_slice())])
                        .unwrap();
                project_validated_source_tree(&root_worker, &entries, Some(&|_| false), || {
                    ready_worker.wait();
                    resume_worker.wait();
                })
            });

            ready.wait();
            std::fs::remove_dir_all(root.join("a")).unwrap();
            symlink(&outside, root.join("a")).unwrap();
            resume.wait();
            handle.join().unwrap()
        });

        assert!(result.is_err(), "a swapped cleanup parent must fail closed");
        assert_eq!(
            std::fs::read(outside.join("delete.txt")).unwrap(),
            b"outside sentinel"
        );
    }
}
