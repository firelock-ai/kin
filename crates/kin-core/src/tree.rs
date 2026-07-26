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
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, GraphStore, Hash256, OperationId, RepoPath,
    RepositoryCommitReceipt, RepositoryId, RepositoryTransaction, ResolvedTree, SemanticChangeId,
    TreeEntry,
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

/// Resolve the exact repository tree at one semantic change.
pub fn resolve_change_tree<G: GraphStore>(
    graph: &G,
    change_id: &SemanticChangeId,
) -> Result<ResolvedTree> {
    graph
        .resolve_tree_at(change_id)
        .map_err(|error| KinError::Graph(error.to_string()))
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
pub fn materialize_session_source_tree<'a>(
    root: &Path,
    base_metadata: &[u8],
    entries: impl IntoIterator<Item = (&'a RepoPath, TreeEntry, &'a [u8])>,
) -> Result<usize> {
    if base_metadata.is_empty() {
        return Err(KinError::Other(
            "session projection base metadata must not be empty".to_string(),
        ));
    }
    let entries: Vec<_> = entries.into_iter().collect();
    for (path, entry, body) in &entries {
        validate_source_content_identity(path, *entry, body)?;
    }
    let entries = validated_source_entries(entries)?;
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
    )?;
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
        || {},
        || {},
        Some(marker),
        || commit_repository_transaction_exact(authority, transaction),
    )
}

fn validate_repository_projection_transaction(
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    previous_entries: &[ValidatedSourceEntry<'_>],
    entries: &[ValidatedSourceEntry<'_>],
    transaction: &RepositoryTransaction,
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
    if mutation.new_tree_hash != target_tree_hash {
        return Err(KinError::Other(format!(
            "workspace mutation tree hash {} does not match requested projection tree {}",
            mutation.new_tree_hash, target_tree_hash
        )));
    }
    validate_projection_entries_match_tree("previous", previous_tree, previous_entries)?;
    validate_projection_entries_match_tree("target", target_tree, entries)?;
    Ok(())
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

/// Identity-bound proof that one complete [`ResolvedTree`] matched the working
/// projection while an [`ExactProjectionFreeze`] was held.
pub struct ExactProjectionVerification {
    tree_hash: Hash256,
    #[cfg(any(unix, windows))]
    entries: Vec<ExactProjectionVerifiedEntry>,
}

#[cfg(any(unix, windows))]
struct ExactProjectionVerifiedEntry {
    path: RepoPath,
    kind: TreeEntry,
    identity: TrackedEntryIdentity,
}

/// Retained, no-follow capability for an already-created eject archive.
///
/// Keeping this target alive prevents the final metadata move from reopening
/// an ambient destination path after verification.
pub struct ExactProjectionDetachTarget {
    #[cfg(any(unix, windows))]
    parent: cap_std::fs::Dir,
    #[cfg(any(unix, windows))]
    directory: cap_std::fs::Dir,
    #[cfg(any(unix, windows))]
    name: OsString,
    #[cfg(any(unix, windows))]
    identity: TrackedEntryIdentity,
    display_path: std::path::PathBuf,
}

impl std::fmt::Debug for ExactProjectionFreeze {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactProjectionFreeze")
            .finish_non_exhaustive()
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

impl ExactProjectionDetachTarget {
    /// Retain an already-created real directory without following its leaf.
    pub fn open_existing(path: &Path) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
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
            let directory = open_directory_nofollow(&parent, name)
                .map_err(|error| KinError::io(path, error))?;
            let identity = tracked_open_directory_identity(&directory)
                .map_err(|error| KinError::io(path, error))?;
            Ok(Self {
                parent,
                directory,
                name: name.to_os_string(),
                identity,
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
                        identity,
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

    /// Bounded-memory variant of [`Self::verify_resolved_tree`] that reads one
    /// exact body at a time from a content-addressed blob store.
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
                validate_projection_proof_entry_path(&artifact.path, artifact.entry)?;
                let content = load_projection_proof_blob(blobs, &artifact.path, artifact.entry)?;
                let entry = ValidatedSourceEntry {
                    file_id: &artifact.path,
                    kind: artifact.entry,
                    content: &content,
                };
                let identity = self.projection.validate_frozen_entry_unchanged(&entry)?;
                verified.push(ExactProjectionVerifiedEntry {
                    path: artifact.path.clone(),
                    kind: artifact.entry,
                    identity,
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
                .map(|entry| entry.identity)
                .collect::<Vec<_>>();
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
                let path = validate_projection_proof_entry_path(&artifact.path, artifact.entry)?;
                let content = load_projection_proof_blob(blobs, &artifact.path, artifact.entry)?;
                let entry = ValidatedSourceEntry {
                    file_id: &artifact.path,
                    kind: artifact.entry,
                    content: &content,
                };
                let identity = self.projection.validate_frozen_entry_unchanged(&entry)?;
                if identity != verified.identity {
                    return Err(KinError::Other(format!(
                        "tracked working-copy path {} changed object identity after exact projection verification",
                        self.projection.display_root.join(path.relative).display()
                    )));
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

    #[cfg(any(unix, windows))]
    fn detach_after_revalidation(
        self,
        target: &ExactProjectionDetachTarget,
        destination_name: &std::ffi::OsStr,
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
            )
    }

    #[cfg(any(unix, windows))]
    fn revalidate_namespace(&self) -> Result<()> {
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
        self.projection.revalidate_projection_lock()
    }
}

fn commit_repository_transaction_exact(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<RepositoryCommitReceipt> {
    let expected_hash = transaction
        .transaction_hash()
        .map_err(|error| KinError::Other(error.to_string()))?;
    match authority.commit_repository_transaction(transaction.clone()) {
        Ok(receipt) => Ok(receipt),
        Err(first_error) => {
            let exact_operation_is_visible = authority
                .read_authority()
                .metadata()
                .operation_log
                .iter()
                .find(|operation| operation.operation_id == transaction.operation_id)
                .is_some_and(|operation| operation.transaction_hash == expected_hash);
            if !exact_operation_is_visible {
                return Err(KinError::Other(format!(
                    "commit repository projection authority: {first_error}"
                )));
            }
            authority
                .commit_repository_transaction(transaction)
                .map_err(|error| {
                    KinError::Other(format!(
                        "recover exact repository projection receipt after durable commit: {error}"
                    ))
                })
        }
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

fn validate_projection_proof_entry_path(
    file_id: &RepoPath,
    kind: TreeEntry,
) -> Result<ValidatedProjectionPath> {
    if matches!(kind, TreeEntry::Gitlink { .. }) {
        return Err(KinError::Other(format!(
            "gitlink {file_id} is repository history, not a materialized working-copy object"
        )));
    }
    validate_projection_proof_path(file_id)
}

fn validate_projection_proof_paths<'a>(
    paths: impl IntoIterator<Item = &'a RepoPath>,
) -> Result<()> {
    let mut paths = paths
        .into_iter()
        .map(|path| {
            validate_projection_proof_path(path)?;
            let key = if let Some(path) = path.as_utf8() {
                projection_path_comparison_key(path).into_bytes()
            } else {
                let mut key = path.as_bytes().to_vec();
                #[cfg(any(windows, target_os = "macos"))]
                key.make_ascii_lowercase();
                key
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
        after_read_only_preflight,
        after_identity_revalidation,
        None,
        || Ok(()),
    )
    .map(|(count, ())| count)
}

#[allow(clippy::too_many_arguments)]
fn project_reconciled_source_tree_and_commit<T>(
    root: &Path,
    previous_entries: &[ValidatedSourceEntry<'_>],
    entries: &[ValidatedSourceEntry<'_>],
    should_preserve: &dyn Fn(&Path) -> bool,
    after_read_only_preflight: impl FnOnce(),
    after_identity_revalidation: impl FnOnce(),
    authority_commit: Option<ReconciliationAuthorityCommit>,
    commit: impl FnOnce() -> Result<T>,
) -> Result<(usize, T)> {
    #[cfg(any(unix, windows))]
    {
        let projection = ProjectionRoot::open(root)?;
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
                target_by_path
                    .get(previous_entry.file_id)
                    .is_none_or(|target_entry| !source_entries_match(previous_entry, target_entry))
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
                previous_by_path
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
        let preflight_previous = if authority_commit.is_some() {
            previous_entries.iter().collect::<Vec<_>>()
        } else {
            affected_previous.clone()
        };
        let preflight_identities =
            projection.validate_tracked_entries_unchanged(&preflight_previous)?;
        let identity_by_path = preflight_previous
            .iter()
            .zip(&preflight_identities)
            .map(|(entry, identity)| (entry.file_id, *identity))
            .collect::<HashMap<_, _>>();
        let previous_identities = affected_previous
            .iter()
            .map(|entry| {
                identity_by_path
                    .get(entry.file_id)
                    .copied()
                    .expect("affected entry was included in exact-source preflight")
            })
            .collect::<Vec<_>>();
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
        projection
            .revalidate_tracked_entries_unchanged(&preflight_previous, &preflight_identities)?;
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
        let mut transaction =
            projection.create_reconciliation_transaction_with_authority_commit(authority_commit)?;
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

        // Tests exercise the final namespace race here. Every later removal is
        // a compare-and-swap: the named object is first moved into the retained
        // transaction, then its exact preflight identity/kind/content is
        // verified before any replacement can publish.
        after_identity_revalidation();

        let mut created_directories = Vec::new();
        let mut removed_directories = Vec::new();

        let mutation_result: Result<()> = (|| {
            for (name_index, (entry, identity)) in affected_previous
                .iter()
                .zip(&previous_identities)
                .enumerate()
            {
                projection.displace_previous_entry(
                    &mut transaction,
                    **entry,
                    *identity,
                    name_index,
                )?;
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
            Ok(committed) => committed,
            Err(error) => {
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
        };

        projection
            .cleanup_reconciliation_transaction(transaction)
            .map_err(|error| {
                KinError::Other(format!(
                    "repository authority committed but exact-source transaction cleanup failed; \
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
            after_read_only_preflight,
            after_identity_revalidation,
            authority_commit,
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
    repository_authority_kindb: Option<PathBuf>,
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
    #[cfg(all(test, unix))]
    relative: PathBuf,
    #[cfg(all(test, unix))]
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
impl ProjectionRoot {
    fn open(root: &Path) -> Result<Self> {
        Self::open_with_projection_lock_deadline(root, PROJECTION_LOCK_WAIT_DEADLINE)
    }

    fn open_session(root: &Path) -> Result<Self> {
        Self::open_with_control_directory(
            root,
            std::ffi::OsStr::new(SESSION_PROJECTION_CONTROL_DIRECTORY),
            None,
            PROJECTION_LOCK_WAIT_DEADLINE,
        )
    }

    fn open_with_projection_lock_deadline(
        root: &Path,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        Self::open_with_control_directory(
            root,
            std::ffi::OsStr::new(".kin"),
            Some(root.join(".kin").join("kindb")),
            lock_deadline,
        )
    }

    fn open_with_control_directory(
        root: &Path,
        projection_control_name: &std::ffi::OsStr,
        repository_authority_kindb: Option<PathBuf>,
        lock_deadline: std::time::Duration,
    ) -> Result<Self> {
        let capability = open_projection_root_nofollow(root)?;
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
            repository_authority_kindb,
            kin_control_identity,
            control_identity,
            authority_key,
        };
        projection.recover_reconciliation_transactions()?;
        Ok(projection)
    }

    fn open_existing_for_freeze(root: &Path, lock_deadline: std::time::Duration) -> Result<Self> {
        let capability = open_projection_root_nofollow(root)?;
        let kin_control = open_directory_nofollow(&capability, std::ffi::OsStr::new(".kin"))
            .map_err(|error| KinError::io(root.join(".kin"), error))?;
        let kin_control_identity = tracked_open_directory_identity(&kin_control)
            .map_err(|error| KinError::io(root.join(".kin"), error))?;
        let display_control = root.join(".kin").join(RECONCILIATION_CONTROL_DIRECTORY);
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
            kin_control_identity,
            control_identity,
            authority_key,
        };
        projection.revalidate_projection_lock()?;
        projection.refuse_reconciliation_transactions()?;
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

    fn create_reconciliation_transaction(&self) -> Result<ReconciliationTransaction> {
        self.create_reconciliation_transaction_with_authority_commit(None)
    }

    fn create_reconciliation_transaction_with_authority_commit(
        &self,
        authority_commit: Option<ReconciliationAuthorityCommit>,
    ) -> Result<ReconciliationTransaction> {
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
        // Read-only identity check, matching the control-root open above.
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

    fn repository_authority_commit_is_installed(
        &self,
        marker: &ReconciliationAuthorityCommit,
    ) -> Result<bool> {
        let authority_kindb = self.repository_authority_kindb.as_ref().ok_or_else(|| {
            KinError::Other(format!(
                "session projection recovery at {} unexpectedly contains a repository-authority commit marker",
                self.display_root.display()
            ))
        })?;
        let manager = RepositoryAuthorityManager::open(
            marker.repository_id.clone(),
            Arc::new(LocalFileBackend::new(authority_kindb)),
        )
        .map_err(|error| {
            KinError::Other(format!(
                "open repository authority while recovering exact-source projection: {error}"
            ))
        })?;
        let lease = manager.read_authority();
        let Some(operation) = lease
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
                Some(marker) => self.repository_authority_commit_is_installed(marker)?,
                None => false,
            };
            if authority_committed {
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
                        return Err(KinError::Other(format!(
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
                        return Err(KinError::Other(format!(
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
                    return Err(KinError::Other(format!(
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
                    return Err(KinError::Other(format!(
                        "untracked working-copy directory {} blocks exact workspace reconciliation",
                        self.display_root.join(&relative).display()
                    )));
                }
                let child = self.open_existing_directory(directory, &name, &relative)?;
                self.validate_removable_directory_contents(&child, &relative, removed)?;
            } else if removed.relation(&relative) != TrackedPathRelation::Exact {
                return Err(KinError::Other(format!(
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
                return Err(KinError::Other(format!(
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
                return Err(KinError::Other(format!(
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
                    return Err(KinError::Other(format!(
                        "exact-source object {} changed kind",
                        display.display()
                    )));
                }
                #[cfg(windows)]
                if metadata_is_reparse(&metadata) {
                    return Err(KinError::Other(format!(
                        "exact-source object {} became a reparse point",
                        display.display()
                    )));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    if (metadata.permissions().mode() & 0o111 != 0) != executable {
                        return Err(KinError::Other(format!(
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
                    return Err(KinError::Other(format!(
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
                        return Err(KinError::Other(format!(
                            "exact-source object {} changed kind",
                            display.display()
                        )));
                    }
                    let target = rustix::fs::readlinkat(parent, name, Vec::new())
                        .map_err(|error| KinError::io(display, error.into()))?;
                    if target.as_bytes() != entry.content {
                        return Err(KinError::Other(format!(
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
            #[cfg(all(test, unix))]
            relative: relative.to_path_buf(),
            #[cfg(all(test, unix))]
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

    fn validate_tracked_entry_unchanged_at_path(
        &self,
        entry: &ValidatedSourceEntry<'_>,
        path: &ValidatedProjectionPath,
    ) -> Result<TrackedEntryIdentity> {
        let display = self.display_root.join(&path.relative);
        let conflict = |reason: &str| {
            KinError::Other(format!(
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
        RefName, ResolvedArtifact, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    fn repo_path(path: impl Into<String>) -> RepoPath {
        RepoPath::from_utf8(path).expect("test repository path must be valid")
    }

    fn regular() -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false)
    }

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
            || {},
            || {},
            None,
            || -> Result<()> {
                Err(KinError::Other(
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
    fn recovery_keeps_projection_when_exact_authority_operation_committed() {
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
        };
        let marker = ReconciliationAuthorityCommit {
            repository_id: transaction.repository_id.clone(),
            operation_id: transaction.operation_id,
            transaction_hash: transaction.transaction_hash().unwrap(),
        };
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
                || {},
                || {},
                Some(marker),
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

        drop(ProjectionRoot::open(root.path()).unwrap());

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
        let contender = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let opened = ProjectionRoot::open_with_projection_lock_deadline(
                &contender_root,
                std::time::Duration::from_secs(10),
            );
            (opened.map(|_| ()), started.elapsed())
        });

        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(first);

        let (opened, waited) = contender.join().unwrap();
        opened.expect("the contender must acquire once the holder releases");
        assert!(
            waited >= std::time::Duration::from_millis(250),
            "the contender should have genuinely waited, waited {waited:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(10),
            "the contender must not burn the full deadline once the lock frees"
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
