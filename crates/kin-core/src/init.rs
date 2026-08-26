// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt as _;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_git::SealedContentSource;
use kin_model::{
    compute_resolved_tree_hash, AdmissionCase, AdmissionPolicyDelta, AuthorId,
    DefaultRefExpectation, DefaultRefMutation, EffectiveAdmissionPolicyStamp, ExternalObjectId,
    ExternalObjectKind, FrozenLocalOverlay, FrozenLocalOverlayDelta, GitMaterialHead, GitRawTarget,
    Hash256, OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryAuthorityStore, RepositoryCommitReceipt, RepositoryId, RepositoryTransaction,
    RootBundle, SemanticChange, SemanticChangeId, SharedAdmissionPolicy, WorkspaceExpectation,
    WorkspaceHead, WorkspaceId, WorkspaceMutation, WorkspaceSemanticDelta,
    WorkspaceSnapshotBinding, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use tracing::debug;
use tracing::{info, info_span};

use crate::config::KinConfig;
use crate::error::{KinError, Result};
use crate::layout::{KinLayout, KIN_LAYOUT_VERSION};
use crate::manifest::KinManifest;

const INIT_STAGE_PREFIX: &str = ".kin.init-";
const INIT_STAGE_OWNER_SUFFIX: &str = ".owner";
const INIT_STAGE_OWNER_SCHEMA_VERSION: u32 = 1;
const MAX_INIT_STAGE_OWNER_BYTES: u64 = 16 * 1024;

/// Result of creating a repository authority envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct RepositoryBootstrap {
    pub receipt: RepositoryCommitReceipt,
    pub workspace: WorkspaceSnapshotBinding,
    /// Generation-bound durable semantic counts computed from the exact
    /// committed bootstrap lease before publication. `kin init` carries this
    /// value forward instead of reopening a potentially advanced repository.
    pub semantic_enrichment: crate::DurableSemanticEnrichmentSummary,
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
    /// Exact material workspace HEAD established by initialization.
    ///
    /// Symbolic targets retain byte-exact `RefName` identity. Detached Git
    /// annotated tags are represented by their verified peeled commit; their
    /// exact raw tag target remains in `GitExternalAuthority`.
    pub head: WorkspaceHead,
    pub authority: RepositoryBootstrap,
    /// Source paths initialization observed differing from the state it
    /// admitted, disclosed rather than admitted.
    ///
    /// Always empty for an unborn native repository, which has no source to
    /// differ from.
    pub workspace_divergence: kin_git::GitWorkspaceDivergenceFacts,
}

#[derive(Clone)]
struct RepositoryMetadataSeal {
    config_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    config_hash: Hash256,
    manifest_hash: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", content = "units", rename_all = "snake_case")]
enum ExactPathIdentity {
    UnixBytes(Vec<u8>),
    WindowsWide(Vec<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
enum RecoverableFileIdentity {
    Unix {
        device: u64,
        inode: u64,
    },
    Windows {
        volume_serial_number: u32,
        file_index: u64,
    },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInitStageOwner {
    schema_version: u32,
    stage_id: String,
    stage_path: ExactPathIdentity,
    destination_path: ExactPathIdentity,
    repository_id: String,
    workspace_id: String,
    stage_identity: RecoverableFileIdentity,
}

struct RepositoryInitStageLease {
    owner_path: PathBuf,
    owner_file: File,
    record: RepositoryInitStageOwner,
}

/// One-shot authority to install a verified stage at its bound `.kin` path.
///
/// The constructor is private. A source verifier receives this capability only
/// after staged repository authority has been durably synced, closed, reopened,
/// and verified. Consuming it performs the atomic no-replace rename.
#[must_use = "repository publication must be consumed or explicitly rejected"]
pub struct RepositoryPublication<'a> {
    staged_path: &'a Path,
    final_kin_dir: &'a Path,
    published: &'a Cell<bool>,
}

/// Proof that the one-shot repository publication rename succeeded.
#[must_use = "a published repository should be post-verified before returning"]
pub struct PublishedRepository<'a> {
    final_kin_dir: &'a Path,
}

impl<'a> RepositoryPublication<'a> {
    pub fn publish(self) -> Result<PublishedRepository<'a>> {
        rename_directory_noreplace(self.staged_path, self.final_kin_dir)?;
        self.published.set(true);
        Ok(PublishedRepository {
            final_kin_dir: self.final_kin_dir,
        })
    }
}

impl PublishedRepository<'_> {
    pub fn path(&self) -> &Path {
        self.final_kin_dir
    }
}

/// One staging-store write session, scoped to the repository that opened it.
///
/// A save publishes the body under its content identity with the same
/// validation and no-clobber rules a single
/// [`PreparedRepositoryInit::save_source_blob`] applies. Durability arrives
/// when the enclosing
/// [`with_source_blob_batch`](PreparedRepositoryInit::with_source_blob_batch)
/// returns, not per body.
pub struct StagedSourceBlobBatch<'a> {
    inner: &'a dyn kin_db::SourceBlobWriteBatch,
}

impl StagedSourceBlobBatch<'_> {
    /// Stage exact bytes under their content identity.
    pub fn save(&self, digest: Hash256, data: &[u8]) -> Result<()> {
        self.inner
            .save(*digest.as_bytes(), data)
            .map_err(graph_error)
    }
}

/// A complete `.kin` repository assembled outside the final namespace.
///
/// The staging directory is private to this object and is removed on drop
/// unless [`publish_repository_layout`] atomically installs it. Authority
/// mutations can be committed only through [`Self::commit_repository_bootstrap`],
/// which binds the first transaction to the exact generation-zero roots
/// created here and supports exact-operation retry after an uncertain durable
/// write.
pub struct PreparedRepositoryInit {
    layout: KinLayout,
    final_kin_dir: PathBuf,
    config: KinConfig,
    manifest: KinManifest,
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
    default_ref: RefName,
    initial_roots: RootBundle,
    metadata_seal: RepositoryMetadataSeal,
    authority: Option<RepositoryAuthorityManager<LocalFileBackend>>,
    bootstrap: Option<RepositoryBootstrap>,
    stage_lease: Option<RepositoryInitStageLease>,
    cleanup_armed: bool,
}

impl std::fmt::Debug for PreparedRepositoryInit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRepositoryInit")
            .field("layout", &self.layout)
            .field("final_kin_dir", &self.final_kin_dir)
            .field("repository_id", &self.repository_id)
            .field("workspace_id", &self.workspace_id)
            .field("default_ref", &self.default_ref)
            .field("initial_roots", &self.initial_roots)
            .field("config_hash", &self.metadata_seal.config_hash)
            .field("manifest_hash", &self.metadata_seal.manifest_hash)
            .field("bootstrap", &self.bootstrap)
            .field("cleanup_armed", &self.cleanup_armed)
            .finish_non_exhaustive()
    }
}

impl PreparedRepositoryInit {
    pub fn config(&self) -> &KinConfig {
        &self.config
    }

    pub fn manifest(&self) -> &KinManifest {
        &self.manifest
    }

    pub fn repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn default_ref(&self) -> &RefName {
        &self.default_ref
    }

    pub fn initial_roots(&self) -> &RootBundle {
        &self.initial_roots
    }

    /// Persist immutable source bytes inside the unpublished staging store.
    ///
    /// Saving a body does not grant it repository authority. A later bootstrap
    /// transaction must reference the digest through exact tree/history
    /// authority before publication.
    pub fn save_source_blob(&self, digest: Hash256, data: &[u8]) -> Result<()> {
        self.authority()?
            .save_source_blob(digest, data)
            .map_err(graph_error)
    }

    /// Persist many immutable source bodies under one authority envelope.
    ///
    /// This is the bulk form of [`Self::save_source_blob`] and it stages
    /// exactly the same bodies. It grants no authority either: a later
    /// bootstrap transaction still has to reference every digest through
    /// exact tree and history authority before publication. The bodies are
    /// durable when this call returns, which is what lets a whole capture
    /// copy run as one session and cross into bootstrap afterwards.
    pub fn with_source_blob_batch(
        &self,
        operation: &mut dyn FnMut(&StagedSourceBlobBatch<'_>) -> Result<()>,
    ) -> Result<()> {
        let authority = self.authority()?;
        // The batch boundary speaks kin-db's error type. Carry the caller's
        // own failure out beside it so a Git or manifest boundary error is
        // reported as itself rather than as a storage error.
        let mut interrupted: Option<KinError> = None;
        let outcome = authority.with_source_blob_write_batch(&mut |inner| match operation(
            &StagedSourceBlobBatch { inner },
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                interrupted = Some(error);
                Err(kin_db::KinDbError::StorageError(
                    "staged source ingest stopped before its batch completed".to_string(),
                ))
            }
        });
        if let Some(error) = interrupted {
            return Err(error);
        }
        outcome.map_err(graph_error)
    }

    /// Read immutable source bytes back out of the unpublished staging store.
    ///
    /// This is the read side of [`Self::save_source_blob`], and it exists so
    /// admission can prove the staged repository owns every body its admitted
    /// trees reference before that repository is published.
    pub fn load_source_blob(&self, digest: Hash256) -> Result<Option<Vec<u8>>> {
        self.authority()?
            .load_source_blob(digest)
            .map_err(graph_error)
    }

    /// Commit exactly one complete generation-zero to generation-one
    /// repository transition.
    ///
    /// Repeating the exact transaction returns the existing bootstrap. A
    /// different transaction is rejected once bootstrap authority exists.
    pub fn commit_repository_bootstrap(
        &mut self,
        transaction: RepositoryTransaction,
    ) -> Result<&RepositoryBootstrap> {
        verify_metadata_seal(&self.layout, &self.metadata_seal)?;
        let operation_id = transaction.operation_id;
        let repository_id = &self.repository_id;
        let workspace_id = self.workspace_id;
        let default_ref = &self.default_ref;
        let initial_roots = &self.initial_roots;
        let authority = self.authority.as_ref().ok_or_else(|| {
            KinError::Other("staged repository authority is no longer open".to_string())
        })?;
        match &mut self.bootstrap {
            Some(bootstrap) => {
                // Hashed here rather than before the match, because only this arm
                // reads it. `transaction_hash` canonicalizes by cloning the whole
                // transaction, which carries every reachable external object and
                // every change in history, so on a real repository it is the
                // largest single allocation in the commit and it retains nothing.
                // The first-commit arm below never used the value and paid for it
                // on every init, and it also validated twice, once here and once
                // in `validate_bootstrap_transaction`.
                let transaction_hash = transaction
                    .transaction_hash()
                    .map_err(|error| KinError::Other(error.to_string()))?;
                if bootstrap.receipt.transaction_hash != transaction_hash
                    || bootstrap.receipt.operation_id != operation_id
                {
                    return Err(KinError::Other(
                        "staged repository already has a different bootstrap transaction"
                            .to_string(),
                    ));
                }
                Ok(bootstrap)
            }
            slot @ None => {
                {
                    crate::report_admission_progress("validating transaction");
                    let _span = info_span!("kin.init.commit.validate_bootstrap").entered();
                    validate_bootstrap_transaction(
                        &transaction,
                        repository_id,
                        workspace_id,
                        default_ref,
                        initial_roots,
                    )?;
                }
                let bootstrap = commit_bootstrap_transaction(
                    authority,
                    transaction,
                    repository_id,
                    workspace_id,
                )?;
                if bootstrap.receipt.generation != 1
                    || bootstrap.receipt.roots_before != *initial_roots
                {
                    return Err(KinError::Graph(
                        "repository bootstrap did not produce the exact generation-zero to generation-one transition"
                            .to_string(),
                    ));
                }
                Ok(slot.insert(bootstrap))
            }
        }
    }

    fn authority(&self) -> Result<&RepositoryAuthorityManager<LocalFileBackend>> {
        self.authority.as_ref().ok_or_else(|| {
            KinError::Other("staged repository authority is no longer open".to_string())
        })
    }
}

/// Graph-owned repository content, exposed to sealed observation.
///
/// The wrapper deliberately narrows a full authority manager down to the single
/// capability an observation needs: resolve a content identity to the bytes the
/// repository already owns. An observation therefore cannot reach the working
/// tree, the ambient object store, or any other authority surface.
pub struct GraphOwnedContent<'a>(&'a RepositoryAuthorityManager<LocalFileBackend>);

impl<'a> GraphOwnedContent<'a> {
    pub const fn new(authority: &'a RepositoryAuthorityManager<LocalFileBackend>) -> Self {
        Self(authority)
    }
}

impl SealedContentSource for GraphOwnedContent<'_> {
    fn load_sealed_content(&self, digest: Hash256) -> std::result::Result<Vec<u8>, String> {
        match self.0.load_source_blob(digest) {
            Ok(Some(body)) => Ok(body),
            Ok(None) => Err("the repository owns no body for this content identity".to_string()),
            Err(error) => Err(error.to_string()),
        }
    }
}

impl SealedContentSource for PreparedRepositoryInit {
    fn load_sealed_content(&self, digest: Hash256) -> std::result::Result<Vec<u8>, String> {
        match self.load_source_blob(digest) {
            Ok(Some(body)) => Ok(body),
            Ok(None) => {
                Err("the staged repository owns no body for this content identity".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

impl Drop for PreparedRepositoryInit {
    fn drop(&mut self) {
        if self.cleanup_armed {
            // Released before the stage is removed, not alongside it. Fields
            // drop only after this body returns, so leaving the authority in
            // place here would mean removing a directory its backend still
            // holds open. Unix allows that and Windows does not, which would
            // leave the stage behind on the platform where a failed init most
            // needs to clean up after itself.
            drop(self.authority.take());
            if let Some(lease) = self.stage_lease.take() {
                cleanup_staging_layout(lease, &self.layout, &self.manifest);
            }
        }
    }
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
    init_with_config(
        working_dir,
        KinConfig::default(),
        KinManifest::new(),
        RepositoryIdentityOrigin::Minted,
    )
}

/// Initialize a repository that will adopt a remote's history over a native
/// clone.
///
/// A clone learns the remote's default ref from the ref advertisement before
/// any history arrives, so the replica is created against that ref rather than
/// the local configuration default. Synthesizing `main` for a remote that does
/// not publish it would leave a ghost ref no import can ever reconcile.
///
/// Like [`init`], this admits no history. The replica holds no changes until
/// the caller imports them, so it stays byte-comparable with the remote at
/// first contact.
///
/// # Errors
///
/// Returns `KinError::AlreadyInitialized` if `.kin/` already exists, and fails
/// loud if `default_branch` is not a valid ref name.
pub fn init_replica(working_dir: &Path, default_branch: &str) -> Result<InitResult> {
    init_with_config(
        working_dir,
        replica_config(default_branch),
        KinManifest::new(),
        RepositoryIdentityOrigin::Minted,
    )
}

/// Initialize a repository that adopts an existing repository identity instead
/// of minting one, admitting no history.
///
/// The native-boundary sibling of [`crate::init_from_git_adopting`]. Both exist
/// for the same reason: every exact-transfer surface is identity-exact, so a
/// store meant to publish into a repository that already exists has to carry
/// that repository's identity from the moment it is created. Relabelling later
/// is not available, because the identity is recorded in the committed
/// authority metadata and in every external-change alias a pack carries.
///
/// # Errors
///
/// Returns `KinError::AlreadyInitialized` if `.kin/` already exists, and
/// refuses an identity the local store cannot be keyed by. See
/// [`RepositoryIdentityOrigin::Adopted`] for what that admits.
pub fn init_adopting(working_dir: &Path, repository_id: &RepositoryId) -> Result<InitResult> {
    refuse_adoption_over_existing_replica(working_dir, repository_id.as_str())?;
    init_with_config(
        working_dir,
        KinConfig::default(),
        KinManifest::adopting(repository_id.as_str()),
        RepositoryIdentityOrigin::Adopted,
    )
}

/// Initialize a replica that adopts an existing repository identity instead of
/// minting one.
///
/// Two replicas can only exchange history when they are replicas of the same
/// repository: the ref advertisement, the transfer expectation, and pack
/// admission all refuse an identity other than the one the receiving authority
/// records. A replica that minted its own identity is therefore unreachable
/// from the repository it was cloned from, which is why this exists.
///
/// `repository_id` must be the identity the remote published over the native
/// transport, and it is written into the manifest verbatim. The workspace
/// identity is still minted here, because repository truth is shared between
/// replicas and local workspace/session authority never is.
///
/// This admits no history. Adoption is not proven by writing the manifest; it
/// is proven when the remote's history is admitted into this replica under the
/// adopted identity and the committed authority is read back and agrees. See
/// `kin_remote::repository_transfer_negotiation::verify_adopted_replica_identity`.
///
/// # Errors
///
/// Refuses a directory that already holds a Kin repository, naming the identity
/// already there alongside the one being adopted, so an adoption never
/// re-identifies an existing replica. Refuses an identity the local store
/// cannot be keyed by; see [`RepositoryIdentityOrigin::Adopted`].
pub fn init_replica_adopting(
    working_dir: &Path,
    default_branch: &str,
    repository_id: &RepositoryId,
) -> Result<InitResult> {
    let adopted = repository_id.as_str();
    refuse_adoption_over_existing_replica(working_dir, adopted)?;
    init_with_config(
        working_dir,
        replica_config(default_branch),
        KinManifest::adopting(adopted),
        RepositoryIdentityOrigin::Adopted,
    )
}

fn replica_config(default_branch: &str) -> KinConfig {
    KinConfig {
        default_branch: default_branch.to_string(),
        ..KinConfig::default()
    }
}

/// Report what is already at `working_dir` before an adoption reaches init.
///
/// [`init_with_config`] refuses an existing `.kin/` on its own and remains the
/// check that decides. This runs first only so the refusal names both
/// identities: a caller who ran a clone into an existing replica needs to know
/// which repository is already there, and `AlreadyInitialized` carries a path
/// alone. A manifest that cannot be read falls through to that generic refusal
/// rather than inventing a reason.
fn refuse_adoption_over_existing_replica(working_dir: &Path, adopted: &str) -> Result<()> {
    let Ok(canonical_working_dir) = working_dir.canonicalize() else {
        return Ok(());
    };
    let layout = KinLayout::new(canonical_working_dir.join(".kin"));
    let Ok(existing) = KinManifest::load(&layout.manifest_path()) else {
        return Ok(());
    };
    if existing.repo_id == adopted {
        return Err(KinError::AlreadyInitialized(format!(
            "{} already holds repository {adopted}",
            canonical_working_dir.display()
        )));
    }
    Err(KinError::AlreadyInitialized(format!(
        "{} already holds repository {}, and adopting {adopted} would re-identify it. Clone into \
         an empty directory instead",
        canonical_working_dir.display(),
        existing.repo_id
    )))
}

fn init_with_config(
    working_dir: &Path,
    config: KinConfig,
    manifest: KinManifest,
    origin: RepositoryIdentityOrigin,
) -> Result<InitResult> {
    let canonical_working_dir = working_dir
        .canonicalize()
        .map_err(|error| KinError::io(working_dir, error))?;
    let kin_dir = canonical_working_dir.join(".kin");
    match std::fs::symlink_metadata(&kin_dir) {
        Ok(_) => {
            return Err(KinError::AlreadyInitialized(
                canonical_working_dir.display().to_string(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(KinError::io(&kin_dir, error)),
    }

    let staging_parent = canonical_working_dir.parent().ok_or_else(|| {
        KinError::Other(format!(
            "repository root has no parent for atomic staging: {}",
            canonical_working_dir.display()
        ))
    })?;
    let staging_dir = staging_parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
    let admission_case = detect_admission_case(&canonical_working_dir)?;
    let mut prepared =
        prepare_repository_layout_with_origin(&staging_dir, &kin_dir, config, manifest, origin)?;
    let transaction = build_repository_bootstrap_transaction(
        prepared.initial_roots().clone(),
        prepared.repository_id().clone(),
        prepared.workspace_id(),
        admission_case,
        prepared.default_ref().clone(),
        SharedAdmissionPolicy::empty(0),
        None,
    )?;
    prepared.commit_repository_bootstrap(transaction)?;
    let result = publish_repository_layout(prepared)?;

    info!(
        path = %canonical_working_dir.display(),
        repository = %result.repository_id,
        workspace = %result.workspace_id,
        head = ?result.head,
        "initialized unborn kin repository authority"
    );

    Ok(result)
}

fn detect_admission_case(workspace_root: &Path) -> Result<AdmissionCase> {
    let probe = tempfile::Builder::new()
        .prefix(".kin-case-probe-a-")
        .tempfile_in(workspace_root)
        .map_err(|error| KinError::io(workspace_root, error))?;
    let name = probe
        .path()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| KinError::Other("case probe produced a non-UTF-8 file name".to_string()))?;
    let folded_name = name.replacen(".kin-case-probe-a-", ".kin-case-probe-A-", 1);
    if folded_name == name {
        return Err(KinError::Other(
            "case probe could not construct a distinct ASCII-folded path".to_string(),
        ));
    }
    match std::fs::symlink_metadata(workspace_root.join(folded_name)) {
        Ok(_) => Ok(AdmissionCase::FoldAscii),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AdmissionCase::Sensitive),
        Err(error) => Err(KinError::io(workspace_root, error)),
    }
}

/// Where a repository identity being staged came from.
///
/// The two cases carry different obligations and always have; only one of them
/// used to be reachable. A minted identity is this build's own choice, so it is
/// held to the shape this build mints: a UUID v4, which is what keeps two
/// repositories created independently from ever colliding. An adopted identity
/// was chosen by the repository this replica is joining, and refusing it for
/// not looking locally minted refuses the whole point of adoption. `RepositoryId`
/// says so itself: "Hosted slugs and UUID text are both valid".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryIdentityOrigin {
    /// Minted here. Must be a UUID v4.
    Minted,
    /// Taken verbatim from the repository this replica joins. Must be one
    /// portable filesystem component, because a local store is a directory
    /// named by its repository id (`{base}/{repo_id}/authority.json` in
    /// `kin-db`'s `LocalFileBackend`), so an identity carrying a separator or a
    /// parent reference would name storage outside the store.
    Adopted,
}

/// Refuse an adopted identity the local store cannot be keyed by.
///
/// `RepositoryId` admits any non-control text up to 255 bytes, which is right
/// for a wire identity and wrong for one that also names a directory. kin-db's
/// `validate_source_blob_repo_id` refuses the unsafe shapes at the storage
/// layer and would refuse these too; this runs first so the refusal names the
/// identity the operator typed rather than surfacing from under a staged
/// layout. Every hosted slug in use clears it.
fn require_storable_adopted_identity(adopted: &str) -> Result<()> {
    let portable = !adopted.is_empty()
        && adopted.len() <= 255
        && !matches!(adopted, "." | "..")
        && !adopted.ends_with(['.', ' '])
        && adopted
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !portable {
        return Err(KinError::Config(format!(
            "repository identity {adopted:?} cannot be adopted: a local store is a directory \
             named by its repository id, so an adopted identity must be one portable filesystem \
             component of ASCII letters, digits, dot, underscore or hyphen"
        )));
    }
    Ok(())
}

/// Create a complete unpublished repository layout at an explicit staging
/// path. The path must be an absolute, direct child of an existing directory
/// and its name must begin with `.kin.init-`.
///
/// Stages a minted identity. Use [`prepare_repository_layout_with_origin`] to
/// stage one adopted from another replica.
pub fn prepare_repository_layout_at(
    staging_kin_dir: &Path,
    final_kin_dir: &Path,
    config: KinConfig,
    manifest: KinManifest,
) -> Result<PreparedRepositoryInit> {
    prepare_repository_layout_with_origin(
        staging_kin_dir,
        final_kin_dir,
        config,
        manifest,
        RepositoryIdentityOrigin::Minted,
    )
}

/// [`prepare_repository_layout_at`], saying where the identity came from.
///
/// Only the repository identity's admissible shape depends on `origin`.
/// Workspace identity is always minted here and always a UUID v4, because
/// repository truth is shared between replicas and local workspace authority
/// never is.
pub fn prepare_repository_layout_with_origin(
    staging_kin_dir: &Path,
    final_kin_dir: &Path,
    config: KinConfig,
    manifest: KinManifest,
    origin: RepositoryIdentityOrigin,
) -> Result<PreparedRepositoryInit> {
    config.validate()?;
    let repository_uuid = match origin {
        RepositoryIdentityOrigin::Minted => {
            let minted = uuid::Uuid::parse_str(&manifest.repo_id).map_err(|error| {
                KinError::Other(format!("invalid repository identity: {error}"))
            })?;
            if minted.get_version_num() != 4 {
                return Err(KinError::Other(
                    "repository manifest identity must be a UUID v4".to_string(),
                ));
            }
            Some(minted)
        }
        RepositoryIdentityOrigin::Adopted => {
            require_storable_adopted_identity(&manifest.repo_id)?;
            // Parsed only so the distinctness check below still fires when a
            // peer's identity happens to be UUID text. A slug parses as
            // nothing and can never equal a workspace identity that must.
            uuid::Uuid::parse_str(&manifest.repo_id).ok()
        }
    };
    let repository_id = RepositoryId::new(manifest.repo_id.clone())
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id)
        .map_err(|error| KinError::Other(format!("invalid workspace identity: {error}")))?;
    if workspace_uuid.get_version_num() != 4 {
        return Err(KinError::Other(
            "workspace manifest identity must be a UUID v4".to_string(),
        ));
    }
    if repository_uuid == Some(workspace_uuid) {
        return Err(KinError::Other(
            "repository and workspace manifest identities must be distinct".to_string(),
        ));
    }
    let workspace_id = WorkspaceId::from_uuid(workspace_uuid);
    let default_ref = RefName::branch(config.default_branch.as_bytes())
        .map_err(|error| KinError::Other(format!("invalid default ref: {error}")))?;
    let staging_root = canonical_staging_root(staging_kin_dir)?;
    let final_kin_dir = canonical_final_kin_dir(final_kin_dir)?;
    let staging_parent = staging_root
        .parent()
        .expect("canonical repository stage always has a parent");
    recover_orphaned_repository_stages(staging_parent, &final_kin_dir)?;

    create_private_staging_root(&staging_root)?;
    let layout = KinLayout::new(staging_root);
    let stage_lease = match create_repository_init_stage_lease(
        layout.root(),
        &final_kin_dir,
        &repository_id,
        workspace_id,
    ) {
        Ok(lease) => lease,
        Err(error) => {
            cleanup_created_staging_root(layout.root());
            return Err(error);
        }
    };
    let mut stage_lease = Some(stage_lease);
    let preparation = (|| {
        let authority_root = layout.kindb_dir();
        let backend = create_staged_repository_authority_backend(&authority_root)?;
        for directory in layout.all_dirs() {
            if directory == authority_root {
                continue;
            }
            std::fs::create_dir(&directory).map_err(|error| KinError::io(&directory, error))?;
        }
        crate::tree::initialize_projection_control_directory(layout.root())?;
        std::fs::write(layout.version_path(), KIN_LAYOUT_VERSION.to_string())
            .map_err(|error| KinError::io(layout.version_path(), error))?;
        config.save_initialization_stage(layout.root())?;
        manifest.save(&layout.manifest_path())?;
        let metadata_seal = capture_metadata_seal(&layout)?;

        let authority = RepositoryAuthorityManager::open(repository_id.clone(), backend)
            .map_err(graph_error)?;
        let initial_roots = authority.read_authority().roots().clone();
        if initial_roots.generation != 0 {
            return Err(KinError::Graph(
                "fresh staged repository did not open at generation zero".to_string(),
            ));
        }
        Ok(PreparedRepositoryInit {
            layout: layout.clone(),
            final_kin_dir,
            config,
            manifest: manifest.clone(),
            repository_id,
            workspace_id,
            default_ref,
            initial_roots,
            metadata_seal,
            authority: Some(authority),
            bootstrap: None,
            stage_lease: stage_lease.take(),
            cleanup_armed: true,
        })
    })();
    match preparation {
        Ok(prepared) => Ok(prepared),
        Err(error) => {
            if let Some(lease) = stage_lease.take() {
                cleanup_owned_staging_root(lease, layout.root());
            }
            Err(error)
        }
    }
}

fn create_private_staging_root(staging_root: &Path) -> Result<()> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder
        .create(staging_root)
        .map_err(|error| KinError::io(staging_root, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) =
            std::fs::set_permissions(staging_root, std::fs::Permissions::from_mode(0o700))
        {
            let _ = std::fs::remove_dir(staging_root);
            return Err(KinError::io(staging_root, error));
        }
    }
    Ok(())
}

/// Create and bind the local authority backend for one unpublished repository.
///
/// This is intentionally an initialization-only boundary. Reopen callers must
/// construct their backend from the already-published `kindb` root and fail
/// closed when that root is missing; they must never call this helper to repair
/// or recreate authority.
fn create_staged_repository_authority_backend(
    authority_root: &Path,
) -> Result<Arc<LocalFileBackend>> {
    create_private_staging_root(authority_root)?;
    let parent = authority_root.parent().ok_or_else(|| {
        KinError::Other(format!(
            "staged repository authority root has no parent: {}",
            authority_root.display()
        ))
    })?;
    sync_parent_directory(parent)?;

    let backend = Arc::new(LocalFileBackend::new(authority_root));
    backend.list_repos().map_err(graph_error)?;
    Ok(backend)
}

fn stage_id_from_directory_name(name: &str) -> Option<uuid::Uuid> {
    let raw = name.strip_prefix(INIT_STAGE_PREFIX)?;
    let id = uuid::Uuid::parse_str(raw).ok()?;
    (id.get_version_num() == 4 && id.to_string() == raw).then_some(id)
}

#[cfg(unix)]
fn stage_id_from_owner_name(name: &str) -> Option<uuid::Uuid> {
    let raw = name
        .strip_prefix(INIT_STAGE_PREFIX)?
        .strip_suffix(INIT_STAGE_OWNER_SUFFIX)?;
    let id = uuid::Uuid::parse_str(raw).ok()?;
    (id.get_version_num() == 4 && id.to_string() == raw).then_some(id)
}

fn stage_directory_name(stage_id: uuid::Uuid) -> String {
    format!("{INIT_STAGE_PREFIX}{stage_id}")
}

fn stage_owner_name(stage_id: uuid::Uuid) -> String {
    format!("{INIT_STAGE_PREFIX}{stage_id}{INIT_STAGE_OWNER_SUFFIX}")
}

/// Longest a concurrent recovery scan may hold the owner file this init just
/// created before the init gives up on it.
const OWN_STAGE_OWNER_LOCK_ATTEMPTS: u32 = 100;
const OWN_STAGE_OWNER_LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(5);

/// Whether a lock attempt was refused because someone else holds the lock.
///
/// The two platforms do not report contention as the same `ErrorKind`. Unix
/// `flock` fails with `EWOULDBLOCK`, which std maps to `WouldBlock`, while
/// Windows `LockFileEx` fails with `ERROR_LOCK_VIOLATION`, which std leaves
/// uncategorized because only the socket-level `WSAEWOULDBLOCK` maps to
/// `WouldBlock` there. Testing the kind alone therefore recognizes contention
/// on Unix and nothing on Windows, which silently turns the bounded retry in
/// `lock_own_stage_owner` into a single attempt. Comparing against the lock
/// crate's own contention error is what keeps this true on both.
fn is_lock_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || (error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

/// Take the exclusive lock on an owner file this call just created with
/// `create_new`, tolerating a concurrent recovery scan.
///
/// Every init recovers orphaned stages first, and that scan locks each sibling
/// owner file to decide whether it is abandoned. A scan that lands in the
/// window between this init creating its owner file and locking it holds the
/// lock for as long as it takes to read one record, and the init used to fail
/// outright on that. Contention on a file nobody else can name is transient by
/// construction, so it is retried; anything else, and contention that outlasts
/// the bound, still fails closed.
fn lock_own_stage_owner(owner_file: &File) -> std::io::Result<()> {
    let mut last = match owner_file.try_lock_exclusive() {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    for _ in 1..OWN_STAGE_OWNER_LOCK_ATTEMPTS {
        if !is_lock_contention(&last) {
            return Err(last);
        }
        std::thread::sleep(OWN_STAGE_OWNER_LOCK_RETRY);
        match owner_file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn create_repository_init_stage_lease(
    stage_root: &Path,
    final_kin_dir: &Path,
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
) -> Result<RepositoryInitStageLease> {
    let stage_id = stage_root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(stage_id_from_directory_name)
        .ok_or_else(|| {
            KinError::Other(format!(
                "cannot lease a non-canonical repository stage: {}",
                stage_root.display()
            ))
        })?;
    let parent = stage_root.parent().ok_or_else(|| {
        KinError::Other(format!(
            "repository stage has no parent: {}",
            stage_root.display()
        ))
    })?;
    let owner_path = parent.join(stage_owner_name(stage_id));
    let stage_metadata =
        std::fs::symlink_metadata(stage_root).map_err(|error| KinError::io(stage_root, error))?;
    let record = RepositoryInitStageOwner {
        schema_version: INIT_STAGE_OWNER_SCHEMA_VERSION,
        stage_id: stage_id.to_string(),
        stage_path: exact_path_identity(stage_root)?,
        destination_path: exact_path_identity(final_kin_dir)?,
        repository_id: repository_id.as_str().to_string(),
        workspace_id: workspace_id.to_string(),
        stage_identity: recoverable_path_identity(stage_root, &stage_metadata),
    };
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|error| KinError::Other(format!("serialize repository stage owner: {error}")))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_INIT_STAGE_OWNER_BYTES {
        return Err(KinError::Other(
            "repository stage owner record exceeds its bounded size".to_string(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut owner_file = options
        .open(&owner_path)
        .map_err(|error| KinError::io(&owner_path, error))?;
    if let Err(error) = lock_own_stage_owner(&owner_file) {
        let _ = std::fs::remove_file(&owner_path);
        return Err(KinError::io(&owner_path, error));
    }
    if let Err(error) = set_private_owner_file_permissions(&owner_file) {
        drop(owner_file);
        let _ = std::fs::remove_file(&owner_path);
        return Err(error);
    }
    if let Err(error) = (|| -> std::io::Result<()> {
        owner_file.write_all(&bytes)?;
        owner_file.sync_all()
    })() {
        drop(owner_file);
        let _ = std::fs::remove_file(&owner_path);
        return Err(KinError::io(&owner_path, error));
    }
    if let Err(error) = sync_parent_directory(parent) {
        drop(owner_file);
        let _ = std::fs::remove_file(&owner_path);
        return Err(error);
    }
    Ok(RepositoryInitStageLease {
        owner_path,
        owner_file,
        record,
    })
}

#[cfg(unix)]
fn set_private_owner_file_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            KinError::Other(format!("set repository stage owner permissions: {error}"))
        })
}

#[cfg(not(unix))]
fn set_private_owner_file_permissions(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn exact_path_identity(path: &Path) -> Result<ExactPathIdentity> {
    use std::os::unix::ffi::OsStrExt;

    Ok(ExactPathIdentity::UnixBytes(
        path.as_os_str().as_bytes().to_vec(),
    ))
}

#[cfg(windows)]
fn exact_path_identity(path: &Path) -> Result<ExactPathIdentity> {
    use std::os::windows::ffi::OsStrExt;

    Ok(ExactPathIdentity::WindowsWide(
        path.as_os_str().encode_wide().collect(),
    ))
}

#[cfg(not(any(unix, windows)))]
fn exact_path_identity(_path: &Path) -> Result<ExactPathIdentity> {
    Err(KinError::Other(
        "exact repository stage path identity is unsupported on this platform".to_string(),
    ))
}

/// Recoverable identity of the entry `metadata` described.
///
/// `metadata` must come from `symlink_metadata` on `path`: Unix identity is
/// read straight out of it, while Windows identity exists only on an open
/// handle and is read by reopening the same unfollowed entry.
#[cfg(unix)]
fn recoverable_path_identity(
    _path: &Path,
    metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    recoverable_unix_identity(metadata)
}

/// Recoverable identity of a handle Kin already holds open.
#[cfg(unix)]
fn recoverable_open_file_identity(
    _file: &File,
    metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    recoverable_unix_identity(metadata)
}

#[cfg(unix)]
fn recoverable_unix_identity(metadata: &std::fs::Metadata) -> RecoverableFileIdentity {
    use std::os::unix::fs::MetadataExt;

    RecoverableFileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

/// Recoverable identity of the entry `metadata` described.
///
/// Windows binds file identity to an open handle rather than to `Metadata`, so
/// the entry is reopened with exactly the access `symlink_metadata` used: a
/// zero access mask asks for identity without demanding read rights,
/// `FILE_FLAG_BACKUP_SEMANTICS` admits directory handles, and
/// `FILE_FLAG_OPEN_REPARSE_POINT` leaves a final symlink unfollowed.
#[cfg(windows)]
fn recoverable_path_identity(
    path: &Path,
    _metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    match OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => recoverable_windows_identity(&file),
        Err(_) => RecoverableFileIdentity::Unavailable,
    }
}

/// Recoverable identity of a handle Kin already holds open.
#[cfg(windows)]
fn recoverable_open_file_identity(
    file: &File,
    _metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    recoverable_windows_identity(file)
}

/// Read the `BY_HANDLE_FILE_INFORMATION` identity pair for an open handle.
///
/// The `std` accessors for these fields are still unstable, so the same
/// handle information is read through a stable wrapper. A handle whose
/// identity cannot be read, or whose volume serial does not fit the `DWORD`
/// it is documented to be, stays `Unavailable` rather than failing the caller
/// or panicking.
#[cfg(windows)]
fn recoverable_windows_identity(file: &File) -> RecoverableFileIdentity {
    let Ok(information) = winapi_util::file::information(file) else {
        return RecoverableFileIdentity::Unavailable;
    };
    let Ok(volume_serial_number) = u32::try_from(information.volume_serial_number()) else {
        return RecoverableFileIdentity::Unavailable;
    };
    RecoverableFileIdentity::Windows {
        volume_serial_number,
        file_index: information.file_index(),
    }
}

#[cfg(not(any(unix, windows)))]
fn recoverable_path_identity(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    RecoverableFileIdentity::Unavailable
}

#[cfg(not(any(unix, windows)))]
fn recoverable_open_file_identity(
    _file: &File,
    _metadata: &std::fs::Metadata,
) -> RecoverableFileIdentity {
    RecoverableFileIdentity::Unavailable
}

/// Atomically publish a fully bootstrapped staged repository as the final
/// `.kin` directory without replacing any existing entry.
pub fn publish_repository_layout(prepared: PreparedRepositoryInit) -> Result<InitResult> {
    publish_repository_layout_linearized(prepared, |publication| {
        let _published = publication.publish()?;
        Ok(())
    })
}

/// Verify external source authority at the repository publication boundary.
///
/// The callback receives a one-shot [`RepositoryPublication`] only after the
/// staged authority has been durably synced, closed, reopened, verified, and
/// synced again. It must perform its final source proof and consume the
/// capability at the exact chosen linearization point. It may then use the
/// returned [`PublishedRepository`] to immediately post-verify the source.
///
/// An error before publication leaves `.kin` absent and reaps the owned stage.
/// An error after publication returns
/// [`KinError::RepositoryPublishedButUncertain`] after final Kin verification
/// and parent namespace sync have also been attempted.
///
/// No supported POSIX, APFS, or Windows filesystem primitive can atomically
/// snapshot an independently mutable Git object database, index, and worktree
/// together with a no-replace rename of a separate `.kin` directory. This API
/// therefore makes the rename the explicit linearization point and lets the
/// caller verify on both sides of it; non-cooperating raw filesystem writers
/// remain detectable rather than lockable.
pub fn publish_repository_layout_linearized(
    prepared: PreparedRepositoryInit,
    verify_and_publish: impl FnOnce(RepositoryPublication<'_>) -> Result<()>,
) -> Result<InitResult> {
    publish_repository_layout_impl(prepared, verify_and_publish)
}

fn publish_repository_layout_impl(
    mut prepared: PreparedRepositoryInit,
    verify_and_publish: impl FnOnce(RepositoryPublication<'_>) -> Result<()>,
) -> Result<InitResult> {
    let final_kin_dir = prepared.final_kin_dir.clone();
    let final_kin_dir = final_kin_dir.as_path();
    // Everything from here to the publication callback is a phase of the
    // admission ladder that used to run unnamed. On a full-history conversion
    // it is seconds of flushing and re-verifying a staged tree, and a profile
    // that cannot name it reports the memory spent here against no phase at
    // all: the peak of a 6,733-commit conversion landed in this gap and the
    // ladder had nothing to attribute it to.
    let staged_layout_span = info_span!("kin.init.verify_staged_layout").entered();
    validate_publish_destination(&prepared.layout, final_kin_dir)?;
    verify_metadata_seal(&prepared.layout, &prepared.metadata_seal)?;
    let bootstrap = prepared.bootstrap.clone().ok_or_else(|| {
        KinError::Other(
            "cannot publish a staged repository before bootstrap authority commits".to_string(),
        )
    })?;
    if bootstrap.receipt.generation != 1 || bootstrap.receipt.roots_before != prepared.initial_roots
    {
        return Err(KinError::Graph(
            "staged repository bootstrap receipt does not bind generation zero to generation one"
                .to_string(),
        ));
    }

    // Closed before the flush rather than after it. The staged authority
    // retains directory handles inside the stage, and flushing a file needs a
    // writable handle on Windows, so the backend is released first and the
    // flush below runs against a stage this call is the only holder of.
    drop(prepared.authority.take());
    sync_layout_recursively(prepared.layout.root())?;
    verify_repository_layout(
        &prepared.layout,
        &prepared.metadata_seal,
        &prepared.repository_id,
        prepared.workspace_id,
        &bootstrap,
    )?;
    // Verification may create or touch backend lock state. Flush the exact
    // verified namespace once more before the publication rename.
    sync_layout_recursively(prepared.layout.root())?;
    drop(staged_layout_span);
    let published = Cell::new(false);
    let publication_result = verify_and_publish(RepositoryPublication {
        staged_path: prepared.layout.root(),
        final_kin_dir,
        published: &published,
    });
    if !published.get() {
        return match publication_result {
            Err(error) => Err(error),
            Ok(()) => Err(KinError::Other(
                "repository publication callback returned without consuming its one-shot capability"
                    .to_string(),
            )),
        };
    }
    // The stretch between the publication callback returning and the result
    // being assembled: lease cleanup, the parent-namespace sync and the final
    // verification of the published layout. Named for the same reason as the
    // staged verification above, so the ladder has no unnamed stretch left for
    // a peak to hide in.
    let finalize_span = info_span!("kin.init.finalize_publication").entered();
    prepared.cleanup_armed = false;
    let owner_cleanup = prepared
        .stage_lease
        .take()
        .ok_or_else(|| KinError::Other("repository stage lease is missing".to_string()))
        .and_then(remove_stage_owner);

    let source_parent = prepared
        .layout
        .root()
        .parent()
        .expect("validated staged path always has a parent");
    let destination_parent = final_kin_dir
        .parent()
        .expect("validated final .kin path always has a parent");
    let namespace_sync =
        owner_cleanup.and_then(|()| sync_publication_parents(source_parent, destination_parent));
    let layout = KinLayout::new(final_kin_dir.to_path_buf());
    let final_verification = verify_repository_layout(
        &layout,
        &prepared.metadata_seal,
        &prepared.repository_id,
        prepared.workspace_id,
        &bootstrap,
    );
    let (config, manifest) = match (publication_result, namespace_sync, final_verification) {
        (Ok(()), Ok(()), Ok(metadata)) => metadata,
        (publication_result, namespace_sync, final_verification) => {
            let mut details = Vec::new();
            if let Err(error) = publication_result {
                details.push(format!(
                    "post-publication source verification failed: {error}"
                ));
            }
            if let Err(error) = namespace_sync {
                details.push(format!("publication namespace sync failed: {error}"));
            }
            if let Err(error) = final_verification {
                details.push(format!("final repository verification failed: {error}"));
            }
            return Err(KinError::RepositoryPublishedButUncertain {
                path: final_kin_dir.display().to_string(),
                detail: details.join("; "),
            });
        }
    };

    drop(finalize_span);

    Ok(InitResult {
        layout,
        config,
        manifest,
        repository_id: prepared.repository_id.clone(),
        workspace_id: prepared.workspace_id,
        head: bootstrap.workspace.workspace_head.clone(),
        authority: bootstrap,
        workspace_divergence: kin_git::GitWorkspaceDivergenceFacts::none(),
    })
}

fn verify_repository_layout(
    layout: &KinLayout,
    metadata_seal: &RepositoryMetadataSeal,
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
    bootstrap: &RepositoryBootstrap,
) -> Result<(KinConfig, KinManifest)> {
    layout.check_version()?;
    verify_metadata_seal(layout, metadata_seal)?;
    let config = KinConfig::load(&layout.config_path())?;
    let manifest = KinManifest::load(&layout.manifest_path())?;
    if manifest.repo_id != repository_id.as_str()
        || manifest.workspace_id != workspace_id.to_string()
    {
        return Err(KinError::Graph(
            "repository manifest does not bind the committed repository and workspace identities"
                .to_string(),
        ));
    }
    let authority = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .map_err(graph_error)?;
    let reopened_roots = authority.read_authority().roots().clone();
    if reopened_roots != bootstrap.receipt.roots_after {
        return Err(KinError::Graph(
            "repository reopened with different authority roots".to_string(),
        ));
    }
    let reopened_workspace = authority
        .workspace_snapshot_binding(repository_id, &workspace_id)
        .map_err(graph_error)?
        .ok_or_else(|| KinError::Graph(format!("repository has no workspace {workspace_id}")))?;
    if reopened_workspace != bootstrap.workspace {
        return Err(KinError::Graph(
            "repository workspace binding changed across reopen".to_string(),
        ));
    }
    Ok((config, manifest))
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
    admission_case: AdmissionCase,
    default_ref: RefName,
    shared_policy: SharedAdmissionPolicy,
    initial_change: Option<SemanticChange>,
) -> Result<RepositoryBootstrap>
where
    B: StorageBackend + 'static,
{
    let initial_roots = authority.read_authority().roots().clone();
    let prepared_default_ref = default_ref.clone();
    let transaction = build_repository_bootstrap_transaction(
        initial_roots.clone(),
        repository_id.clone(),
        workspace_id,
        admission_case,
        default_ref,
        shared_policy,
        initial_change,
    )?;
    validate_bootstrap_transaction(
        &transaction,
        &repository_id,
        workspace_id,
        &prepared_default_ref,
        &initial_roots,
    )?;
    commit_bootstrap_transaction(authority, transaction, &repository_id, workspace_id)
}

fn build_repository_bootstrap_transaction(
    initial_roots: RootBundle,
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
    admission_case: AdmissionCase,
    default_ref: RefName,
    shared_policy: SharedAdmissionPolicy,
    initial_change: Option<SemanticChange>,
) -> Result<RepositoryTransaction> {
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
    let semantic_delta = initial_change
        .as_ref()
        .map(|change| {
            WorkspaceSemanticDelta::new(
                change.entity_deltas.clone(),
                change.relation_deltas.clone(),
            )
        })
        .transpose()
        .map_err(|error| KinError::Other(error.to_string()))?
        .unwrap_or_default();
    let tree = kin_model::ResolvedTree::default()
        .apply(&tree_deltas)
        .map_err(|error| KinError::Other(error.to_string()))?;
    let tree_hash =
        compute_resolved_tree_hash(&tree).map_err(|error| KinError::Other(error.to_string()))?;
    let base_target = initial_change_id.map(RefTarget::change);
    let base_tree_hash = initial_change_id.map(|_| tree_hash);
    let workspace_head = WorkspaceHead::Symbolic {
        target: default_ref.clone(),
    };
    let local_overlay = FrozenLocalOverlay::new(workspace_id, 0, admission_case, Vec::new())
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
        semantic_delta,
        new_shared_admission_policy: shared_policy,
        new_admission_policy: admission_policy,
    };

    let mut transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: repository_id.clone(),
        expected_generation: initial_roots.generation,
        expected_roots: initial_roots,
        actor: AuthorId::new("kin"),
        reason: if initial_change.is_some() {
            "initialize repository with admitted history".to_string()
        } else {
            "initialize unborn repository workspace".to_string()
        },
        external_objects: Vec::new(),
        changes: initial_change.into_iter().collect(),
        aliases: Vec::new(),
        git_authority_delta: None,
        ref_mutations: Vec::new(),
        default_ref_mutation: Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(default_ref.clone()),
        }),
        workspace_mutation: Some(workspace_mutation),
        local_overlay_delta: Some(FrozenLocalOverlayDelta::initialize(local_overlay)),
        merge_transaction_delta: None,
        sealed_observation: None,
    };

    if let Some(change_id) = initial_change_id {
        transaction.ref_mutations.push(RefMutation {
            name: default_ref,
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::change(change_id)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
    }
    Ok(transaction)
}

fn commit_bootstrap_transaction<B>(
    authority: &RepositoryAuthorityManager<B>,
    transaction: RepositoryTransaction,
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
) -> Result<RepositoryBootstrap>
where
    B: StorageBackend + 'static,
{
    // A bootstrap transaction carries every reachable external object and every
    // change in history, so on a repository with real history a copy taken to
    // satisfy the owned-parameter commit is a second whole-history allocation,
    // charged at the point init already holds its largest working set. The
    // transaction is therefore moved into the commit rather than cloned, and
    // every field the receipt is checked against is read before the move.
    let initial_change_id = transaction
        .workspace_mutation
        .as_ref()
        .and_then(|mutation| match mutation.new_base_target {
            Some(RefTarget::Change { change_id }) => Some(change_id),
            _ => None,
        });
    // Coarse ticks across the four sub-steps of the commit, because this is
    // the longest phase in the ladder and none of it is reachable from the
    // phase reporter: `commit_repository_transaction` takes no progress
    // callback, so between entering this phase and leaving it the line would
    // otherwise sit unchanged for minutes, which reads as a hang. What kin-db
    // reports from inside its own replay arrives through the same sink.
    let receipt = {
        crate::report_admission_progress(&format!(
            "committing {} changes to authority",
            transaction.changes.len()
        ));
        let _span = info_span!(
            "kin.init.commit.authority_commit",
            external_objects = transaction.external_objects.len(),
            changes = transaction.changes.len()
        )
        .entered();
        authority
            .commit_repository_transaction(transaction)
            .map_err(graph_error)?
    };
    let workspace = {
        crate::report_admission_progress("binding workspace to committed roots");
        let _span = info_span!("kin.init.commit.workspace_binding").entered();
        authority
            .workspace_snapshot_binding(repository_id, &workspace_id)
            .map_err(graph_error)?
            .ok_or_else(|| {
                KinError::Graph(format!(
                    "repository authority committed without workspace {workspace_id}"
                ))
            })?
    };
    if workspace.roots != receipt.roots_after {
        return Err(KinError::Graph(
            "repository bootstrap workspace is not bound to the committed roots".to_string(),
        ));
    }
    workspace
        .validate()
        .map_err(|error| KinError::Other(error.to_string()))?;
    let semantic_enrichment = {
        crate::report_admission_progress("summarizing semantic enrichment");
        let _span = info_span!("kin.init.commit.enrichment_summary").entered();
        let lease = authority.read_authority();
        if lease.roots() != &receipt.roots_after {
            return Err(KinError::Graph(
                "repository bootstrap enrichment lease is not bound to the committed roots"
                    .to_string(),
            ));
        }
        crate::durable_semantic_enrichment_summary(&lease, &workspace_id)?
    };
    Ok(RepositoryBootstrap {
        receipt,
        workspace,
        semantic_enrichment,
        initial_change_id,
    })
}

fn validate_bootstrap_transaction(
    transaction: &RepositoryTransaction,
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
    default_ref: &RefName,
    initial_roots: &RootBundle,
) -> Result<()> {
    transaction
        .validate()
        .map_err(|error| KinError::Other(error.to_string()))?;
    if initial_roots.generation != 0
        || transaction.expected_generation != 0
        || &transaction.expected_roots != initial_roots
    {
        return Err(KinError::Other(
            "repository bootstrap must compare-and-swap the exact generation-zero roots"
                .to_string(),
        ));
    }
    if &transaction.repository_id != repository_id {
        return Err(KinError::Other(format!(
            "repository bootstrap belongs to {}, not {}",
            transaction.repository_id, repository_id
        )));
    }
    let expected_default = transaction
        .git_authority_delta
        .as_ref()
        .and_then(|delta| delta.new.as_ref())
        .map_or_else(
            || {
                Some(DefaultRefMutation {
                    expected: DefaultRefExpectation::MustBeUnset,
                    new_default: Some(default_ref.clone()),
                })
            },
            |git_authority| match &git_authority.raw_head {
                GitRawTarget::Symbolic { target } => Some(DefaultRefMutation {
                    expected: DefaultRefExpectation::MustBeUnset,
                    new_default: Some(target.clone()),
                }),
                GitRawTarget::Direct { .. } => None,
            },
        );
    if transaction.default_ref_mutation != expected_default {
        return Err(KinError::Other(
            "repository bootstrap default ref must exactly match native config or raw Git HEAD"
                .to_string(),
        ));
    }
    let workspace = transaction.workspace_mutation.as_ref().ok_or_else(|| {
        KinError::Other("repository bootstrap requires an exact workspace mutation".to_string())
    })?;
    if let Some(delta) = &transaction.git_authority_delta {
        if delta.old.is_some() {
            return Err(KinError::Other(
                "repository bootstrap cannot replace pre-existing Git authority".to_string(),
            ));
        }
        let git_authority = delta.new.as_ref().ok_or_else(|| {
            KinError::Other("repository bootstrap cannot remove absent Git authority".to_string())
        })?;
        let expected_head = match (&git_authority.raw_head, &git_authority.material_head) {
            (
                GitRawTarget::Symbolic { target },
                GitMaterialHead::Unborn { .. } | GitMaterialHead::Commit { .. },
            ) => WorkspaceHead::Symbolic {
                target: target.clone(),
            },
            (GitRawTarget::Direct { .. }, GitMaterialHead::Commit { commit_oid, .. }) => {
                WorkspaceHead::Detached {
                    target: RefTarget::external_object(ExternalObjectId::new(
                        ExternalObjectKind::Commit,
                        *commit_oid,
                    )),
                }
            }
            (GitRawTarget::Direct { .. }, GitMaterialHead::Unborn { .. }) => {
                return Err(KinError::Other(
                    "direct raw Git HEAD cannot be verified as unborn".to_string(),
                ));
            }
            (_, GitMaterialHead::NonMaterializable { .. }) => {
                return Err(KinError::Other(
                    "repository bootstrap cannot materialize raw Git HEAD as a workspace"
                        .to_string(),
                ));
            }
        };
        if workspace.new_head != expected_head {
            return Err(KinError::Other(
                "repository bootstrap workspace head must exactly match material Git HEAD"
                    .to_string(),
            ));
        }
    }
    if workspace.workspace_id != workspace_id
        || workspace.expected != WorkspaceExpectation::MustNotExist
        || workspace.new_generation != 0
    {
        return Err(KinError::Other(
            "repository bootstrap must initialize the staged workspace at generation zero"
                .to_string(),
        ));
    }
    let overlay = transaction.local_overlay_delta.as_ref().ok_or_else(|| {
        KinError::Other(
            "repository bootstrap requires a frozen local admission overlay".to_string(),
        )
    })?;
    if overlay.old.is_some()
        || overlay.new.as_ref().is_none_or(|candidate| {
            candidate.workspace_id != workspace_id || candidate.generation != 0
        })
    {
        return Err(KinError::Other(
            "repository bootstrap must initialize the exact staged workspace overlay".to_string(),
        ));
    }
    Ok(())
}

/// Read one staged metadata file, saying which read this was.
///
/// The config writer reports its own refusals against the same path this reads,
/// so an unlabelled failure here is indistinguishable from a failure to publish
/// and sends the reader to the wrong component. Sealing happens after
/// publication, so naming the step is the difference between "the writer could
/// not publish" and "the writer published something this cannot read".
fn read_to_seal(path: &Path, label: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| {
        KinError::Other(format!(
            "read published {label} at {} to seal staged repository metadata: {error}",
            path.display()
        ))
    })
}

/// Read one staged metadata file again, to check it against its seal.
///
/// Sealing and verifying read the same name at different points in the
/// transaction, so they need to be told apart for the same reason the seal
/// needs to be told apart from the writer. A verification that cannot be read
/// means something took the file away after preparation, which is a different
/// failure from never having been able to read it.
fn read_to_verify_seal(path: &Path, label: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| {
        KinError::Other(format!(
            "reread {label} at {} to check it against its seal: {error}",
            path.display()
        ))
    })
}

fn capture_metadata_seal(layout: &KinLayout) -> Result<RepositoryMetadataSeal> {
    let config_bytes = read_to_seal(&layout.config_path(), "repository config")?;
    let manifest_bytes = read_to_seal(&layout.manifest_path(), "repository manifest")?;
    Ok(RepositoryMetadataSeal {
        config_hash: Hash256::from_bytes(Sha256::digest(&config_bytes).into()),
        manifest_hash: Hash256::from_bytes(Sha256::digest(&manifest_bytes).into()),
        config_bytes,
        manifest_bytes,
    })
}

fn verify_metadata_seal(layout: &KinLayout, seal: &RepositoryMetadataSeal) -> Result<()> {
    verify_sealed_metadata_file(
        &layout.config_path(),
        "repository config",
        &seal.config_bytes,
        seal.config_hash,
    )?;
    verify_sealed_metadata_file(
        &layout.manifest_path(),
        "repository manifest",
        &seal.manifest_bytes,
        seal.manifest_hash,
    )
}

fn verify_sealed_metadata_file(
    path: &Path,
    label: &str,
    expected_bytes: &[u8],
    expected_hash: Hash256,
) -> Result<()> {
    let observed = read_to_verify_seal(path, label)?;
    let observed_hash = Hash256::from_bytes(Sha256::digest(&observed).into());
    if observed_hash != expected_hash || observed != expected_bytes {
        return Err(KinError::Other(format!(
            "{label} changed after staged repository preparation"
        )));
    }
    Ok(())
}

fn canonical_staging_root(staging_kin_dir: &Path) -> Result<PathBuf> {
    if !staging_kin_dir.is_absolute() {
        return Err(KinError::Other(format!(
            "staged repository path must be absolute: {}",
            staging_kin_dir.display()
        )));
    }
    let name = staging_kin_dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(stage_id_from_directory_name)
        .ok_or_else(|| {
            KinError::Other(format!(
                "staged repository name must be .kin.init- followed by a canonical UUID v4: {}",
                staging_kin_dir.display()
            ))
        })?;
    let supplied_parent = staging_kin_dir.parent().ok_or_else(|| {
        KinError::Other(format!(
            "staged repository path has no parent: {}",
            staging_kin_dir.display()
        ))
    })?;
    let parent = supplied_parent
        .canonicalize()
        .map_err(|error| KinError::io(supplied_parent, error))?;
    let canonical_root = parent.join(stage_directory_name(name));
    if canonical_root != staging_kin_dir {
        return Err(KinError::Other(format!(
            "staged repository path must use its canonical parent: {}",
            canonical_root.display()
        )));
    }
    Ok(canonical_root)
}

fn canonical_final_kin_dir(final_kin_dir: &Path) -> Result<PathBuf> {
    if !final_kin_dir.is_absolute()
        || final_kin_dir.file_name() != Some(std::ffi::OsStr::new(".kin"))
    {
        return Err(KinError::Other(format!(
            "published repository path must be an absolute .kin directory: {}",
            final_kin_dir.display()
        )));
    }
    let supplied_parent = final_kin_dir.parent().ok_or_else(|| {
        KinError::Other(format!(
            "published repository path has no parent: {}",
            final_kin_dir.display()
        ))
    })?;
    let parent = supplied_parent
        .canonicalize()
        .map_err(|error| KinError::io(supplied_parent, error))?;
    let canonical = parent.join(".kin");
    if canonical != final_kin_dir {
        return Err(KinError::Other(format!(
            "published repository path must use its canonical parent: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn validate_publish_destination(layout: &KinLayout, final_kin_dir: &Path) -> Result<()> {
    let canonical_final = canonical_final_kin_dir(final_kin_dir)?;
    let stage_parent = layout.root().parent().ok_or_else(|| {
        KinError::Other(format!(
            "staged repository has no parent: {}",
            layout.root().display()
        ))
    })?;
    let final_parent = final_kin_dir.parent().ok_or_else(|| {
        KinError::Other(format!(
            "published repository has no parent: {}",
            final_kin_dir.display()
        ))
    })?;
    let stage_parent = stage_parent
        .canonicalize()
        .map_err(|error| KinError::io(stage_parent, error))?;
    let final_parent = final_parent
        .canonicalize()
        .map_err(|error| KinError::io(final_parent, error))?;
    if canonical_final != final_kin_dir || layout.root() == final_kin_dir {
        return Err(KinError::Other(
            "published repository path must be the canonical .kin child of its repository root"
                .to_string(),
        ));
    }
    validate_same_filesystem(&stage_parent, &final_parent)?;
    let metadata = std::fs::symlink_metadata(layout.root())
        .map_err(|error| KinError::io(layout.root(), error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(KinError::Other(format!(
            "staged repository is not a real directory: {}",
            layout.root().display()
        )));
    }
    Ok(())
}

/// Open one staged file for the flush below.
///
/// Unix `fsync` accepts a read-only descriptor, so opening read-only is both
/// sufficient and the weaker request. Windows has no equivalent: `sync_all` is
/// `FlushFileBuffers`, which Microsoft documents as requiring `GENERIC_WRITE`
/// on the handle, and which refuses a read-only one with
/// `ERROR_ACCESS_DENIED`. Publication has to ask for write access there.
///
/// The difference is named here because of how it presents when it is missed.
/// `sync_layout_recursively` walks each directory's children in sorted order,
/// and a staged layout's first three entries are the empty directories
/// `adapters`, `backups`, and `bench`, so `config.toml` is the first regular
/// file the walk reaches. A read-only flush therefore reports an access denial
/// against the staged repository config, which reads as the config writer
/// refusing to publish rather than as publication failing to flush.
#[cfg(not(windows))]
fn open_to_flush(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn open_to_flush(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn sync_layout_recursively(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| KinError::io(path, error))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(KinError::Other(format!(
            "staged repository metadata must not contain symlinks: {}",
            path.display()
        )));
    }
    if file_type.is_file() {
        let file = open_to_flush(path).map_err(|error| KinError::io(path, error))?;
        return file.sync_all().map_err(|error| KinError::io(path, error));
    }
    if !file_type.is_dir() {
        return Err(KinError::Other(format!(
            "staged repository metadata contains a special filesystem entry: {}",
            path.display()
        )));
    }
    let mut children = std::fs::read_dir(path)
        .map_err(|error| KinError::io(path, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| KinError::io(path, error))?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        sync_layout_recursively(&child.path())?;
    }
    sync_parent_directory(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let directory = std::fs::File::open(path).map_err(|error| KinError::io(path, error))?;
    directory
        .sync_all()
        .map_err(|error| KinError::io(path, error))
}

fn sync_publication_parents(source_parent: &Path, destination_parent: &Path) -> Result<()> {
    sync_parent_directory(source_parent)?;
    if source_parent != destination_parent {
        sync_parent_directory(destination_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_same_filesystem(source_parent: &Path, destination_parent: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let source =
        std::fs::metadata(source_parent).map_err(|error| KinError::io(source_parent, error))?;
    let destination = std::fs::metadata(destination_parent)
        .map_err(|error| KinError::io(destination_parent, error))?;
    if source.dev() != destination.dev() {
        return Err(KinError::Other(
            "staged and published repository directories must be on the same filesystem"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_filesystem(_source_parent: &Path, _destination_parent: &Path) -> Result<()> {
    // MoveFileExW below fails before mutation when the paths span volumes.
    Ok(())
}

#[cfg(windows)]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    // MoveFileExW(MOVEFILE_WRITE_THROUGH) below flushes the namespace move.
    // Windows has no supported directory fsync equivalent.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Err(KinError::Other(
        "atomic repository publication is unsupported on this platform".to_string(),
    ))
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
))]
fn rename_directory_noreplace(source: &Path, destination: &Path) -> Result<()> {
    let source_parent_path = source.parent().expect("validated source has a parent");
    let destination_parent_path = destination
        .parent()
        .expect("validated destination has a parent");
    let source_parent = std::fs::File::open(source_parent_path)
        .map_err(|error| KinError::io(source_parent_path, error))?;
    let destination_parent = std::fs::File::open(destination_parent_path)
        .map_err(|error| KinError::io(destination_parent_path, error))?;
    rustix::fs::renameat_with(
        &source_parent,
        source
            .file_name()
            .expect("validated staged source has a file name"),
        &destination_parent,
        destination
            .file_name()
            .expect("validated destination has a file name"),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| KinError::io(destination, std::io::Error::from(error)))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))
))]
fn rename_directory_noreplace(_source: &Path, _destination: &Path) -> Result<()> {
    Err(KinError::Other(
        "atomic no-replace repository publication is unsupported on this Unix target".to_string(),
    ))
}

#[cfg(windows)]
fn rename_directory_noreplace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(KinError::io(destination, std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn rename_directory_noreplace(_source: &Path, _destination: &Path) -> Result<()> {
    Err(KinError::Other(
        "atomic repository publication is unsupported on this platform".to_string(),
    ))
}

fn cleanup_created_staging_root(root: &Path) {
    let safe_name = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(stage_id_from_directory_name)
        .is_some();
    let safe_directory = std::fs::symlink_metadata(root)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink());
    if safe_name && safe_directory {
        let _ = std::fs::remove_dir_all(root);
    }
}

fn cleanup_staging_layout(
    lease: RepositoryInitStageLease,
    layout: &KinLayout,
    expected_manifest: &KinManifest,
) {
    let manifest_matches = KinManifest::load(&layout.manifest_path()).is_ok_and(|manifest| {
        manifest.repo_id == expected_manifest.repo_id
            && manifest.workspace_id == expected_manifest.workspace_id
    });
    if manifest_matches {
        cleanup_owned_staging_root(lease, layout.root());
    }
}

fn cleanup_owned_staging_root(lease: RepositoryInitStageLease, stage_root: &Path) {
    if validate_live_stage_lease(&lease, stage_root).is_ok() {
        let _ = std::fs::remove_dir_all(stage_root);
        if !stage_root.exists() {
            let _ = remove_stage_owner(lease);
        }
    }
}

fn remove_stage_owner(lease: RepositoryInitStageLease) -> Result<()> {
    if read_stage_owner_record(&lease.owner_file, &lease.owner_path)? != lease.record {
        return Err(KinError::Other(format!(
            "repository stage owner record changed while held: {}",
            lease.owner_path.display()
        )));
    }
    let open_metadata = lease
        .owner_file
        .metadata()
        .map_err(|error| KinError::io(&lease.owner_path, error))?;
    let path_metadata = std::fs::symlink_metadata(&lease.owner_path)
        .map_err(|error| KinError::io(&lease.owner_path, error))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.file_type().is_symlink()
        || recoverable_open_file_identity(&lease.owner_file, &open_metadata)
            != recoverable_path_identity(&lease.owner_path, &path_metadata)
    {
        return Err(KinError::Other(format!(
            "repository stage owner path changed while held: {}",
            lease.owner_path.display()
        )));
    }
    validate_private_owner_file(&path_metadata)?;
    drop(lease.owner_file);
    std::fs::remove_file(&lease.owner_path)
        .map_err(|error| KinError::io(&lease.owner_path, error))?;
    if let Some(parent) = lease.owner_path.parent() {
        sync_parent_directory(parent)?;
    }
    Ok(())
}

fn validate_live_stage_lease(lease: &RepositoryInitStageLease, stage_root: &Path) -> Result<()> {
    let observed = read_stage_owner_record(&lease.owner_file, &lease.owner_path)?;
    if observed != lease.record
        || observed.stage_path != exact_path_identity(stage_root)?
        || observed.stage_identity
            != recoverable_path_identity(
                stage_root,
                &std::fs::symlink_metadata(stage_root)
                    .map_err(|error| KinError::io(stage_root, error))?,
            )
    {
        return Err(KinError::Other(
            "repository stage ownership changed while held".to_string(),
        ));
    }
    validate_private_stage_directory(stage_root)
}

fn read_stage_owner_record(
    owner_file: &File,
    owner_path: &Path,
) -> Result<RepositoryInitStageOwner> {
    let metadata = owner_file
        .metadata()
        .map_err(|error| KinError::io(owner_path, error))?;
    validate_private_owner_file(&metadata)?;
    if metadata.len() == 0 || metadata.len() > MAX_INIT_STAGE_OWNER_BYTES {
        return Err(KinError::Other(format!(
            "repository stage owner record has an invalid size: {}",
            owner_path.display()
        )));
    }
    let mut reader = owner_file
        .try_clone()
        .map_err(|error| KinError::io(owner_path, error))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| KinError::io(owner_path, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .take(MAX_INIT_STAGE_OWNER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| KinError::io(owner_path, error))?;
    let record: RepositoryInitStageOwner = serde_json::from_slice(&bytes)
        .map_err(|error| KinError::Other(format!("invalid repository stage owner: {error}")))?;
    if record.schema_version != INIT_STAGE_OWNER_SCHEMA_VERSION {
        return Err(KinError::Other(format!(
            "unsupported repository stage owner schema {}",
            record.schema_version
        )));
    }
    Ok(record)
}

#[cfg(unix)]
fn validate_private_owner_file(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(KinError::Other(
            "repository stage owner is not a private, singly linked file owned by this user"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_owner_file(metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(KinError::Other(
            "repository stage owner is not a regular file".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_stage_directory(stage_root: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        std::fs::symlink_metadata(stage_root).map_err(|error| KinError::io(stage_root, error))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(KinError::Other(format!(
            "repository stage is not a private directory owned by this user: {}",
            stage_root.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_stage_directory(stage_root: &Path) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(stage_root).map_err(|error| KinError::io(stage_root, error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(KinError::Other(format!(
            "repository stage is not a real directory: {}",
            stage_root.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn open_stage_owner_for_recovery(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| KinError::io(path, error))
}

#[cfg(unix)]
fn filesystem_entry_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(KinError::io(path, error)),
    }
}

/// Reap only stages whose exact owner record is private, destination-bound,
/// inode-bound, and no longer locked by a live initializer.
///
/// Invalid, ambiguous, replaced, or active candidates are retained. Automatic
/// orphan recovery is disabled when the platform cannot expose a stable file
/// identity and current-user ownership.
pub(crate) fn recover_orphaned_repository_stages(
    staging_parent: &Path,
    final_kin_dir: &Path,
) -> Result<usize> {
    #[cfg(not(unix))]
    {
        let _ = (staging_parent, final_kin_dir);
        return Ok(0);
    }

    #[cfg(unix)]
    {
        let expected_destination = exact_path_identity(final_kin_dir)?;
        let mut entries = std::fs::read_dir(staging_parent)
            .map_err(|error| KinError::io(staging_parent, error))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| KinError::io(staging_parent, error))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut recovered = 0;
        let mut retained = 0;
        for entry in entries {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(stage_id) = stage_id_from_owner_name(&name) else {
                continue;
            };
            let owner_path = entry.path();
            let owner_file = match open_stage_owner_for_recovery(&owner_path) {
                Ok(file) => file,
                Err(error) => {
                    debug!(
                        path = %owner_path.display(),
                        %error,
                        "retaining unprovable repository stage owner"
                    );
                    retained += 1;
                    continue;
                }
            };
            if owner_file.try_lock_exclusive().is_err() {
                continue;
            }
            let record = match read_stage_owner_record(&owner_file, &owner_path) {
                Ok(record) => record,
                Err(error) => {
                    debug!(
                        path = %owner_path.display(),
                        %error,
                        "retaining repository stage with invalid owner record"
                    );
                    retained += 1;
                    continue;
                }
            };
            let stage_root = staging_parent.join(stage_directory_name(stage_id));
            if record.stage_id != stage_id.to_string()
                || record.stage_path != exact_path_identity(&stage_root)?
                || record.destination_path != expected_destination
            {
                continue;
            }
            let repository_uuid = uuid::Uuid::parse_str(&record.repository_id).ok();
            let workspace_uuid = uuid::Uuid::parse_str(&record.workspace_id).ok();
            // This gate asks one question: is this a record this build could
            // have written? Since adoption, the answer has two shapes. A minted
            // repository identity is a UUID v4 in canonical text; an adopted one
            // is the peer's identity verbatim, which is a slug on every hosted
            // repository there is. Admitting only the first left an interrupted
            // adopting init's stage matching nothing here, so it was skipped on
            // every later pass and its disk was never reclaimed. Workspace
            // identity is always minted, so it keeps the stricter rule.
            let repository_identity_is_one_this_build_writes = match repository_uuid {
                Some(id) => id.get_version_num() == 4 && id.to_string() == record.repository_id,
                None => require_storable_adopted_identity(&record.repository_id).is_ok(),
            };
            if !repository_identity_is_one_this_build_writes
                || workspace_uuid.is_none_or(|id| {
                    id.get_version_num() != 4 || id.to_string() != record.workspace_id
                })
                || repository_uuid == workspace_uuid
            {
                continue;
            }
            let reap_root = staging_parent.join(format!(".kin.reap-{stage_id}"));
            let stage_exists = match filesystem_entry_exists(&stage_root) {
                Ok(exists) => exists,
                Err(error) => {
                    debug!(
                        path = %stage_root.display(),
                        %error,
                        "retaining repository stage whose presence is not provable"
                    );
                    retained += 1;
                    continue;
                }
            };
            let reap_exists = match filesystem_entry_exists(&reap_root) {
                Ok(exists) => exists,
                Err(error) => {
                    debug!(
                        path = %reap_root.display(),
                        %error,
                        "retaining repository stage whose recovery state is not provable"
                    );
                    retained += 1;
                    continue;
                }
            };
            if stage_exists && reap_exists {
                debug!(
                    stage = %stage_root.display(),
                    reap = %reap_root.display(),
                    "retaining ambiguous repository stage recovery state"
                );
                retained += 1;
                continue;
            }
            let owned_root = if reap_exists {
                &reap_root
            } else if stage_exists {
                &stage_root
            } else {
                let lease = RepositoryInitStageLease {
                    owner_path,
                    owner_file,
                    record,
                };
                remove_stage_owner(lease)?;
                recovered += 1;
                continue;
            };
            if validate_private_stage_directory(owned_root).is_err()
                || recoverable_path_identity(
                    owned_root,
                    &std::fs::symlink_metadata(owned_root)
                        .map_err(|error| KinError::io(owned_root, error))?,
                ) != record.stage_identity
            {
                debug!(
                    path = %owned_root.display(),
                    "retaining repository stage whose filesystem identity is not provable"
                );
                retained += 1;
                continue;
            }
            if owned_root == &stage_root {
                if let Err(error) = rename_directory_noreplace(&stage_root, &reap_root) {
                    debug!(
                        path = %stage_root.display(),
                        %error,
                        "retaining repository stage after failed recovery claim"
                    );
                    retained += 1;
                    continue;
                }
                let reaped_identity = recoverable_path_identity(
                    &reap_root,
                    &std::fs::symlink_metadata(&reap_root)
                        .map_err(|error| KinError::io(&reap_root, error))?,
                );
                if reaped_identity != record.stage_identity {
                    debug!(
                        path = %reap_root.display(),
                        "retaining claimed repository stage after identity changed"
                    );
                    retained += 1;
                    continue;
                }
            }
            std::fs::remove_dir_all(&reap_root).map_err(|error| KinError::io(&reap_root, error))?;
            let lease = RepositoryInitStageLease {
                owner_path,
                owner_file,
                record,
            };
            remove_stage_owner(lease)?;
            recovered += 1;
        }
        if recovered > 0 {
            info!(
                count = recovered,
                destination = %final_kin_dir.display(),
                "recovered inactive repository initialization stages"
            );
        }
        if retained > 0 {
            let (noun, pronoun) = if retained == 1 {
                ("staging directory", "it")
            } else {
                ("staging directories", "them")
            };
            info!(
                count = retained,
                parent = %staging_parent.display(),
                "kin init kept {retained} earlier {noun} under {} because it could not prove \
                 {pronoun} unused; that costs disk and nothing else, and {pronoun} can be deleted \
                 by hand once no kin init is running here",
                staging_parent.display()
            );
        }
        Ok(recovered)
    }
}

fn graph_error(error: impl std::fmt::Display) -> KinError {
    KinError::Graph(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        compute_semantic_change_id, ChangeOrigin, GitExternalAuthority, GitExternalAuthorityDelta,
        GitObjectBodyLoader, GitObjectFormat, Hash256, RefTarget, Timestamp, WorkspaceHead,
    };
    use sha2::{Digest, Sha256};

    /// A store may adopt a hosted repository identity, and it is the committed
    /// authority that has to carry it, not just the manifest.
    ///
    /// The manifest is the easy half and proves nothing a transfer cares
    /// about. Every identity check on the transfer path reads
    /// `authority_metadata().repository_id`, so that is what this asserts.
    #[test]
    fn an_adopted_hosted_identity_reaches_the_committed_authority() {
        let working = tempfile::tempdir().unwrap();
        let adopted = RepositoryId::new("kin-db".to_string()).unwrap();

        let result = init_adopting(working.path(), &adopted).expect("a hosted slug is adoptable");

        assert_eq!(result.repository_id, adopted);
        assert_eq!(
            KinManifest::load(&result.layout.manifest_path())
                .unwrap()
                .repo_id,
            "kin-db"
        );
        let authority = RepositoryAuthorityManager::open(
            adopted.clone(),
            Arc::new(LocalFileBackend::new(result.layout.kindb_dir())) as Arc<dyn StorageBackend>,
        )
        .expect("the adopted store reopens under the identity it adopted");
        assert_eq!(
            authority.read_authority().metadata().repository_id,
            adopted,
            "the identity every transfer check reads must be the adopted one"
        );
    }

    /// Minting is unchanged, and that is half of what makes adoption safe.
    ///
    /// Two repositories created independently must never collide, which is
    /// what the UUID v4 shape buys. Adoption opts out of that because the peer
    /// already chose the identity; a mint that opted out would be a
    /// regression, so the gate is asserted from both sides.
    #[test]
    fn a_minted_identity_is_still_required_to_be_a_uuid_v4() {
        let working = tempfile::tempdir().unwrap();
        let minted = init(working.path()).expect("a plain init still mints");
        let parsed = uuid::Uuid::parse_str(minted.repository_id.as_str())
            .expect("a minted identity is UUID text");
        assert_eq!(parsed.get_version_num(), 4);

        // A slug never parses as UUID text at all, and a UUID of another
        // version parses and is still the wrong shape. Both have to stay
        // refused on the minting path, and only the second can reach the
        // version check, so asserting on one of them would leave the other
        // unguarded.
        let staging = tempfile::tempdir().unwrap();
        for (candidate, expected) in [
            ("kin-db", "invalid repository identity"),
            // A UUID v1: parses, wrong version.
            ("2c5ea4c0-4067-11e9-8bad-9b1deb4d3b7d", "UUID v4"),
        ] {
            let error = prepare_repository_layout_at(
                &staging.path().join(format!(".kin.init-{candidate}")),
                &staging.path().join(".kin"),
                KinConfig::default(),
                KinManifest::adopting(candidate),
            )
            .expect_err("a mint refuses any identity it would not have minted");
            assert!(
                error.to_string().contains(expected),
                "the refusal for {candidate} must name why a mint would not have produced it: {error}"
            );
        }
    }

    /// An adopted identity still has to be one the local store can be keyed
    /// by, because a local store is a directory named by its repository id.
    ///
    /// `RepositoryId` admits any non-control text up to 255 bytes, which is
    /// right for a wire identity and wrong for a directory name: kin-db's
    /// `LocalFileBackend` lays a store out at `{base}/{repo_id}/authority.json`,
    /// so a separator would nest the store and a parent reference would put it
    /// outside the tree entirely. Both are valid `RepositoryId` values, so the
    /// type cannot refuse them and this must.
    #[test]
    fn an_adopted_identity_that_is_not_one_path_component_is_refused() {
        for hostile in ["..", ".", "../escaped", "org/repo", "has space", ""] {
            let working = tempfile::tempdir().unwrap();
            let Ok(candidate) = RepositoryId::new(hostile.to_string()) else {
                // Refused by the type already, which is the outcome this wants.
                continue;
            };
            let error = init_adopting(working.path(), &candidate)
                .expect_err("an identity the store cannot be keyed by is refused");
            assert!(
                error.to_string().contains("portable filesystem component"),
                "the refusal must name why {hostile:?} cannot be adopted: {error}"
            );
            assert!(
                !working.path().join(".kin").exists(),
                "a refused adoption leaves no store behind for {hostile:?}"
            );
        }
    }

    /// A concurrent recovery scan holding this init's own owner file must not
    /// fail the init.
    ///
    /// Every init scans sibling stages and locks each owner file to judge it,
    /// so a scan can land between this init creating its owner file and
    /// locking it. That contention is transient and cannot mean anything else,
    /// because the file was created with `create_new` under a fresh UUID.
    #[test]
    fn a_concurrent_scan_holding_the_new_owner_file_does_not_fail_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let owner_path = dir.path().join("stage.owner");
        let owner_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&owner_path)
            .unwrap();

        let scanner = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&owner_path)
            .unwrap();
        scanner.try_lock_exclusive().unwrap();
        assert!(
            is_lock_contention(&owner_file.try_lock_exclusive().unwrap_err()),
            "the scan must really be holding the lock"
        );

        let released = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(40));
            fs2::FileExt::unlock(&scanner).unwrap();
        });
        lock_own_stage_owner(&owner_file).expect("a transient scan must not fail the lease");
        released.join().unwrap();
    }

    /// Contention that never clears still fails closed rather than hanging or
    /// proceeding without the lock.
    #[test]
    fn an_unyielding_holder_still_fails_the_lease_closed() {
        let dir = tempfile::tempdir().unwrap();
        let owner_path = dir.path().join("stage.owner");
        let owner_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&owner_path)
            .unwrap();
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&owner_path)
            .unwrap();
        holder.try_lock_exclusive().unwrap();

        assert!(is_lock_contention(
            &lock_own_stage_owner(&owner_file).unwrap_err()
        ));
    }

    fn prepare_unborn(
        working_dir: &Path,
        _suffix: &str,
    ) -> (PreparedRepositoryInit, RepositoryTransaction) {
        let working_dir = working_dir.canonicalize().unwrap();
        let final_kin_dir = working_dir.join(".kin");
        let prepared = prepare_repository_layout_at(
            &working_dir.join(format!(".kin.init-{}", uuid::Uuid::new_v4())),
            &final_kin_dir,
            KinConfig::default(),
            KinManifest::new(),
        )
        .unwrap();
        let transaction = build_repository_bootstrap_transaction(
            prepared.initial_roots().clone(),
            prepared.repository_id().clone(),
            prepared.workspace_id(),
            AdmissionCase::Sensitive,
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap();
        assert!(prepared.bootstrap.is_none());
        (prepared, transaction)
    }

    /// A canonical stage, built the way admission builds one.
    ///
    /// Admission canonicalizes before it stages, and the config writer only
    /// owns a `.kin.init-<uuid-v4>` directory, so both are required here for
    /// the save below to be the same call admission makes.
    fn canonical_stage(parent: &tempfile::TempDir) -> PathBuf {
        let root = parent.path().canonicalize().expect("canonicalize parent");
        let stage = root.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        create_private_staging_root(&stage).expect("create stage");
        stage
    }

    fn publish_staged_config(stage: &Path) {
        KinConfig::default()
            .save_initialization_stage(stage)
            .expect("publish staged repository config");
        let published =
            std::fs::read(stage.join("config.toml")).expect("read back the published config");
        assert!(
            !published.is_empty(),
            "a published config must hold the bytes it was given"
        );
    }

    /// Building the stage must not break publishing into it.
    ///
    /// `kin init` assembles a stage in steps and then saves the repository
    /// config into it. The config writer's own cases already prove it publishes
    /// into a bare stage, so when admission refuses at that save, the cause has
    /// to be something the stage gained on the way rather than the writer. Each
    /// case below adds one construction step and then publishes through the
    /// same entry admission uses, so the first one to refuse names the step
    /// that caused it instead of leaving a whole transaction under suspicion.
    #[test]
    fn a_bare_stage_publishes_its_config() {
        let parent = tempfile::tempdir().unwrap();
        let stage = canonical_stage(&parent);
        publish_staged_config(&stage);
    }

    #[test]
    fn a_stage_holding_its_authority_backend_publishes_its_config() {
        let parent = tempfile::tempdir().unwrap();
        let stage = canonical_stage(&parent);
        let layout = KinLayout::new(stage.clone());
        // Held across the save, exactly as admission holds it.
        let _backend = create_staged_repository_authority_backend(&layout.kindb_dir())
            .expect("create staged authority backend");
        publish_staged_config(&stage);
    }

    #[test]
    fn a_stage_with_its_projection_control_directory_publishes_its_config() {
        let parent = tempfile::tempdir().unwrap();
        let stage = canonical_stage(&parent);
        crate::tree::initialize_projection_control_directory(&stage)
            .expect("initialize projection control directory");
        publish_staged_config(&stage);
    }

    /// The platform fact `open_to_flush` exists for.
    ///
    /// Windows refuses `FlushFileBuffers` on a handle without write access,
    /// while the identical Unix `fsync` on a read-only descriptor is legal.
    /// That asymmetry is the whole reason publication opens staged files for
    /// write, so it is asserted rather than left as a claim in a comment: if
    /// Windows ever stops refusing, this fails and the extra access being
    /// requested can be given back. Pairing the refusal with the same flush
    /// succeeding through `open_to_flush` is what keeps a refusal arriving for
    /// some unrelated reason from passing as this one.
    #[cfg(windows)]
    #[test]
    fn a_read_only_handle_cannot_flush_on_windows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged.toml");
        std::fs::write(&path, b"mode = \"native\"\n").unwrap();

        let refused = File::open(&path)
            .expect("a read-only handle opens")
            .sync_all()
            .expect_err("a read-only handle must not be able to flush on Windows");
        let access_denied = i32::try_from(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED)
            .expect("a documented WIN32_ERROR fits an i32");
        assert_eq!(
            refused.raw_os_error(),
            Some(access_denied),
            "the refusal must be the documented access denial, not something else: {refused}"
        );

        open_to_flush(&path)
            .expect("a writable handle opens")
            .sync_all()
            .expect("the same file must flush through a writable handle");
    }

    /// Publication flushes a staged layout, so every file in one must flush.
    ///
    /// This is the call `kin init` refused at on native Windows. The walk sorts
    /// each directory's children, and a staged layout opens with the empty
    /// directories `adapters`, `backups`, and `bench`, so `config.toml` is the
    /// first regular file it reaches and was the name every access denial
    /// carried. Building the layout the way preparation builds it is what makes
    /// this case reach the same file in the same order.
    #[test]
    fn a_staged_layout_flushes_every_file_it_holds() {
        let parent = tempfile::tempdir().unwrap();
        let stage = canonical_stage(&parent);
        let layout = KinLayout::new(stage.clone());
        for directory in layout.all_dirs() {
            std::fs::create_dir_all(&directory).expect("create a staged layout directory");
        }
        std::fs::write(layout.version_path(), KIN_LAYOUT_VERSION.to_string())
            .expect("write the staged layout version");
        KinConfig::default()
            .save_initialization_stage(&stage)
            .expect("publish the staged repository config");

        sync_layout_recursively(&stage).expect("a staged layout must flush before publication");
    }

    /// Orphan recovery stays disabled where it cannot prove what it reaps.
    ///
    /// The reaping cases are gated to Unix because this returns zero without
    /// scanning anywhere else. Asserting that here is what keeps the gate a
    /// stated platform boundary rather than a silent hole: if recovery is ever
    /// implemented off Unix, this fails and sends the reader to the cases that
    /// should then be ungated.
    #[cfg(not(unix))]
    #[test]
    fn orphan_recovery_is_disabled_off_unix() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap();
        let repository = parent.join("repository");
        std::fs::create_dir(&repository).unwrap();
        let final_kin = repository.canonicalize().unwrap().join(".kin");
        let staging_root = parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        let mut prepared = prepare_repository_layout_at(
            &staging_root,
            &final_kin,
            KinConfig::default(),
            KinManifest::new(),
        )
        .unwrap();
        prepared.cleanup_armed = false;
        drop(prepared);

        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            0,
            "recovery must reap nothing where it cannot prove ownership"
        );
        assert!(
            staging_root.is_dir(),
            "an unreaped stage must be left exactly where it was"
        );
    }

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
        assert!(result
            .layout
            .root()
            .join("reconciliation/projection.lock")
            .is_file());
        assert!(result
            .layout
            .root()
            .join("reconciliation/authority.key")
            .is_file());
        drop(crate::tree::ExactProjectionFreeze::acquire_existing(directory.path()).unwrap());

        assert_eq!(
            result.head,
            WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap()
            }
        );
        assert_eq!(result.authority.initial_change_id, None);
        assert_eq!(result.authority.workspace.workspace_head, result.head);
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
    fn independent_initializations_hold_an_equal_change_set() {
        let first_directory = tempfile::tempdir().unwrap();
        let second_directory = tempfile::tempdir().unwrap();
        let first = init(first_directory.path()).unwrap();
        let second = init(second_directory.path()).unwrap();

        // Replication between two repositories that were initialized separately
        // compares the changes each side holds. Initialization admits no
        // history, so neither side carries a synthesized root whose payload
        // could differ. A synthetic root stamped at initialization time would
        // make these sets unequal and first contact unreconcilable.
        let first_changes = held_change_ids(&first);
        let second_changes = held_change_ids(&second);
        assert!(first_changes.is_empty());
        assert_eq!(first_changes, second_changes);

        assert_eq!(first.authority.initial_change_id, None);
        assert_eq!(second.authority.initial_change_id, None);
        assert_eq!(first.head, second.head);
        assert_eq!(
            first.authority.workspace.base_target,
            second.authority.workspace.base_target
        );
        assert_eq!(
            first.authority.workspace.base_tree_hash,
            second.authority.workspace.base_tree_hash
        );
        assert_eq!(
            first.authority.workspace.workspace_tree_hash,
            second.authority.workspace.workspace_tree_hash
        );
        assert_eq!(
            first.authority.workspace.workspace_semantic_overlay_hash,
            second.authority.workspace.workspace_semantic_overlay_hash
        );

        // Repository and workspace identity stay per-repository. Only history
        // is shared across a replication boundary.
        assert_ne!(first.repository_id, second.repository_id);
        assert_ne!(first.workspace_id, second.workspace_id);
    }

    #[test]
    fn replica_adopts_the_remote_default_ref_without_inventing_main() {
        let directory = tempfile::tempdir().unwrap();
        let result = init_replica(directory.path(), "trunk").unwrap();

        assert_eq!(
            result.head,
            WorkspaceHead::Symbolic {
                target: RefName::branch(b"trunk").unwrap()
            }
        );
        assert_ne!(
            result.head,
            WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap()
            }
        );
        let loaded = KinConfig::load(&result.layout.config_path()).unwrap();
        assert_eq!(loaded.default_branch, "trunk");

        // A replica carries no history of its own. Import supplies it, so the
        // replica is comparable with the remote at first contact.
        assert_eq!(result.authority.initial_change_id, None);
        assert!(held_change_ids(&result).is_empty());
        assert_eq!(result.authority.workspace.base_target, None);
    }

    #[test]
    fn replica_and_plain_init_differ_only_in_the_adopted_ref() {
        let replica_directory = tempfile::tempdir().unwrap();
        let init_directory = tempfile::tempdir().unwrap();
        let replica = init_replica(replica_directory.path(), "main").unwrap();
        let plain = init(init_directory.path()).unwrap();

        assert_eq!(replica.head, plain.head);
        assert_eq!(held_change_ids(&replica), held_change_ids(&plain));
        assert_eq!(
            replica.authority.workspace.workspace_tree_hash,
            plain.authority.workspace.workspace_tree_hash
        );
        assert_eq!(
            replica.authority.workspace.workspace_semantic_overlay_hash,
            plain.authority.workspace.workspace_semantic_overlay_hash
        );
    }

    #[test]
    fn replica_rejects_an_invalid_remote_default_ref() {
        let parent = tempfile::tempdir().unwrap();
        let repository = parent.path().join("replica");
        std::fs::create_dir(&repository).unwrap();

        assert!(init_replica(&repository, "").is_err());
        assert!(!repository.join(".kin").exists());
        let leftovers = std::fs::read_dir(parent.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".kin.init-"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
    }

    /// The whole point of adoption: the replica is a replica of the remote's
    /// repository, not of a repository that happens to hold the same files.
    #[test]
    fn an_adopting_replica_takes_the_remote_identity_and_mints_only_its_workspace() {
        let remote_directory = tempfile::tempdir().unwrap();
        let replica_directory = tempfile::tempdir().unwrap();
        let remote = init(remote_directory.path()).unwrap();
        let replica =
            init_replica_adopting(replica_directory.path(), "main", &remote.repository_id).unwrap();

        assert_eq!(replica.repository_id, remote.repository_id);
        assert_ne!(replica.workspace_id, remote.workspace_id);

        // The adopted identity is what the replica's own authority records,
        // not only what its manifest says.
        let manifest = KinManifest::load(&replica.layout.manifest_path()).unwrap();
        assert_eq!(manifest.repo_id, remote.repository_id.to_string());
        assert_ne!(manifest.workspace_id, remote.manifest.workspace_id);
        let authority = RepositoryAuthorityManager::open(
            replica.repository_id.clone(),
            Arc::new(LocalFileBackend::new(replica.layout.kindb_dir())),
        )
        .unwrap();
        assert_eq!(
            authority
                .read_authority()
                .snapshot()
                .repository_authority
                .as_ref()
                .unwrap()
                .repository_id,
            remote.repository_id
        );

        // Adoption imports no history. The transfer that follows is what does.
        assert_eq!(replica.authority.initial_change_id, None);
        assert!(held_change_ids(&replica).is_empty());
    }

    #[test]
    fn a_plain_replica_still_mints_its_own_identity() {
        let first_directory = tempfile::tempdir().unwrap();
        let second_directory = tempfile::tempdir().unwrap();
        let first = init_replica(first_directory.path(), "main").unwrap();
        let second = init_replica(second_directory.path(), "main").unwrap();

        assert_ne!(first.repository_id, second.repository_id);
        assert_ne!(first.workspace_id, second.workspace_id);
    }

    /// A directory that already holds a replica must never be re-identified,
    /// and the refusal has to name the identity that is already there: a caller
    /// who cloned into the wrong directory cannot act on a bare path.
    #[test]
    fn adopting_over_an_existing_replica_names_both_identities() {
        let directory = tempfile::tempdir().unwrap();
        let existing = init(directory.path()).unwrap();
        let adopted = RepositoryId::new(uuid::Uuid::new_v4().to_string()).unwrap();

        let error = init_replica_adopting(directory.path(), "main", &adopted).unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, KinError::AlreadyInitialized(_)),
            "{message}"
        );
        assert!(
            message.contains(&existing.repository_id.to_string()),
            "{message}"
        );
        assert!(message.contains(&adopted.to_string()), "{message}");

        // Nothing was re-identified.
        let manifest = KinManifest::load(&existing.layout.manifest_path()).unwrap();
        assert_eq!(manifest.repo_id, existing.repository_id.to_string());
    }

    #[test]
    fn adopting_the_identity_already_present_is_still_refused() {
        let directory = tempfile::tempdir().unwrap();
        let existing = init(directory.path()).unwrap();

        let error =
            init_replica_adopting(directory.path(), "main", &existing.repository_id).unwrap_err();
        assert!(matches!(error, KinError::AlreadyInitialized(_)));
        assert!(error
            .to_string()
            .contains(&existing.repository_id.to_string()));
    }

    /// A clone adopts the identity its peer published, whatever shape that is,
    /// and refuses one the local store could not be keyed by. Both halves are
    /// asserted here because this entry point is the one that adopts an
    /// identity the local operator did not choose.
    ///
    /// This test used to require a UUID v4 and refuse everything else. That was
    /// right while a peer could only ever be another locally minted repository,
    /// and wrong the moment a peer could be a hosted one, whose repositories are
    /// named by slug. `RepositoryId` says so itself: hosted slugs and UUID text
    /// are both valid. What survives from the old contract is the part that was
    /// always the point, that an identity this store cannot serve is refused
    /// before a layout is staged rather than after.
    #[test]
    fn a_remote_identity_is_adopted_when_the_store_can_be_keyed_by_it_and_refused_when_it_cannot() {
        let parent = tempfile::tempdir().unwrap();

        for adopted in [
            RepositoryId::new("hosted-repo-42").unwrap(),
            RepositoryId::new(uuid::Uuid::new_v4().to_string()).unwrap(),
        ] {
            let replica = parent.path().join(format!("adopted-{}", adopted.as_str()));
            std::fs::create_dir(&replica).unwrap();
            let result = init_replica_adopting(&replica, "main", &adopted)
                .expect("a peer's own identity is adoptable");
            assert_eq!(result.repository_id, adopted);
            assert_eq!(
                KinManifest::load(&result.layout.manifest_path())
                    .unwrap()
                    .repo_id,
                adopted.as_str()
            );
        }

        // A local store is a directory named by its repository id, so these are
        // valid `RepositoryId` values that no local replica can be built on.
        for hostile in ["..", "org/repo", "trailing.", "has space"] {
            let Ok(adopted) = RepositoryId::new(hostile.to_string()) else {
                continue;
            };
            let replica = parent.path().join("refused");
            std::fs::create_dir_all(&replica).unwrap();
            let error = init_replica_adopting(&replica, "main", &adopted)
                .expect_err("an identity the store cannot be keyed by is refused");
            let message = error.to_string();
            assert!(
                matches!(error, KinError::Config(_)),
                "{hostile:?}: {message}"
            );
            assert!(
                message.contains("portable filesystem component"),
                "{hostile:?}: {message}"
            );
            assert!(
                !replica.join(".kin").exists(),
                "{hostile:?} must be refused before a layout is staged: {message}"
            );
            std::fs::remove_dir_all(&replica).unwrap();
        }
    }

    fn held_change_ids(result: &InitResult) -> std::collections::BTreeSet<SemanticChangeId> {
        let authority = RepositoryAuthorityManager::open(
            result.repository_id.clone(),
            Arc::new(LocalFileBackend::new(result.layout.kindb_dir())),
        )
        .unwrap();
        let lease = authority.read_authority();
        lease.snapshot().changes.keys().copied().collect()
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
    fn preparation_never_exposes_partial_final_repository() {
        let directory = tempfile::tempdir().unwrap();
        let final_kin = directory.path().canonicalize().unwrap().join(".kin");
        let (prepared, _) = prepare_unborn(directory.path(), "hidden");

        assert!(!final_kin.exists());
        assert!(prepared.layout.root().is_dir());
        assert!(prepared.layout.config_path().is_file());
        assert!(prepared.layout.manifest_path().is_file());
        assert_eq!(prepared.initial_roots().generation, 0);
        assert!(prepared.bootstrap.is_none());

        let staging_root = prepared.layout.root().to_path_buf();
        let owner_path = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
        drop(prepared);
        assert!(!staging_root.exists());
        assert!(!owner_path.exists());
        assert!(!final_kin.exists());
    }

    #[test]
    fn orphan_recovery_never_reaps_a_live_stage() {
        let directory = tempfile::tempdir().unwrap();
        let final_kin = directory.path().canonicalize().unwrap().join(".kin");
        let (prepared, _) = prepare_unborn(directory.path(), "active-stage");
        let staging_root = prepared.layout.root().to_path_buf();
        let owner_path = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
        let staging_parent = staging_root.parent().unwrap();

        assert_eq!(
            recover_orphaned_repository_stages(staging_parent, &final_kin).unwrap(),
            0
        );
        assert!(staging_root.is_dir());
        assert!(owner_path.is_file());

        drop(prepared);
        assert!(!staging_root.exists());
        assert!(!owner_path.exists());
    }

    /// Reaping is Unix-only, so the case that asserts a reap is too.
    ///
    /// `recover_orphaned_repository_stages` returns zero without scanning
    /// anything off Unix, by the design stated on it: recovery stays disabled
    /// where the platform cannot expose a stable file identity and
    /// current-user ownership. `orphan_recovery_is_disabled_off_unix` below is
    /// what holds that boundary honest, so this stays where the behaviour it
    /// names actually exists rather than being weakened to pass everywhere.
    #[cfg(unix)]
    #[test]
    fn orphan_recovery_reaps_only_an_unlocked_exactly_owned_stage() {
        let directory = tempfile::tempdir().unwrap();
        let final_kin = directory.path().canonicalize().unwrap().join(".kin");
        let (mut prepared, _) = prepare_unborn(directory.path(), "orphan-stage");
        let staging_root = prepared.layout.root().to_path_buf();
        let owner_path = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
        let staging_parent = staging_root.parent().unwrap().to_path_buf();
        prepared.cleanup_armed = false;
        drop(prepared);

        assert!(staging_root.is_dir());
        assert!(owner_path.is_file());
        assert_eq!(
            recover_orphaned_repository_stages(&staging_parent, &final_kin).unwrap(),
            1
        );
        assert!(!staging_root.exists());
        assert!(!owner_path.exists());
    }

    /// A stage left by an interrupted adopting init is still reapable.
    ///
    /// Orphan recovery refuses to act on an owner record this build could not
    /// have written, and it decided that by requiring a UUID v4 repository
    /// identity. Adoption made a second shape writable, so that gate started
    /// skipping the very stages it exists to reclaim: an adopting init killed
    /// mid-run left a private staging root that every later pass walked past in
    /// silence, and for a repository the size of `kin` that is gigabytes nothing
    /// ever comes back for.
    ///
    /// The minted stage beside it is the control. Both are built the same way
    /// and only the identity differs, so a pass that reclaims one and not the
    /// other is measuring the identity and nothing else.
    ///
    /// Unix-only because the thing under test is: `recover_orphaned_repository_stages`
    /// returns `Ok(0)` unconditionally off Unix, so on Windows nothing is ever
    /// reclaimed and a reclaim count would measure the platform rather than the
    /// identity. `orphan_recovery_retains_non_private_or_hard_linked_owner_records`
    /// is gated for the same reason; the recovery tests that stay ungated are the
    /// ones asserting a count of zero, which is true on both.
    #[cfg(unix)]
    #[test]
    fn orphan_recovery_reclaims_a_stage_whose_repository_identity_was_adopted() {
        for (label, manifest, origin) in [
            (
                "adopted",
                KinManifest::adopting("kin-db"),
                RepositoryIdentityOrigin::Adopted,
            ),
            (
                "minted",
                KinManifest::new(),
                RepositoryIdentityOrigin::Minted,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let parent = directory.path().canonicalize().unwrap();
            let final_kin = parent.join(".kin");

            let mut prepared = prepare_repository_layout_with_origin(
                &parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4())),
                &final_kin,
                KinConfig::default(),
                manifest,
                origin,
            )
            .unwrap();
            let stage_root = prepared.layout.root().to_path_buf();
            let owner_path = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
            // Abandon the stage the way a kill does: nothing runs, and what is
            // on disk is all the next pass has to go on.
            prepared.cleanup_armed = false;
            drop(prepared);
            assert!(stage_root.is_dir(), "{label} stage must exist to be reaped");

            assert_eq!(
                recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
                1,
                "an abandoned {label} stage must be reclaimed, not walked past"
            );
            assert!(
                !stage_root.exists(),
                "the {label} stage root must be gone after recovery"
            );
            assert!(
                !owner_path.exists(),
                "the {label} owner record must be gone after recovery"
            );
        }
    }

    #[test]
    fn orphan_recovery_retains_unprovable_and_replaced_stages() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap();
        let final_kin = parent.join(".kin");

        let unproved = parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        create_private_staging_root(&unproved).unwrap();
        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            0
        );
        assert!(unproved.is_dir());

        let (mut prepared, _) = prepare_unborn(directory.path(), "replaced-stage");
        let replaced = prepared.layout.root().to_path_buf();
        let owner = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
        prepared.cleanup_armed = false;
        drop(prepared);
        let original = parent.join(".kin-test-original-stage");
        std::fs::rename(&replaced, &original).unwrap();
        create_private_staging_root(&replaced).unwrap();

        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            0
        );
        assert!(replaced.is_dir());
        assert!(original.is_dir());
        assert!(owner.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn orphan_recovery_retains_non_private_or_hard_linked_owner_records() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap();
        let final_kin = parent.join(".kin");

        let (mut non_private, _) = prepare_unborn(directory.path(), "non-private-owner");
        let non_private_stage = non_private.layout.root().to_path_buf();
        let non_private_owner = non_private.stage_lease.as_ref().unwrap().owner_path.clone();
        non_private.cleanup_armed = false;
        drop(non_private);
        std::fs::set_permissions(&non_private_owner, std::fs::Permissions::from_mode(0o644))
            .unwrap();

        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            0
        );
        assert!(non_private_stage.is_dir());
        assert!(non_private_owner.is_file());

        std::fs::set_permissions(&non_private_owner, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let hard_link = parent.join(".kin-test-hard-linked-owner");
        std::fs::hard_link(&non_private_owner, &hard_link).unwrap();

        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            0
        );
        assert!(non_private_stage.is_dir());
        assert!(non_private_owner.is_file());
        assert!(hard_link.is_file());
    }

    /// Also asserts a reap, so it is bound to the platform that reaps.
    #[cfg(unix)]
    #[test]
    fn orphan_recovery_is_bound_to_the_exact_destination() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap();
        let repository = parent.join("repository");
        let other_repository = parent.join("other");
        std::fs::create_dir(&repository).unwrap();
        std::fs::create_dir(&other_repository).unwrap();
        let final_kin = repository.canonicalize().unwrap().join(".kin");
        let other_final_kin = other_repository.canonicalize().unwrap().join(".kin");
        let staging_root = parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        let mut prepared = prepare_repository_layout_at(
            &staging_root,
            &final_kin,
            KinConfig::default(),
            KinManifest::new(),
        )
        .unwrap();
        prepared.cleanup_armed = false;
        drop(prepared);

        assert_eq!(
            recover_orphaned_repository_stages(&parent, &other_final_kin).unwrap(),
            0
        );
        assert!(staging_root.is_dir());
        assert_eq!(
            recover_orphaned_repository_stages(&parent, &final_kin).unwrap(),
            1
        );
        assert!(!staging_root.exists());
    }

    #[test]
    fn preparation_rejects_aliased_manifest_identities_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = directory
            .path()
            .canonicalize()
            .unwrap()
            .join(".kin.init-aliased-identities");
        let final_kin = directory.path().canonicalize().unwrap().join(".kin");
        let mut manifest = KinManifest::new();
        manifest.workspace_id.clone_from(&manifest.repo_id);

        let error =
            prepare_repository_layout_at(&staging_root, &final_kin, KinConfig::default(), manifest)
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("repository and workspace manifest identities must be distinct"));
        assert!(!staging_root.exists());
    }

    #[test]
    fn staged_source_batch_stages_the_same_bodies_as_repeated_single_writes() {
        let batched_dir = tempfile::tempdir().unwrap();
        let (batched, _) = prepare_unborn(batched_dir.path(), "batched");
        let single_dir = tempfile::tempdir().unwrap();
        let (single, _) = prepare_unborn(single_dir.path(), "single");

        let bodies: Vec<Vec<u8>> = (0..16)
            .map(|index| format!("staged body {index}\n\0\u{feff}").into_bytes())
            .collect();
        let digests: Vec<Hash256> = bodies
            .iter()
            .map(|body| Hash256::from_bytes(Sha256::digest(body).into()))
            .collect();

        batched
            .with_source_blob_batch(&mut |batch| {
                for (digest, body) in digests.iter().zip(&bodies) {
                    batch.save(*digest, body)?;
                }
                Ok(())
            })
            .expect("one session stages every body");
        for (digest, body) in digests.iter().zip(&bodies) {
            single.save_source_blob(*digest, body).unwrap();
        }

        for (digest, body) in digests.iter().zip(&bodies) {
            assert_eq!(
                batched.load_source_blob(*digest).unwrap().as_ref(),
                Some(body),
                "a batched body must be readable at its content identity"
            );
            assert_eq!(
                batched.load_source_blob(*digest).unwrap(),
                single.load_source_blob(*digest).unwrap(),
                "both paths must stage the same bytes at the same identity"
            );
        }
    }

    #[test]
    fn staged_source_batch_reports_the_callers_own_failure() {
        let directory = tempfile::tempdir().unwrap();
        let (prepared, _) = prepare_unborn(directory.path(), "interrupted");
        let body = b"a body staged before the caller stops";
        let digest = Hash256::from_bytes(Sha256::digest(body).into());

        let error = prepared
            .with_source_blob_batch(&mut |batch| {
                batch.save(digest, body)?;
                Err(KinError::Other("git capture boundary failed".to_string()))
            })
            .expect_err("a session that stops must not report success");
        // The caller's own error survives the kin-db batch boundary instead of
        // arriving as a storage error about a batch the caller never saw.
        assert!(
            matches!(&error, KinError::Other(message) if message == "git capture boundary failed"),
            "{error}"
        );
    }

    #[test]
    fn publish_atomically_reopens_exact_authority_and_source_bodies() {
        let directory = tempfile::tempdir().unwrap();
        let final_kin = directory.path().canonicalize().unwrap().join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "publish");
        let body = b"services:\n  api:\n    image: kin:test\n\0\xff";
        let digest = Hash256::from_bytes(Sha256::digest(body).into());
        prepared.save_source_blob(digest, body).unwrap();
        let staging_root = prepared.layout.root().to_path_buf();
        let owner_path = prepared.stage_lease.as_ref().unwrap().owner_path.clone();
        let expected_repository = prepared.repository_id().clone();

        let bootstrap = prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap()
            .clone();
        let published = publish_repository_layout(prepared).unwrap();

        assert!(!staging_root.exists());
        assert!(!owner_path.exists());
        assert_eq!(published.layout.root(), final_kin);
        assert_eq!(published.authority, bootstrap);
        assert_eq!(published.authority.receipt.generation, 1);
        let reopened = RepositoryAuthorityManager::open(
            expected_repository,
            Arc::new(LocalFileBackend::new(published.layout.kindb_dir())),
        )
        .unwrap();
        assert_eq!(reopened.load_source_blob(digest).unwrap().unwrap(), body);
    }

    #[test]
    fn publish_atomically_moves_an_external_same_filesystem_stage() {
        let container = tempfile::tempdir().unwrap();
        let repository = container.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        let repository = repository.canonicalize().unwrap();
        let staging_root = container
            .path()
            .canonicalize()
            .unwrap()
            .join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        let final_kin = repository.join(".kin");
        let mut prepared = prepare_repository_layout_at(
            &staging_root,
            &final_kin,
            KinConfig::default(),
            KinManifest::new(),
        )
        .unwrap();
        let transaction = build_repository_bootstrap_transaction(
            prepared.initial_roots().clone(),
            prepared.repository_id().clone(),
            prepared.workspace_id(),
            AdmissionCase::Sensitive,
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap();
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();

        let published = publish_repository_layout(prepared).unwrap();

        assert_eq!(published.layout.root(), repository.join(".kin"));
        assert!(!staging_root.exists());
    }

    /// The bootstrap commit reports each of its steps into the admission
    /// phase open on the committing thread, and an exact retry reports none.
    #[test]
    fn a_bootstrap_commit_reports_each_step_into_the_open_admission_phase() {
        let directory = tempfile::tempdir().unwrap();
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "progress");
        let mut progress = crate::init_progress::PhaseProgress::new(1);
        progress.begin("commit bootstrap transaction");

        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        assert_eq!(
            progress.detail_updates(),
            4,
            "validating, committing, binding and summarizing must each advance the phase line"
        );

        prepared.commit_repository_bootstrap(transaction).unwrap();
        assert_eq!(
            progress.detail_updates(),
            4,
            "an exact retry returns the existing bootstrap without reporting new work"
        );
    }

    #[test]
    fn bootstrap_allows_only_exact_operation_retry() {
        let directory = tempfile::tempdir().unwrap();
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "retry");

        let first = prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap()
            .clone();
        let replay = prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap()
            .clone();
        assert_eq!(first, replay);

        let mut different = transaction;
        different.operation_id = OperationId::new();
        let error = prepared
            .commit_repository_bootstrap(different.clone())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("already has a different bootstrap transaction"));
    }

    #[test]
    fn bootstrap_rejects_a_default_ref_that_disagrees_with_prepared_config() {
        let directory = tempfile::tempdir().unwrap();
        let (mut prepared, mut transaction) =
            prepare_unborn(directory.path(), "default-ref-mismatch");
        transaction.default_ref_mutation = None;

        let error = prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap_err();

        assert!(error.to_string().contains("default ref must exactly match"));
        assert_eq!(
            prepared
                .authority()
                .unwrap()
                .read_authority()
                .roots()
                .generation,
            0
        );
    }

    #[test]
    fn git_bootstrap_uses_raw_symbolic_head_instead_of_native_config_default() {
        struct EmptyBodyLoader;
        impl GitObjectBodyLoader for EmptyBodyLoader {
            type Error = &'static str;

            fn load_body(
                &mut self,
                _body_hash: &Hash256,
            ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (prepared, mut transaction) = prepare_unborn(directory.path(), "git-default-ref");
        let git_default = RefName::branch(b"future").unwrap();
        let git_head = WorkspaceHead::Symbolic {
            target: git_default.clone(),
        };
        let authority = GitExternalAuthority::from_raw_parts(
            prepared.repository_id().clone(),
            GitObjectFormat::Sha1,
            Vec::new(),
            GitRawTarget::Symbolic {
                target: git_default.clone(),
            },
            Vec::new(),
            &mut EmptyBodyLoader,
        )
        .unwrap();
        transaction.git_authority_delta = Some(GitExternalAuthorityDelta::initialize(authority));
        transaction.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(git_default),
        });
        transaction.workspace_mutation.as_mut().unwrap().new_head = git_head;

        validate_bootstrap_transaction(
            &transaction,
            prepared.repository_id(),
            prepared.workspace_id(),
            prepared.default_ref(),
            prepared.initial_roots(),
        )
        .unwrap();
    }

    #[test]
    fn metadata_mutation_fails_before_repository_visibility() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "metadata-drift");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();
        std::fs::write(
            prepared.layout.config_path(),
            b"default_branch = \"other\"\n",
        )
        .unwrap();

        let error = publish_repository_layout(prepared).unwrap_err();

        assert!(error.to_string().contains("repository config changed"));
        assert!(!final_kin.exists());
        assert!(!staging_root.exists());
    }

    #[test]
    fn post_rename_failure_is_reported_as_published_but_uncertain() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "uncertain");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error = publish_repository_layout_linearized(prepared, |publication| {
            let published = publication.publish()?;
            std::fs::remove_file(published.path().join("manifest.json")).unwrap();
            Ok(())
        })
        .unwrap_err();

        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(final_kin.exists());
        assert!(!staging_root.exists());
    }

    #[test]
    fn publish_never_replaces_a_destination_created_after_preparation() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "collision");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        std::fs::create_dir(&final_kin).unwrap();
        let sentinel = final_kin.join("belongs-to-another-process");
        std::fs::write(&sentinel, b"do not replace").unwrap();
        let error = publish_repository_layout(prepared).unwrap_err();

        assert!(matches!(error, KinError::Io { .. }));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"do not replace");
        assert!(!staging_root.exists());
    }

    #[test]
    fn failed_final_source_check_discards_unpublished_authority() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "final-check");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error = publish_repository_layout_linearized(prepared, |_publication| {
            Err(KinError::Other(
                "source changed during final migration preflight".to_string(),
            ))
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("source changed during final migration preflight"));
        assert!(!final_kin.exists());
        assert!(!staging_root.exists());
    }

    #[test]
    fn successful_verifier_cannot_skip_the_one_shot_publication() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "unused-capability");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error =
            publish_repository_layout_linearized(prepared, |_publication| Ok(())).unwrap_err();

        assert!(error
            .to_string()
            .contains("without consuming its one-shot capability"));
        assert!(!final_kin.exists());
        assert!(!staging_root.exists());
    }

    #[test]
    fn verifier_error_after_atomic_publication_is_fail_loud_and_not_rolled_back() {
        let directory = tempfile::tempdir().unwrap();
        let working_dir = directory.path().canonicalize().unwrap();
        let final_kin = working_dir.join(".kin");
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "post-publish-check");
        prepared
            .commit_repository_bootstrap(transaction.clone())
            .unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error = publish_repository_layout_linearized(prepared, |publication| {
            let _published = publication.publish()?;
            Err(KinError::Other(
                "external source drifted after publication".to_string(),
            ))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            KinError::RepositoryPublishedButUncertain { .. }
        ));
        assert!(error
            .to_string()
            .contains("external source drifted after publication"));
        assert!(final_kin.is_dir());
        assert!(!staging_root.exists());
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
            external_reference_deltas: Vec::new(),
        };
        initial_change.id = compute_semantic_change_id(&initial_change).unwrap();

        let kindb = directory.path().join("kindb");
        let backend = create_staged_repository_authority_backend(&kindb).unwrap();
        let authority = RepositoryAuthorityManager::open(repository_id.clone(), backend).unwrap();
        let bootstrap = initialize_repository_authority(
            &authority,
            repository_id.clone(),
            workspace_id,
            AdmissionCase::Sensitive,
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

    #[test]
    fn bootstrap_refuses_to_recreate_a_missing_authority_root() {
        let directory = tempfile::tempdir().unwrap();
        let kindb = directory.path().join("missing-kindb");
        let repository_id = RepositoryId::new("missing-root-repository").unwrap();
        let authority = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(&kindb)),
        )
        .unwrap();

        let error = initialize_repository_authority(
            &authority,
            repository_id,
            WorkspaceId::new(),
            AdmissionCase::Sensitive,
            RefName::branch(b"main").unwrap(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("refusing to recreate a detached authority namespace"));
        assert!(
            !kindb.exists(),
            "bootstrap through an unanchored backend must not create its missing root"
        );
    }

    /// The replacement this detects cannot be staged on Windows at all.
    ///
    /// The case works by renaming the authority root out from under a live
    /// backend. On Windows that rename is refused with a sharing violation,
    /// because the backend retains directory handles that withhold DELETE
    /// sharing, so the scenario cannot be constructed and the test fails in
    /// its own setup rather than in the behaviour it checks. Windows excludes
    /// the replacement where Unix detects it, which is the stronger of the two
    /// and is why this is gated rather than weakened.
    #[cfg(unix)]
    #[test]
    fn staged_authority_backend_rejects_a_replaced_root() {
        let directory = tempfile::tempdir().unwrap();
        let kindb = directory.path().join("kindb");
        let detached = directory.path().join("detached-kindb");
        let backend = create_staged_repository_authority_backend(&kindb).unwrap();
        std::fs::rename(&kindb, &detached).unwrap();
        create_private_staging_root(&kindb).unwrap();
        let repository_id = RepositoryId::new("replaced-root-repository").unwrap();

        let error = match RepositoryAuthorityManager::open(repository_id.clone(), backend) {
            Ok(_) => panic!("backend accepted a replacement authority root"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("changed since this backend opened"));
        assert!(
            !kindb.join(repository_id.as_str()).exists(),
            "replacement root must remain untouched"
        );
        assert!(
            detached.is_dir(),
            "original authority root remains recoverable"
        );
    }
}
