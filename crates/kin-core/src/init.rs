// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs2::FileExt as _;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_model::{
    compute_resolved_tree_hash, AdmissionCase, AdmissionPolicyDelta, AdmissionScanToken, AuthorId,
    DefaultRefExpectation, DefaultRefMutation, EffectiveAdmissionPolicyStamp, ExternalObjectId,
    ExternalObjectKind, FrozenLocalOverlay, FrozenLocalOverlayDelta, GitMaterialHead, GitRawTarget,
    Hash256, OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryAuthorityStore, RepositoryCommitReceipt, RepositoryId, RepositoryTransaction,
    RootBundle, SemanticChange, SemanticChangeId, SharedAdmissionPolicy, WorkspaceExpectation,
    WorkspaceHead, WorkspaceId, WorkspaceMutation, WorkspaceSnapshotBinding,
    ADMISSION_POLICY_SEMANTICS_VERSION, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::KinConfig;
use crate::error::{KinError, Result};
use crate::layout::{KinLayout, KIN_LAYOUT_VERSION};
use crate::manifest::KinManifest;

const INIT_STAGE_PREFIX: &str = ".kin.init-";
const INIT_STAGE_OWNER_SUFFIX: &str = ".owner";
const INIT_STAGE_OWNER_SCHEMA_VERSION: u32 = 1;
const MAX_INIT_STAGE_OWNER_BYTES: u64 = 16 * 1024;

/// Result of creating a repository authority envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Exact material workspace HEAD established by initialization.
    ///
    /// Symbolic targets retain byte-exact `RefName` identity. Detached Git
    /// annotated tags are represented by their verified peeled commit; their
    /// exact raw tag target remains in `GitExternalAuthority`.
    pub head: WorkspaceHead,
    pub authority: RepositoryBootstrap,
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

    /// Commit exactly one complete generation-zero to generation-one
    /// repository transition.
    ///
    /// Repeating the exact transaction returns the existing bootstrap. A
    /// different transaction is rejected once bootstrap authority exists.
    pub fn commit_repository_bootstrap(
        &mut self,
        transaction: &RepositoryTransaction,
    ) -> Result<&RepositoryBootstrap> {
        verify_metadata_seal(&self.layout, &self.metadata_seal)?;
        let transaction_hash = transaction
            .transaction_hash()
            .map_err(|error| KinError::Other(error.to_string()))?;
        let repository_id = &self.repository_id;
        let workspace_id = self.workspace_id;
        let default_ref = &self.default_ref;
        let initial_roots = &self.initial_roots;
        let authority = self.authority.as_ref().ok_or_else(|| {
            KinError::Other("staged repository authority is no longer open".to_string())
        })?;
        match &mut self.bootstrap {
            Some(bootstrap) => {
                if bootstrap.receipt.transaction_hash != transaction_hash
                    || bootstrap.receipt.operation_id != transaction.operation_id
                {
                    return Err(KinError::Other(
                        "staged repository already has a different bootstrap transaction"
                            .to_string(),
                    ));
                }
                Ok(bootstrap)
            }
            slot @ None => {
                validate_bootstrap_transaction(
                    transaction,
                    repository_id,
                    workspace_id,
                    default_ref,
                    initial_roots,
                )?;
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

impl Drop for PreparedRepositoryInit {
    fn drop(&mut self) {
        if self.cleanup_armed {
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

    let config = KinConfig::default();
    let manifest = KinManifest::new();
    let staging_parent = canonical_working_dir.parent().ok_or_else(|| {
        KinError::Other(format!(
            "repository root has no parent for atomic staging: {}",
            canonical_working_dir.display()
        ))
    })?;
    let staging_dir = staging_parent.join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
    let mut prepared = prepare_repository_layout_at(&staging_dir, &kin_dir, config, manifest)?;
    let transaction = build_repository_bootstrap_transaction(
        prepared.initial_roots().clone(),
        prepared.repository_id().clone(),
        prepared.workspace_id(),
        prepared.default_ref().clone(),
        SharedAdmissionPolicy::empty(0),
        None,
    )?;
    prepared.commit_repository_bootstrap(&transaction)?;
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

/// Create a complete unpublished repository layout at an explicit staging
/// path. The path must be an absolute, direct child of an existing directory
/// and its name must begin with `.kin.init-`.
pub fn prepare_repository_layout_at(
    staging_kin_dir: &Path,
    final_kin_dir: &Path,
    config: KinConfig,
    manifest: KinManifest,
) -> Result<PreparedRepositoryInit> {
    config.validate()?;
    let repository_uuid = uuid::Uuid::parse_str(&manifest.repo_id)
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    if repository_uuid.get_version_num() != 4 {
        return Err(KinError::Other(
            "repository manifest identity must be a UUID v4".to_string(),
        ));
    }
    let repository_id = RepositoryId::new(manifest.repo_id.clone())
        .map_err(|error| KinError::Other(format!("invalid repository identity: {error}")))?;
    let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id)
        .map_err(|error| KinError::Other(format!("invalid workspace identity: {error}")))?;
    if workspace_uuid.get_version_num() != 4 {
        return Err(KinError::Other(
            "workspace manifest identity must be a UUID v4".to_string(),
        ));
    }
    if repository_uuid == workspace_uuid {
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
        for directory in layout.all_dirs() {
            std::fs::create_dir(&directory).map_err(|error| KinError::io(&directory, error))?;
        }
        std::fs::write(layout.version_path(), KIN_LAYOUT_VERSION.to_string())
            .map_err(|error| KinError::io(layout.version_path(), error))?;
        config.save(&layout.config_path())?;
        manifest.save(&layout.manifest_path())?;
        let metadata_seal = capture_metadata_seal(&layout)?;

        let backend = Arc::new(LocalFileBackend::new(layout.kindb_dir()));
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
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        builder.mode(0o700);
    }
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

fn stage_id_from_directory_name(name: &str) -> Option<uuid::Uuid> {
    let raw = name.strip_prefix(INIT_STAGE_PREFIX)?;
    let id = uuid::Uuid::parse_str(raw).ok()?;
    (id.get_version_num() == 4 && id.to_string() == raw).then_some(id)
}

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
        stage_identity: recoverable_file_identity(&stage_metadata),
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
    if let Err(error) = owner_file.try_lock_exclusive() {
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

#[cfg(unix)]
fn recoverable_file_identity(metadata: &std::fs::Metadata) -> RecoverableFileIdentity {
    use std::os::unix::fs::MetadataExt;

    RecoverableFileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn recoverable_file_identity(metadata: &std::fs::Metadata) -> RecoverableFileIdentity {
    use std::os::windows::fs::MetadataExt;

    match (metadata.volume_serial_number(), metadata.file_index()) {
        (Some(volume_serial_number), Some(file_index)) => RecoverableFileIdentity::Windows {
            volume_serial_number,
            file_index,
        },
        _ => RecoverableFileIdentity::Unavailable,
    }
}

#[cfg(not(any(unix, windows)))]
fn recoverable_file_identity(_metadata: &std::fs::Metadata) -> RecoverableFileIdentity {
    RecoverableFileIdentity::Unavailable
}

/// Atomically publish a fully bootstrapped staged repository as the final
/// `.kin` directory without replacing any existing entry.
pub fn publish_repository_layout(prepared: PreparedRepositoryInit) -> Result<InitResult> {
    publish_repository_layout_with_hooks(prepared, || Ok(()), |_| {})
}

/// Publish a staged repository only if one final read-only source check passes.
///
/// The callback runs after the staged authority has been durably synced,
/// closed, reopened, verified, and synced again, immediately before the atomic
/// no-replace rename. A callback error leaves the final `.kin` absent and arms
/// normal staged cleanup. Git migration uses this boundary to repeat its exact
/// source preflight without allowing the staging directory to contaminate the
/// observed worktree.
pub fn publish_repository_layout_after_check(
    prepared: PreparedRepositoryInit,
    before_rename: impl FnOnce() -> Result<()>,
) -> Result<InitResult> {
    publish_repository_layout_with_hooks(prepared, before_rename, |_| {})
}

fn publish_repository_layout_with_hooks(
    mut prepared: PreparedRepositoryInit,
    before_rename: impl FnOnce() -> Result<()>,
    after_rename: impl FnOnce(&Path),
) -> Result<InitResult> {
    let final_kin_dir = prepared.final_kin_dir.clone();
    let final_kin_dir = final_kin_dir.as_path();
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

    sync_layout_recursively(prepared.layout.root())?;
    drop(prepared.authority.take());
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
    before_rename()?;
    rename_directory_noreplace(prepared.layout.root(), final_kin_dir)?;
    prepared.cleanup_armed = false;
    let owner_cleanup = prepared
        .stage_lease
        .take()
        .ok_or_else(|| KinError::Other("repository stage lease is missing".to_string()))
        .and_then(remove_stage_owner);
    after_rename(final_kin_dir);

    let source_parent = prepared
        .layout
        .root()
        .parent()
        .expect("validated staged path always has a parent");
    let destination_parent = final_kin_dir
        .parent()
        .expect("validated final .kin path always has a parent");
    let parent_sync =
        owner_cleanup.and_then(|()| sync_publication_parents(source_parent, destination_parent));
    let layout = KinLayout::new(final_kin_dir.to_path_buf());
    let final_verification = verify_repository_layout(
        &layout,
        &prepared.metadata_seal,
        &prepared.repository_id,
        prepared.workspace_id,
        &bootstrap,
    );
    let (config, manifest) = match (parent_sync, final_verification) {
        (Ok(()), Ok(metadata)) => metadata,
        (Err(sync_error), Ok(_)) => {
            return Err(published_uncertain(final_kin_dir, sync_error));
        }
        (Ok(()), Err(verification_error)) => {
            return Err(published_uncertain(final_kin_dir, verification_error));
        }
        (Err(sync_error), Err(verification_error)) => {
            return Err(KinError::RepositoryPublishedButUncertain {
                path: final_kin_dir.display().to_string(),
                detail: format!(
                    "parent namespace sync failed: {sync_error}; final verification failed: \
                     {verification_error}"
                ),
            });
        }
    };

    Ok(InitResult {
        layout,
        config,
        manifest,
        repository_id: prepared.repository_id.clone(),
        workspace_id: prepared.workspace_id,
        head: bootstrap.workspace.workspace_head.clone(),
        authority: bootstrap,
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

fn published_uncertain(final_kin_dir: &Path, error: KinError) -> KinError {
    KinError::RepositoryPublishedButUncertain {
        path: final_kin_dir.display().to_string(),
        detail: error.to_string(),
    }
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
    let initial_roots = authority.read_authority().roots().clone();
    let prepared_default_ref = default_ref.clone();
    let transaction = build_repository_bootstrap_transaction(
        initial_roots.clone(),
        repository_id.clone(),
        workspace_id,
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
    commit_bootstrap_transaction(authority, &transaction, &repository_id, workspace_id)
}

fn build_repository_bootstrap_transaction(
    initial_roots: RootBundle,
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
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
    let local_overlay =
        FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
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
    transaction: &RepositoryTransaction,
    repository_id: &RepositoryId,
    workspace_id: WorkspaceId,
) -> Result<RepositoryBootstrap>
where
    B: StorageBackend + 'static,
{
    let receipt = authority
        .commit_repository_transaction(transaction.clone())
        .map_err(graph_error)?;
    let workspace = authority
        .workspace_snapshot_binding(repository_id, &workspace_id)
        .map_err(graph_error)?
        .ok_or_else(|| {
            KinError::Graph(format!(
                "repository authority committed without workspace {workspace_id}"
            ))
        })?;
    if workspace.roots != receipt.roots_after {
        return Err(KinError::Graph(
            "repository bootstrap workspace is not bound to the committed roots".to_string(),
        ));
    }
    workspace
        .validate()
        .map_err(|error| KinError::Other(error.to_string()))?;
    let initial_change_id = transaction
        .workspace_mutation
        .as_ref()
        .and_then(|mutation| match mutation.new_base_target {
            Some(RefTarget::Change { change_id }) => Some(change_id),
            _ => None,
        });
    Ok(RepositoryBootstrap {
        receipt,
        workspace,
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

fn capture_metadata_seal(layout: &KinLayout) -> Result<RepositoryMetadataSeal> {
    let config_bytes = std::fs::read(layout.config_path())
        .map_err(|error| KinError::io(layout.config_path(), error))?;
    let manifest_bytes = std::fs::read(layout.manifest_path())
        .map_err(|error| KinError::io(layout.manifest_path(), error))?;
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
    let observed = std::fs::read(path).map_err(|error| KinError::io(path, error))?;
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
        let file = std::fs::File::open(path).map_err(|error| KinError::io(path, error))?;
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
        || recoverable_file_identity(&open_metadata) != recoverable_file_identity(&path_metadata)
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
            != recoverable_file_identity(
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

#[cfg(not(unix))]
fn open_stage_owner_for_recovery(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| KinError::io(path, error))
}

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
fn recover_orphaned_repository_stages(
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
                    warn!(
                        path = %owner_path.display(),
                        %error,
                        "retaining unprovable repository stage owner"
                    );
                    continue;
                }
            };
            if owner_file.try_lock_exclusive().is_err() {
                continue;
            }
            let record = match read_stage_owner_record(&owner_file, &owner_path) {
                Ok(record) => record,
                Err(error) => {
                    warn!(
                        path = %owner_path.display(),
                        %error,
                        "retaining repository stage with invalid owner record"
                    );
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
            if repository_uuid.is_none_or(|id| {
                id.get_version_num() != 4 || id.to_string() != record.repository_id
            }) || workspace_uuid
                .is_none_or(|id| id.get_version_num() != 4 || id.to_string() != record.workspace_id)
                || repository_uuid == workspace_uuid
            {
                continue;
            }
            let reap_root = staging_parent.join(format!(".kin.reap-{stage_id}"));
            let stage_exists = match filesystem_entry_exists(&stage_root) {
                Ok(exists) => exists,
                Err(error) => {
                    warn!(
                        path = %stage_root.display(),
                        %error,
                        "retaining repository stage whose presence is not provable"
                    );
                    continue;
                }
            };
            let reap_exists = match filesystem_entry_exists(&reap_root) {
                Ok(exists) => exists,
                Err(error) => {
                    warn!(
                        path = %reap_root.display(),
                        %error,
                        "retaining repository stage whose recovery state is not provable"
                    );
                    continue;
                }
            };
            if stage_exists && reap_exists {
                warn!(
                    stage = %stage_root.display(),
                    reap = %reap_root.display(),
                    "retaining ambiguous repository stage recovery state"
                );
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
                || recoverable_file_identity(
                    &std::fs::symlink_metadata(owned_root)
                        .map_err(|error| KinError::io(owned_root, error))?,
                ) != record.stage_identity
            {
                warn!(
                    path = %owned_root.display(),
                    "retaining repository stage whose filesystem identity is not provable"
                );
                continue;
            }
            if owned_root == &stage_root {
                if let Err(error) = rename_directory_noreplace(&stage_root, &reap_root) {
                    warn!(
                        path = %stage_root.display(),
                        %error,
                        "retaining repository stage after failed recovery claim"
                    );
                    continue;
                }
                let reaped_identity = recoverable_file_identity(
                    &std::fs::symlink_metadata(&reap_root)
                        .map_err(|error| KinError::io(&reap_root, error))?,
                );
                if reaped_identity != record.stage_identity {
                    warn!(
                        path = %reap_root.display(),
                        "retaining claimed repository stage after identity changed"
                    );
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
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap();
        assert!(prepared.bootstrap.is_none());
        (prepared, transaction)
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
            .commit_repository_bootstrap(&transaction)
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
            prepared.default_ref().clone(),
            SharedAdmissionPolicy::empty(0),
            None,
        )
        .unwrap();
        prepared.commit_repository_bootstrap(&transaction).unwrap();

        let published = publish_repository_layout(prepared).unwrap();

        assert_eq!(published.layout.root(), repository.join(".kin"));
        assert!(!staging_root.exists());
    }

    #[test]
    fn bootstrap_allows_only_exact_operation_retry() {
        let directory = tempfile::tempdir().unwrap();
        let (mut prepared, transaction) = prepare_unborn(directory.path(), "retry");

        let first = prepared
            .commit_repository_bootstrap(&transaction)
            .unwrap()
            .clone();
        let replay = prepared
            .commit_repository_bootstrap(&transaction)
            .unwrap()
            .clone();
        assert_eq!(first, replay);

        let mut different = transaction;
        different.operation_id = OperationId::new();
        let error = prepared
            .commit_repository_bootstrap(&different)
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
            .commit_repository_bootstrap(&transaction)
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
        transaction.workspace_mutation.as_mut().unwrap().new_head = git_head.clone();
        transaction
            .admission_scan_token
            .as_mut()
            .unwrap()
            .workspace_head = git_head;

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
        prepared.commit_repository_bootstrap(&transaction).unwrap();
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
        prepared.commit_repository_bootstrap(&transaction).unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error = publish_repository_layout_with_hooks(
            prepared,
            || Ok(()),
            |published| {
                std::fs::remove_file(published.join("manifest.json")).unwrap();
            },
        )
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
        prepared.commit_repository_bootstrap(&transaction).unwrap();
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
        prepared.commit_repository_bootstrap(&transaction).unwrap();
        let staging_root = prepared.layout.root().to_path_buf();

        let error = publish_repository_layout_after_check(prepared, || {
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
