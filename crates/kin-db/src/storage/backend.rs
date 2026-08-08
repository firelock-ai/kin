// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;
use crate::storage::local_journal::{
    delete_quarantined_delta_exact_at, is_quarantine_delta_name, load_quarantined_deltas_at,
    quarantine_delta_path, quarantined_file_matches_at,
};
use crate::storage::mmap::{self, AtomicWriteOutcome};

/// Generation counter for compare-and-swap writes.
///
/// On local filesystems this is a monotonically increasing counter persisted
/// alongside the snapshot. On GCS this maps directly to the object generation.
pub type Generation = u64;

/// Sentinel value indicating no prior generation exists (first write).
pub const GENERATION_INIT: Generation = 0;

/// Opaque backend compare-and-swap cursor for full snapshot authority.
///
/// This is intentionally distinct from Kin's logical repository generation.
/// A local or SQLite backend may happen to allocate `1, 2, ...`, while a cloud
/// provider can return unrelated object versions such as `100, 101, ...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotCursor(Generation);

impl SnapshotCursor {
    pub const INITIAL: Self = Self(GENERATION_INIT);

    pub const fn from_backend_generation(generation: Generation) -> Self {
        Self(generation)
    }

    pub const fn backend_generation(self) -> Generation {
        self.0
    }
}

/// Classified outcome of a full snapshot compare-and-swap attempt.
#[must_use = "a snapshot save outcome must be classified before authority publication"]
#[derive(Debug)]
pub enum SnapshotSaveOutcome {
    /// The exact candidate is installed at `cursor`.
    Committed { cursor: SnapshotCursor },
    /// The backend proved the candidate was not installed.
    NotCommitted(KinDbError),
    /// The backend cannot prove whether the candidate was installed.
    Indeterminate(KinDbError),
}

/// Maximum exact-source object size accepted by any storage backend.
/// Archive consumers may apply a lower aggregate limit, but no individual
/// object is allowed to force an allocation larger than this boundary.
pub const MAX_SOURCE_BLOB_BYTES: u64 = 1024 * 1024 * 1024;

/// One distinct immutable source body requested for a validated batch read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBlobValidationRequest {
    pub digest: [u8; 32],
    pub max_bytes: u64,
}

/// Immutable source bytes whose storage backend verified their SHA-256
/// content identity while loading them.
///
/// The only constructor re-verifies the content identity, so an optimized
/// backend implementation cannot promote arbitrary bytes to a verified body.
/// Higher-level validators may still apply domain-specific checks such as
/// exact Git object identity.
#[derive(Debug)]
pub struct VerifiedSourceBlob {
    digest: [u8; 32],
    bytes: Vec<u8>,
}

/// One integrity-checking immutable-body read session.
///
/// A backend may retain a repository capability or remote read context for
/// the lifetime of this value. Every returned body still passes through
/// [`VerifiedSourceBlob::from_verified_bytes`].
pub trait VerifiedSourceBlobBatch {
    fn load_verified(
        &self,
        request: SourceBlobValidationRequest,
    ) -> Result<Option<VerifiedSourceBlob>, KinDbError>;
}

/// One immutable-body write session against a single repository.
///
/// A backend may hold a repository lock and a retained namespace capability
/// for the lifetime of this value, so a bulk ingest pays the repository
/// authority envelope once instead of once per content address.
///
/// [`save`](Self::save) publishes a body under its content identity with the
/// same validation, no-clobber, and collision rules as
/// [`StorageBackend::save_source_blob`]. It does not promise that the body has
/// reached the storage device: a batch amortizes its durability barriers and
/// discharges them at a flush. Bodies written through a batch are durable when
/// [`StorageBackend::with_source_blob_write_batch`] returns `Ok`, or at an
/// earlier explicit [`flush`](Self::flush).
pub trait SourceBlobWriteBatch {
    /// Publish exact bytes under their SHA-256 content identity.
    fn save(&self, digest: [u8; 32], data: &[u8]) -> Result<(), KinDbError>;

    /// Make every body written since the last flush durable.
    fn flush(&self) -> Result<(), KinDbError>;
}

impl VerifiedSourceBlob {
    /// Bind bytes to `digest` after recomputing their SHA-256 identity.
    pub fn from_verified_bytes(digest: [u8; 32], bytes: Vec<u8>) -> Result<Self, KinDbError> {
        verify_source_blob_digest(digest, &bytes, "verified source blob batch")?;
        Ok(Self { digest, bytes })
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(all(test, unix))]
std::thread_local! {
    static SOURCE_FILE_AFTER_METADATA_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static SOURCE_FILE_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
fn set_source_file_after_metadata_hook(hook: impl FnOnce() + 'static) {
    SOURCE_FILE_AFTER_METADATA_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn run_source_file_after_metadata_hook() {
    SOURCE_FILE_AFTER_METADATA_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(all(not(test), unix))]
fn run_source_file_after_metadata_hook() {}

#[derive(Clone, Copy)]
enum LocalDirectoryBindKind {
    Repository,
    Surface,
    Staging,
}

/// Whether a repository authority lock excludes other holders of the same
/// repository, or only excludes writers.
///
/// Every mutation takes `Exclusive`. `Shared` belongs to entry points that
/// create nothing, rename nothing and delete nothing, so concurrent readers
/// of one repository stop serializing on each other.
#[derive(Clone, Copy)]
enum LocalRepositoryLockAccess {
    Exclusive,
    Shared,
}

#[cfg(test)]
std::thread_local! {
    static REPOSITORY_AFTER_PREOPEN_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static SURFACE_AFTER_PREOPEN_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn set_local_directory_after_preopen_hook(
    kind: LocalDirectoryBindKind,
    hook: impl FnOnce() + 'static,
) {
    match kind {
        LocalDirectoryBindKind::Repository => {
            REPOSITORY_AFTER_PREOPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        }
        LocalDirectoryBindKind::Surface => {
            SURFACE_AFTER_PREOPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        }
        LocalDirectoryBindKind::Staging => {
            panic!("test hooks may not target private randomized staging directories")
        }
    }
}

#[cfg(test)]
fn run_local_directory_after_preopen_hook(kind: LocalDirectoryBindKind) {
    match kind {
        LocalDirectoryBindKind::Repository => {
            REPOSITORY_AFTER_PREOPEN_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().take() {
                    hook();
                }
            });
        }
        LocalDirectoryBindKind::Surface => {
            SURFACE_AFTER_PREOPEN_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().take() {
                    hook();
                }
            });
        }
        LocalDirectoryBindKind::Staging => {}
    }
}

#[cfg(not(test))]
fn run_local_directory_after_preopen_hook(_kind: LocalDirectoryBindKind) {}

#[cfg(test)]
std::thread_local! {
    /// How many times this thread re-resolved the repository namespace from
    /// the filesystem root, and how many digest-prefix capability chains it
    /// walked. Both are load-independent proxies for the per-object syscall
    /// envelope: a confirmation is roughly twenty syscalls including two
    /// `realpath` calls and a directory-stream read, and a walk is an `openat`
    /// per chain component. A test asserts they are amortized per write
    /// session rather than paid per body.
    static SOURCE_ENVELOPE_REPOSITORY_CONFIRMATIONS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    static SOURCE_ENVELOPE_CAPABILITY_WALKS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_source_blob_capability_walk() {
    SOURCE_ENVELOPE_CAPABILITY_WALKS.with(|walks| walks.set(walks.get() + 1));
}

#[cfg(not(test))]
fn record_source_blob_capability_walk() {}

#[cfg(test)]
fn record_repository_visibility_confirmation() {
    SOURCE_ENVELOPE_REPOSITORY_CONFIRMATIONS
        .with(|confirmations| confirmations.set(confirmations.get() + 1));
}

#[cfg(not(test))]
fn record_repository_visibility_confirmation() {}

/// Repository-visibility confirmations and prefix capability walks recorded on
/// this thread since the last reset.
#[cfg(all(test, unix))]
fn source_envelope_counters() -> (u64, u64) {
    (
        SOURCE_ENVELOPE_REPOSITORY_CONFIRMATIONS.with(std::cell::Cell::get),
        SOURCE_ENVELOPE_CAPABILITY_WALKS.with(std::cell::Cell::get),
    )
}

#[cfg(all(test, unix))]
fn reset_source_envelope_counters() {
    SOURCE_ENVELOPE_REPOSITORY_CONFIRMATIONS.with(|confirmations| confirmations.set(0));
    SOURCE_ENVELOPE_CAPABILITY_WALKS.with(|walks| walks.set(0));
}

#[cfg(test)]
std::thread_local! {
    /// Device cache flushes and ordering barriers this thread issued through
    /// the immutable-source write path. Directory barriers are not counted
    /// here; these are the per-body costs, which are the ones that scale.
    static SOURCE_DEVICE_FLUSHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static SOURCE_ORDERING_BARRIERS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_source_device_flush() {
    SOURCE_DEVICE_FLUSHES.with(|flushes| flushes.set(flushes.get() + 1));
}

#[cfg(not(test))]
fn record_source_device_flush() {}

// Gated to Apple, not merely to unix: `F_BARRIERFSYNC` is the only ordering
// barrier this path issues and it exists nowhere else, so a unix-wide
// definition is dead code on Linux and fails the `-D warnings` gate there.
#[cfg(all(test, target_vendor = "apple"))]
fn record_source_ordering_barrier() {
    SOURCE_ORDERING_BARRIERS.with(|barriers| barriers.set(barriers.get() + 1));
}

#[cfg(all(not(test), target_vendor = "apple"))]
fn record_source_ordering_barrier() {}

/// Device flushes and ordering barriers recorded on this thread since the
/// last reset.
#[cfg(all(test, unix))]
fn source_barrier_counters() -> (u64, u64) {
    (
        SOURCE_DEVICE_FLUSHES.with(std::cell::Cell::get),
        SOURCE_ORDERING_BARRIERS.with(std::cell::Cell::get),
    )
}

#[cfg(all(test, unix))]
fn reset_source_barrier_counters() {
    SOURCE_DEVICE_FLUSHES.with(|flushes| flushes.set(0));
    SOURCE_ORDERING_BARRIERS.with(|barriers| barriers.set(0));
}

/// How a body's own bytes reach the device before the `linkat` that names it.
///
/// `FullDevice` is an `fsync` plus a flush of the drive's write cache. On
/// Apple platforms that is what `File::sync_all` issues: the standard library
/// maps `fsync` to `fcntl(F_FULLFSYNC)` there.
///
/// `Ordering` is Apple's `F_BARRIERFSYNC`, which `fcntl(2)` documents as
/// doing the same thing as `fsync` and then issuing a barrier to the drive,
/// so that everything fsynced on that device beforehand is persisted before
/// any I/O issued after the barrier. That is precisely the data-before-name
/// guarantee this path needs, and the man page names this two-phase use as
/// what the barrier is for. It exists only on HFS and APFS, so every other
/// platform and every unsupported volume resolves back to `FullDevice`, which
/// is the stronger barrier rather than a weaker one.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum SourceBodyBarrier {
    FullDevice,
    Ordering,
}

#[cfg(unix)]
fn issue_source_body_barrier(
    file: &std::fs::File,
    barrier: SourceBodyBarrier,
) -> Result<(), std::io::Error> {
    #[cfg(target_vendor = "apple")]
    if matches!(barrier, SourceBodyBarrier::Ordering) {
        // SAFETY: the descriptor is live for the duration of the call and
        // F_BARRIERFSYNC ignores its argument.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_BARRIERFSYNC) } == 0 {
            record_source_ordering_barrier();
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOTTY) | Some(libc::ENOTSUP) | Some(libc::EINVAL) => {}
            _ => return Err(error),
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    let _ = barrier;
    record_source_device_flush();
    file.sync_all()
}

#[cfg(all(test, unix))]
fn fail_source_file_sync_once() {
    SOURCE_FILE_SYNC_FAILURE.with(|failure| failure.set(true));
}

#[cfg(unix)]
fn sync_source_file_for_ack(file: &std::fs::File, display_path: &Path) -> Result<(), KinDbError> {
    #[cfg(test)]
    let inject_failure = SOURCE_FILE_SYNC_FAILURE.with(|failure| failure.replace(false));
    #[cfg(not(test))]
    let inject_failure = false;
    if inject_failure {
        return Err(KinDbError::StorageError(format!(
            "injected immutable source file fsync failure for {}",
            display_path.display()
        )));
    }
    record_source_device_flush();
    file.sync_all().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to fsync immutable source blob {}: {error}",
            display_path.display()
        ))
    })
}

#[cfg(windows)]
fn sync_source_file_for_ack(file: &std::fs::File, display_path: &Path) -> Result<(), KinDbError> {
    record_source_device_flush();
    file.sync_all().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to flush immutable source blob {}: {error}",
            display_path.display()
        ))
    })
}

pub(crate) fn validate_source_blob_repo_id(repo_id: &str) -> Result<(), KinDbError> {
    if repo_id.is_empty()
        || repo_id.len() > 255
        || matches!(repo_id, "." | "..")
        || repo_id.ends_with(['.', ' '])
        || is_windows_reserved_source_component(repo_id)
        || !repo_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KinDbError::StorageError(format!(
            "invalid repo id {repo_id:?} for immutable source blob storage"
        )));
    }
    Ok(())
}

fn validate_local_storage_component(component: &str, role: &str) -> Result<(), KinDbError> {
    if component.is_empty()
        || component.len() > 255
        || matches!(component, "." | "..")
        || component.ends_with(['.', ' '])
        || is_windows_reserved_source_component(component)
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KinDbError::StorageError(format!(
            "{role} must be one portable filesystem component"
        )));
    }
    Ok(())
}

/// Reject DOS device aliases even on non-Windows hosts so a repository
/// identifier has one portable storage meaning on every supported platform.
fn is_windows_reserved_source_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _extension)| stem);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(
                |suffix| matches!(suffix.as_bytes(), [digit] if (b'1'..=b'9').contains(digit)),
            )
}

pub(crate) fn verify_source_blob_digest(
    digest: [u8; 32],
    data: &[u8],
    authority: &str,
) -> Result<(), KinDbError> {
    let actual: [u8; 32] = Sha256::digest(data).into();
    if actual != digest {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob digest mismatch for {authority}: requested {}, found {}",
            hex::encode(digest),
            hex::encode(actual)
        )));
    }
    Ok(())
}

pub(crate) fn validate_source_blob_size(byte_len: u64, authority: &str) -> Result<(), KinDbError> {
    if byte_len > MAX_SOURCE_BLOB_BYTES {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob for {authority} is {byte_len} bytes, above the {MAX_SOURCE_BLOB_BYTES}-byte safety limit"
        )));
    }
    Ok(())
}

/// Reject a write request before it reaches a repository lock or the disk.
///
/// One body and a whole batch validate identically, so a batch never accepts
/// bytes a single write would have refused.
fn validate_source_blob_write_request(
    repo_id: &str,
    digest: [u8; 32],
    data: &[u8],
) -> Result<(), KinDbError> {
    validate_source_blob_repo_id(repo_id)?;
    let byte_len = u64::try_from(data.len()).map_err(|_| {
        KinDbError::StorageError(format!(
            "immutable source blob for repo {repo_id} does not fit the size boundary"
        ))
    })?;
    validate_source_blob_size(byte_len, &format!("repo {repo_id}"))?;
    verify_source_blob_digest(digest, data, &format!("repo {repo_id}"))
}

pub(crate) fn validate_source_blob_read_size(
    byte_len: u64,
    max_bytes: u64,
    authority: &str,
) -> Result<(), KinDbError> {
    validate_source_blob_size(byte_len, authority)?;
    if byte_len > max_bytes {
        return Err(KinDbError::SourceBlobReadLimitExceeded {
            actual_bytes: byte_len,
            max_bytes,
        });
    }
    Ok(())
}

#[cfg(unix)]
struct SourceBlobCapability {
    repo_dir: std::fs::File,
    leaf_dir: std::fs::File,
    leaf_path: PathBuf,
}

#[cfg(unix)]
struct OpenedSourceBlob {
    file: std::fs::File,
    data: Vec<u8>,
}

#[cfg(unix)]
fn source_component(name: &str) -> Result<CString, KinDbError> {
    CString::new(name).map_err(|_| {
        KinDbError::StorageError(format!(
            "immutable source blob path component contains NUL: {name:?}"
        ))
    })
}

/// Open one immutable-source directory component, reporting a component that
/// simply is not there as absence rather than as a fault.
///
/// Only `ENOENT` is absence. A symlinked component fails `O_NOFOLLOW` with
/// `ELOOP` and a non-directory fails `O_DIRECTORY` with `ENOTDIR`, so the
/// refusals this walk exists to make are still errors.
#[cfg(unix)]
fn open_optional_source_directory_at(
    parent: &std::fs::File,
    name: &str,
    display_path: &Path,
    create: bool,
    confirm_durability: bool,
) -> Result<Option<std::fs::File>, KinDbError> {
    let component = source_component(name)?;
    if create {
        // SAFETY: both descriptors and the NUL-terminated component are valid
        // for the duration of the call. The component contains no separator.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(KinDbError::StorageError(format!(
                    "failed to create immutable source blob directory {}: {error}",
                    display_path.display()
                )));
            }
        }
    }

    // SAFETY: openat receives a live parent directory handle and a valid
    // component. O_NOFOLLOW rejects a symlink/reparse-like final component;
    // O_DIRECTORY rejects every non-directory object.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(KinDbError::StorageError(format!(
            "refusing symlinked or non-directory immutable source blob ancestor {} (or missing path): {error}",
            display_path.display()
        )));
    }
    // SAFETY: fd was returned uniquely by openat above.
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    if confirm_durability {
        mmap::sync_directory_handle(parent, display_path.parent().unwrap_or(display_path))?;
    }
    Ok(Some(directory))
}

#[cfg(unix)]
fn open_source_directory_at(
    parent: &std::fs::File,
    name: &str,
    display_path: &Path,
    create: bool,
    confirm_durability: bool,
) -> Result<std::fs::File, KinDbError> {
    open_optional_source_directory_at(parent, name, display_path, create, confirm_durability)?
        .ok_or_else(|| {
            KinDbError::StorageError(format!(
                "refusing symlinked or non-directory immutable source blob ancestor {} (or missing path): {}",
                display_path.display(),
                std::io::Error::from(std::io::ErrorKind::NotFound)
            ))
        })
}

#[cfg(unix)]
fn prepare_source_trust_root(
    base_path: &Path,
    confirm_durability: bool,
    confirmed_for_process: &parking_lot::Mutex<bool>,
) -> Result<(), KinDbError> {
    // The storage root is an explicit repository-layout boundary. Source-body
    // IO may create descendants beneath it, but must never recreate the root:
    // exact eject revokes this backend by atomically moving the whole `.kin`
    // namespace while already-open processes may still exist.
    let metadata = std::fs::symlink_metadata(base_path).map_err(|error| {
        KinDbError::StorageError(format!(
            "immutable source blob trust root {} is unavailable; refusing to recreate a detached repository namespace: {error}",
            base_path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root {} is not a real directory",
            base_path.display()
        )));
    }

    // A new process cannot infer that an externally created visible root is
    // durable, so its first source-object acknowledgement conservatively
    // confirms the complete resolved ancestor chain.
    let mut confirmed = confirmed_for_process.lock();
    if confirm_durability && !*confirmed {
        let resolved = std::fs::canonicalize(base_path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to resolve immutable source blob trust root {} for durability confirmation: {error}",
                base_path.display()
            ))
        })?;
        let mut chain = Vec::new();
        let mut cursor = resolved;
        while let Some(parent) = cursor.parent() {
            if parent == cursor {
                break;
            }
            chain.push(cursor.clone());
            cursor = parent.to_path_buf();
        }
        chain.reverse();
        for path in &chain {
            mmap::sync_parent_dir(path)?;
        }
        *confirmed = true;
    }
    Ok(())
}

/// The `source-blobs/sha256/HH` directory component a digest publishes into.
#[cfg(unix)]
fn source_blob_prefix(digest: [u8; 32]) -> String {
    hex::encode(&digest[..1])
}

#[cfg(unix)]
fn open_source_blob_prefix_capability_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    prefix: &str,
    create: bool,
    confirm_durability: bool,
) -> Result<SourceBlobCapability, KinDbError> {
    record_source_blob_capability_walk();
    let repo_dir = mmap::open_directory_handle_at(repository, Path::new("."), repository_display)
        .map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository capability {}: {error}",
            repository_display.display()
        ))
    })?;
    let mut parent = repo_dir.try_clone().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository directory {}: {error}",
            repository_display.display()
        ))
    })?;
    let mut display = repository_display.to_path_buf();
    for component in ["source-blobs", "sha256", prefix] {
        display.push(component);
        parent =
            open_source_directory_at(&parent, component, &display, create, confirm_durability)?;
    }
    Ok(SourceBlobCapability {
        repo_dir,
        leaf_dir: parent,
        leaf_path: display,
    })
}

#[cfg(unix)]
fn open_source_blob_capability_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
    create: bool,
    confirm_durability: bool,
) -> Result<SourceBlobCapability, KinDbError> {
    open_source_blob_prefix_capability_from_repository(
        repository,
        repository_display,
        &source_blob_prefix(digest),
        create,
        confirm_durability,
    )
}

/// Pin the digest-prefix chain for a read, creating nothing.
///
/// A repository that has never stored a body has no `source-blobs/sha256/HH`
/// chain, which is the same answer as a repository that does not hold this
/// body: `None`, with nothing written.
#[cfg(unix)]
fn open_existing_source_blob_capability_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
) -> Result<Option<SourceBlobCapability>, KinDbError> {
    record_source_blob_capability_walk();
    let repo_dir = mmap::open_directory_handle_at(repository, Path::new("."), repository_display)
        .map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository capability {}: {error}",
            repository_display.display()
        ))
    })?;
    let mut parent = repo_dir.try_clone().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository directory {}: {error}",
            repository_display.display()
        ))
    })?;
    let mut display = repository_display.to_path_buf();
    for component in ["source-blobs", "sha256", &source_blob_prefix(digest)] {
        display.push(component);
        let Some(next) =
            open_optional_source_directory_at(&parent, component, &display, false, false)?
        else {
            return Ok(None);
        };
        parent = next;
    }
    Ok(Some(SourceBlobCapability {
        repo_dir,
        leaf_dir: parent,
        leaf_path: display,
    }))
}

#[cfg(unix)]
fn same_directory(left: &std::fs::File, right: &std::fs::File) -> Result<bool, KinDbError> {
    let left = left
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    let right = right
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(unix)]
fn confirm_source_blob_prefix_namespace_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    prefix: &str,
    capability: &SourceBlobCapability,
) -> Result<(), KinDbError> {
    let current = open_source_blob_prefix_capability_from_repository(
        repository,
        repository_display,
        prefix,
        false,
        false,
    )?;
    if !same_directory(&capability.repo_dir, &current.repo_dir)?
        || !same_directory(&capability.leaf_dir, &current.leaf_dir)?
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob repository namespace changed while accessing {}",
            capability.leaf_path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn confirm_source_blob_namespace_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
    capability: &SourceBlobCapability,
) -> Result<(), KinDbError> {
    confirm_source_blob_prefix_namespace_from_repository(
        repository,
        repository_display,
        &source_blob_prefix(digest),
        capability,
    )
}

#[cfg(unix)]
fn open_source_file_at(
    directory: &std::fs::File,
    name: &str,
) -> Result<Option<(std::fs::File, u64)>, KinDbError> {
    let name = source_component(name)?;
    // SAFETY: directory and component are valid. O_NOFOLLOW rejects a final
    // symlink atomically with the open. O_NONBLOCK makes opening a FIFO or
    // device return before the descriptor-backed regular-file check below.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(KinDbError::StorageError(format!(
            "failed to open immutable source blob through pinned directory: {error}"
        )));
    }
    // SAFETY: fd is uniquely owned after successful openat.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    if !metadata.is_file() {
        return Err(KinDbError::StorageError(
            "refusing non-regular immutable source blob".to_string(),
        ));
    }
    let byte_len = metadata.len();
    validate_source_blob_size(byte_len, "pinned local source object")?;
    Ok(Some((file, byte_len)))
}

#[cfg(unix)]
fn read_source_file_at(
    directory: &std::fs::File,
    name: &str,
    max_bytes: u64,
) -> Result<Option<OpenedSourceBlob>, KinDbError> {
    let Some((mut file, byte_len)) = open_source_file_at(directory, name)? else {
        return Ok(None);
    };
    // Reject objects larger than the caller's budget before allocating their
    // bytes. The backend safety limit was already enforced at open time; this
    // is the caller's stricter, possibly per-request, boundary.
    validate_source_blob_read_size(byte_len, max_bytes, "pinned local source object")?;
    run_source_file_after_metadata_hook();

    let capacity = usize::try_from(byte_len).map_err(|_| {
        KinDbError::StorageError(format!(
            "pinned local source object length {byte_len} does not fit in memory"
        ))
    })?;
    let mut data = Vec::new();
    data.try_reserve_exact(capacity).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to reserve {byte_len} bytes for pinned local source object: {error}"
        ))
    })?;
    data.resize(capacity, 0);
    file.read_exact(&mut data).map_err(|error| {
        KinDbError::StorageError(format!(
            "pinned local source object changed length while reading {byte_len} bytes: {error}"
        ))
    })?;

    // Probe growth with one fixed byte instead of `take(MAX + 1).read_to_end`:
    // `read_to_end` may geometrically allocate beyond its logical bound before
    // it notices EOF. Reinspect the same pinned descriptor as well, so truncate
    // and regrow races cannot hide behind a zero-byte probe.
    let mut trailing = [0u8; 1];
    let trailing_len = file
        .read(&mut trailing)
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    let final_len = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?
        .len();
    if trailing_len != 0 || final_len != byte_len {
        return Err(KinDbError::StorageError(format!(
            "pinned local source object changed length while reading: expected {byte_len} bytes, found at least {final_len}; the {MAX_SOURCE_BLOB_BYTES}-byte allocation safety limit remains enforced"
        )));
    }
    Ok(Some(OpenedSourceBlob { file, data }))
}

#[cfg(unix)]
/// Stage, fsync, and no-clobber link one body into its pinned digest
/// directory.
///
/// `confirm_directory` decides whether the directory entry is made durable
/// before this call returns. A batch clears it and issues one directory
/// barrier per touched directory at its flush instead. The body's own barrier
/// always happens before the `linkat` that names it, in both modes, so a
/// deferred barrier can only lose the name.
///
/// `barrier` decides how strong that body barrier is. A batch orders rather
/// than flushes, and flushes the device once for the whole session before it
/// makes any name durable, so the body still reaches the device before the
/// name that points at it.
fn publish_source_file_at(
    directory: &std::fs::File,
    digest_hex: &str,
    data: &[u8],
    confirm_directory: bool,
    barrier: SourceBodyBarrier,
) -> Result<bool, KinDbError> {
    let staging = format!(".{digest_hex}.no-clobber-{}", uuid::Uuid::new_v4());
    let staging_name = source_component(&staging)?;
    let target_name = source_component(digest_hex)?;
    // SAFETY: pinned directory and validated single-component name.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            staging_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(KinDbError::StorageError(format!(
            "failed to create pinned immutable source staging file: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is uniquely owned after successful openat.
    let mut staged = unsafe { std::fs::File::from_raw_fd(fd) };
    let write_result = staged
        .write_all(data)
        .and_then(|()| issue_source_body_barrier(&staged, barrier))
        .map_err(|error| KinDbError::StorageError(error.to_string()));
    drop(staged);
    if let Err(error) = write_result {
        // SAFETY: names and directory descriptor remain valid.
        unsafe { libc::unlinkat(directory.as_raw_fd(), staging_name.as_ptr(), 0) };
        return Err(error);
    }

    // SAFETY: both names are relative to the same pinned directory. linkat is
    // the no-clobber publication point.
    let linked = unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            staging_name.as_ptr(),
            directory.as_raw_fd(),
            target_name.as_ptr(),
            0,
        )
    };
    let published = if linked == 0 {
        true
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            false
        } else {
            unsafe { libc::unlinkat(directory.as_raw_fd(), staging_name.as_ptr(), 0) };
            return Err(KinDbError::StorageError(format!(
                "failed to publish immutable source blob without clobbering: {error}"
            )));
        }
    };
    if confirm_directory {
        mmap::sync_directory_handle(directory, Path::new("pinned immutable source directory"))?;
    }
    // SAFETY: cleanup is relative to the same pinned directory and never
    // follows an ancestor path.
    unsafe { libc::unlinkat(directory.as_raw_fd(), staging_name.as_ptr(), 0) };
    Ok(published)
}

#[cfg(windows)]
struct WindowsSourceBlobCapability {
    /// Every directory from the filesystem root through the digest prefix.
    /// The handles intentionally omit `FILE_SHARE_DELETE`, pinning the whole
    /// namespace chain against rename or replacement for the operation.
    directories: Vec<cap_std::fs::Dir>,
    display_paths: Vec<PathBuf>,
    leaf_path: PathBuf,
}

#[cfg(windows)]
impl WindowsSourceBlobCapability {
    fn leaf_dir(&self) -> &cap_std::fs::Dir {
        self.directories
            .last()
            .expect("source capability always contains its digest-prefix directory")
    }

    fn sync_directory(&self, index: usize) -> Result<(), KinDbError> {
        let directory = self.directories[index].open_dir(".").map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to clone retained Windows source directory {} for durability confirmation: {error}",
                self.display_paths[index].display()
            ))
        })?;
        mmap::sync_directory_handle(
            &directory.into_std_file(),
            self.display_paths[index].as_path(),
        )
    }

    /// Confirm every newly created ancestor entry child-before-parent. The
    /// digest-prefix directory itself is flushed after the digest file is
    /// installed.
    fn sync_ancestor_publication(&self) -> Result<(), KinDbError> {
        for index in (0..self.directories.len().saturating_sub(1)).rev() {
            self.sync_directory(index)?;
        }
        Ok(())
    }

    fn sync_leaf_publication(&self) -> Result<(), KinDbError> {
        self.sync_directory(
            self.directories
                .len()
                .checked_sub(1)
                .expect("source capability always retains a leaf directory"),
        )
    }
}

#[cfg(windows)]
struct WindowsOpenedSourceBlob {
    file: std::fs::File,
    data: Vec<u8>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WindowsSourceIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
fn validate_windows_source_component(component: &std::ffi::OsStr) -> Result<(), KinDbError> {
    use std::os::windows::ffi::OsStrExt;

    let mut components = Path::new(component).components();
    if !matches!(
        components.next(),
        Some(std::path::Component::Normal(name)) if name == component
    ) || components.next().is_some()
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source path component is not one normal name: {component:?}"
        )));
    }

    let wide = component.encode_wide().collect::<Vec<_>>();
    let invalid_character = wide.iter().any(|character| {
        *character == 0
            || *character < 32
            || matches!(
                *character,
                value if value == u16::from(b'<')
                    || value == u16::from(b'>')
                    || value == u16::from(b':')
                    || value == u16::from(b'"')
                    || value == u16::from(b'/')
                    || value == u16::from(b'\\')
                    || value == u16::from(b'|')
                    || value == u16::from(b'?')
                    || value == u16::from(b'*')
            )
    });
    if wide.is_empty()
        || invalid_character
        || matches!(wide.last(), Some(last) if *last == u16::from(b'.') || *last == u16::from(b' '))
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source path component is not a portable Windows name: {component:?}"
        )));
    }

    let stem_end = wide
        .iter()
        .position(|character| *character == u16::from(b'.'))
        .unwrap_or(wide.len());
    let ascii_stem = wide[..stem_end]
        .iter()
        .copied()
        .map(u8::try_from)
        .collect::<Result<Vec<_>, _>>();
    if ascii_stem
        .ok()
        .and_then(|stem| String::from_utf8(stem).ok())
        .is_some_and(|stem| is_windows_reserved_source_component(&stem))
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source path component is a reserved Windows device name: {component:?}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_source_metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    cap_fs_ext::OsMetadataExt::file_attributes(metadata) & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Open one immutable-source directory component, reporting a component that
/// simply is not there as absence rather than as a fault.
///
/// Only a not-found open is absence. A reparse point or a non-directory still
/// fails, so the refusals this walk exists to make are unchanged.
#[cfg(windows)]
fn open_optional_windows_source_directory_at(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
    display_path: &Path,
    create: bool,
) -> Result<Option<cap_std::fs::Dir>, KinDbError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    validate_windows_source_component(component)?;
    if create {
        match parent.create_dir(component) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to create immutable source blob directory {}: {error}",
                    display_path.display()
                )));
            }
        }
    }

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        // Deliberately do not share DELETE. Keeping every ancestor handle in
        // the capability prevents path displacement for the operation.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = match parent.open_with(component, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "refusing reparse-point or non-directory immutable source blob ancestor {} (or missing path): {error}",
                display_path.display()
            )));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    if windows_source_metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(KinDbError::StorageError(format!(
            "refusing reparse-point or non-directory immutable source blob ancestor {}",
            display_path.display()
        )));
    }
    Ok(Some(cap_std::fs::Dir::from_std_file(file.into_std())))
}

#[cfg(windows)]
fn open_windows_source_directory_at(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
    display_path: &Path,
    create: bool,
) -> Result<cap_std::fs::Dir, KinDbError> {
    open_optional_windows_source_directory_at(parent, component, display_path, create)?.ok_or_else(
        || {
            KinDbError::StorageError(format!(
                "refusing reparse-point or non-directory immutable source blob ancestor {} (or missing path): {}",
                display_path.display(),
                std::io::Error::from(std::io::ErrorKind::NotFound)
            ))
        },
    )
}

#[cfg(windows)]
fn open_windows_source_blob_capability_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
    create: bool,
) -> Result<WindowsSourceBlobCapability, KinDbError> {
    record_source_blob_capability_walk();
    let mut directories = vec![repository.open_dir(".").map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained Windows repository capability {}: {error}",
            repository_display.display()
        ))
    })?];
    let mut display_paths = vec![repository_display.to_path_buf()];
    let mut display = repository_display.to_path_buf();
    let digest_hex = hex::encode(digest);
    for component in [
        std::ffi::OsStr::new("source-blobs"),
        std::ffi::OsStr::new("sha256"),
        std::ffi::OsStr::new(&digest_hex[..2]),
    ] {
        display.push(component);
        let next = open_windows_source_directory_at(
            directories
                .last()
                .expect("repository capability was inserted"),
            component,
            &display,
            create,
        )?;
        directories.push(next);
        display_paths.push(display.clone());
    }
    let capability = WindowsSourceBlobCapability {
        directories,
        display_paths,
        leaf_path: display,
    };
    if create {
        capability.sync_ancestor_publication()?;
    }
    Ok(capability)
}

/// Pin the digest-prefix chain for a read, creating nothing.
///
/// A repository that has never stored a body has no `source-blobs/sha256/HH`
/// chain, which is the same answer as a repository that does not hold this
/// body: `None`, with nothing written.
#[cfg(windows)]
fn open_existing_windows_source_blob_capability_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
) -> Result<Option<WindowsSourceBlobCapability>, KinDbError> {
    record_source_blob_capability_walk();
    let mut directories = vec![repository.open_dir(".").map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained Windows repository capability {}: {error}",
            repository_display.display()
        ))
    })?];
    let mut display_paths = vec![repository_display.to_path_buf()];
    let mut display = repository_display.to_path_buf();
    let digest_hex = hex::encode(digest);
    for component in [
        std::ffi::OsStr::new("source-blobs"),
        std::ffi::OsStr::new("sha256"),
        std::ffi::OsStr::new(&digest_hex[..2]),
    ] {
        display.push(component);
        let Some(next) = open_optional_windows_source_directory_at(
            directories
                .last()
                .expect("repository capability was inserted"),
            component,
            &display,
            false,
        )?
        else {
            return Ok(None);
        };
        directories.push(next);
        display_paths.push(display.clone());
    }
    Ok(Some(WindowsSourceBlobCapability {
        directories,
        display_paths,
        leaf_path: display,
    }))
}

#[cfg(windows)]
fn windows_source_handle_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<WindowsSourceIdentity, KinDbError> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `handle` remains live and `info` is correctly sized for
    // `FileIdInfo`.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(KinDbError::StorageError(format!(
            "failed to inspect Windows filesystem object identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    let identity = WindowsSourceIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    };
    if identity.volume_serial == 0 || identity.file_id.iter().all(|byte| *byte == 0) {
        return Err(KinDbError::StorageError(
            "Windows filesystem object returned a zero FILE_ID_128 identity".to_string(),
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
fn windows_source_directory_identity(
    directory: &cap_std::fs::Dir,
) -> Result<WindowsSourceIdentity, KinDbError> {
    use std::os::windows::io::AsRawHandle;

    windows_source_handle_identity(directory.as_raw_handle().cast())
}

#[cfg(windows)]
fn windows_source_file_identity(file: &std::fs::File) -> Result<WindowsSourceIdentity, KinDbError> {
    use std::os::windows::io::AsRawHandle;

    windows_source_handle_identity(file.as_raw_handle().cast())
}

#[cfg(windows)]
fn confirm_windows_source_blob_namespace_from_repository(
    repository: &cap_std::fs::Dir,
    repository_display: &Path,
    digest: [u8; 32],
    capability: &WindowsSourceBlobCapability,
) -> Result<(), KinDbError> {
    let current = open_windows_source_blob_capability_from_repository(
        repository,
        repository_display,
        digest,
        false,
    )?;
    if current.directories.len() != capability.directories.len() {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob repository namespace changed while accessing {}",
            capability.leaf_path.display()
        )));
    }
    for (pinned, reopened) in capability
        .directories
        .iter()
        .zip(current.directories.iter())
    {
        if windows_source_directory_identity(pinned)?
            != windows_source_directory_identity(reopened)?
        {
            return Err(KinDbError::StorageError(format!(
                "immutable source blob repository namespace changed while accessing {}",
                capability.leaf_path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_source_file_at(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    writable: bool,
) -> Result<Option<(std::fs::File, u64)>, KinDbError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    validate_windows_source_component(name)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .access_mode(if writable {
            GENERIC_READ | GENERIC_WRITE
        } else {
            GENERIC_READ
        })
        // Immutable bytes are read through an exclusive namespace/content
        // handle. A pre-existing incompatible writer makes the read fail
        // closed instead of permitting a torn body.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .follow(FollowSymlinks::No)
        .maybe_dir(false);
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to open immutable source blob through pinned Windows directory: {error}"
            )));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    if windows_source_metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(KinDbError::StorageError(
            "refusing reparse-point or non-regular immutable source blob".to_string(),
        ));
    }
    let byte_len = metadata.len();
    validate_source_blob_size(byte_len, "pinned local Windows source object")?;
    Ok(Some((file.into_std(), byte_len)))
}

#[cfg(windows)]
fn read_windows_source_file_at(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    max_bytes: u64,
    writable: bool,
) -> Result<Option<WindowsOpenedSourceBlob>, KinDbError> {
    let Some((mut file, byte_len)) = open_windows_source_file_at(directory, name, writable)? else {
        return Ok(None);
    };
    validate_source_blob_read_size(byte_len, max_bytes, "pinned local Windows source object")?;
    let capacity = usize::try_from(byte_len).map_err(|_| {
        KinDbError::StorageError(format!(
            "pinned local Windows source object length {byte_len} does not fit in memory"
        ))
    })?;
    let mut data = Vec::new();
    data.try_reserve_exact(capacity).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to reserve {byte_len} bytes for pinned local Windows source object: {error}"
        ))
    })?;
    data.resize(capacity, 0);
    file.read_exact(&mut data).map_err(|error| {
        KinDbError::StorageError(format!(
            "pinned local Windows source object changed length while reading {byte_len} bytes: {error}"
        ))
    })?;
    let mut trailing = [0_u8; 1];
    let trailing_len = file
        .read(&mut trailing)
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    let final_len = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?
        .len();
    if trailing_len != 0 || final_len != byte_len {
        return Err(KinDbError::StorageError(format!(
            "pinned local Windows source object changed length while reading: expected {byte_len} bytes, found at least {final_len}; the {MAX_SOURCE_BLOB_BYTES}-byte allocation safety limit remains enforced"
        )));
    }
    Ok(Some(WindowsOpenedSourceBlob { file, data }))
}

#[cfg(windows)]
fn mark_windows_source_file_for_deletion(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the exact staged handle is live and was opened with DELETE
    // access; the disposition buffer has the required layout and size.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsStagedSourceFile {
    file: Option<std::fs::File>,
    published: bool,
}

#[cfg(windows)]
impl WindowsStagedSourceFile {
    fn file(&self) -> &std::fs::File {
        self.file
            .as_ref()
            .expect("staged source handle remains live until drop")
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file
            .as_mut()
            .expect("staged source handle remains live until drop")
    }
}

#[cfg(windows)]
impl Drop for WindowsStagedSourceFile {
    fn drop(&mut self) {
        if !self.published {
            if let Some(file) = self.file.as_ref() {
                // Best-effort exact-handle cleanup. A crash or cleanup failure
                // can leave only a UUID-named, unreachable staging orphan; it
                // can never become digest authority.
                let _ = mark_windows_source_file_for_deletion(file);
            }
        }
        drop(self.file.take());
    }
}

#[cfg(windows)]
fn create_windows_staged_source_file(
    directory: &cap_std::fs::Dir,
    digest_hex: &str,
) -> Result<WindowsStagedSourceFile, KinDbError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
    };

    let staging = format!(".{digest_hex}.no-clobber-{}", uuid::Uuid::new_v4());
    let name = std::ffi::OsStr::new(&staging);
    validate_windows_source_component(name)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
        .follow(FollowSymlinks::No)
        .maybe_dir(false);
    let file = directory.open_with(name, &options).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to create pinned immutable source staging file on Windows: {error}"
        ))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    if windows_source_metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(KinDbError::StorageError(
            "new immutable source staging object is a reparse point or non-regular file"
                .to_string(),
        ));
    }
    Ok(WindowsStagedSourceFile {
        file: Some(file.into_std()),
        published: false,
    })
}

#[cfg(windows)]
fn rename_windows_source_file_noreplace(
    source: &std::fs::File,
    destination_parent: &cap_std::fs::Dir,
    destination_name: &std::ffi::OsStr,
) -> Result<bool, KinDbError> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_EXISTS,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    validate_windows_source_component(destination_name)?;
    let name_wide = destination_name.encode_wide().collect::<Vec<_>>();
    let name_bytes = name_wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| {
            KinDbError::StorageError(
                "immutable source destination length overflow on Windows".to_string(),
            )
        })?;
    let buffer_bytes = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(name_bytes)
        .ok_or_else(|| {
            KinDbError::StorageError(
                "immutable source rename buffer length overflow on Windows".to_string(),
            )
        })?;
    let file_name_length = u32::try_from(name_bytes).map_err(|_| {
        KinDbError::StorageError(
            "immutable source destination exceeds the Windows length limit".to_string(),
        )
    })?;
    let buffer_length = u32::try_from(buffer_bytes).map_err(|_| {
        KinDbError::StorageError(
            "immutable source rename buffer exceeds the Windows length limit".to_string(),
        )
    })?;
    let mut storage = vec![0_usize; buffer_bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        // `NtSetInformationFile` (unlike Win32
        // `SetFileInformationByHandle`) honors a relative FileName against
        // RootDirectory. Flags=0 is the atomic no-replace publication point.
        (*info).Anonymous.Flags = 0;
        (*info).RootDirectory = destination_parent.as_raw_handle().cast();
        (*info).FileNameLength = file_name_length;
        std::ptr::copy_nonoverlapping(
            name_wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name_wide.len(),
        );
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: source and destination directory handles remain live, and the
    // aligned variable-sized rename buffer matches `FILE_RENAME_INFORMATION`.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle().cast(),
            &raw mut io_status,
            info.cast(),
            buffer_length,
            FileRenameInformation,
        )
    };
    if status == 0 {
        return Ok(true);
    }
    if matches!(
        status,
        STATUS_OBJECT_NAME_COLLISION | STATUS_OBJECT_NAME_EXISTS
    ) {
        return Ok(false);
    }
    // SAFETY: converting an NTSTATUS to a Win32 error code has no pointer
    // preconditions.
    let windows_error = unsafe { RtlNtStatusToDosError(status) };
    Err(KinDbError::StorageError(format!(
        "failed to publish immutable source blob without replacing Windows authority: {}",
        std::io::Error::from_raw_os_error(windows_error as i32)
    )))
}

#[cfg(windows)]
fn publish_windows_source_file_at(
    directory: &cap_std::fs::Dir,
    directory_display: &Path,
    digest_hex: &str,
    data: &[u8],
) -> Result<Option<WindowsSourceIdentity>, KinDbError> {
    let mut staged = create_windows_staged_source_file(directory, digest_hex)?;
    staged
        .file_mut()
        .write_all(data)
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    sync_source_file_for_ack(
        staged.file(),
        Path::new("pinned immutable Windows source staging file"),
    )?;
    if !rename_windows_source_file_noreplace(
        staged.file(),
        directory,
        std::ffi::OsStr::new(digest_hex),
    )? {
        return Ok(None);
    }
    // The handle now names the digest object. Any later durability or identity
    // failure must leave that no-clobber publication in place for an exact
    // retry; cleanup is only valid while the handle still names staging.
    staged.published = true;

    // Flush the exact renamed file and containing retained directory after the
    // namespace transition. A failure keeps the no-clobber digest entry in
    // place so an exact retry can re-confirm both boundaries.
    sync_source_file_for_ack(
        staged.file(),
        Path::new("pinned immutable Windows source object"),
    )?;
    let retained_directory = directory.open_dir(".").map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained immutable source directory {} after Windows publication: {error}",
            directory_display.display()
        ))
    })?;
    mmap::sync_directory_handle(&retained_directory.into_std_file(), directory_display)?;
    let identity = windows_source_file_identity(staged.file())?;
    Ok(Some(identity))
}

pub(crate) fn checked_next_generation(
    generation: Generation,
    authority: &str,
) -> Result<Generation, KinDbError> {
    generation.checked_add(1).ok_or_else(|| {
        KinDbError::StorageError(format!(
            "generation exhausted at {generation} while allocating {authority}"
        ))
    })
}

/// Atomic persistence authority for a snapshot plus its acknowledged journal.
#[derive(Debug)]
pub struct SnapshotAuthority {
    pub snapshot_bytes: Vec<u8>,
    /// Generation represented by `snapshot_bytes` before journal replay.
    pub snapshot_generation: Generation,
    /// Last acknowledged generation. Every generation in
    /// `(snapshot_generation, head_generation]` must have one exact delta.
    pub head_generation: Generation,
    /// Durable claim that `snapshot_bytes` already passed complete open-time
    /// validation. Backends with no durable place to bind such a claim leave
    /// this `None`, and their repositories revalidate in full on every open.
    pub history_validation: Option<HistoryValidationProof>,
}

impl SnapshotAuthority {
    /// Backend CAS cursor represented by this coherent authority view.
    pub const fn cursor(&self) -> SnapshotCursor {
        SnapshotCursor::from_backend_generation(self.head_generation)
    }
}

pub type PersistedDelta = (Vec<u8>, Generation);
pub type SnapshotRecoveryState = (Option<SnapshotAuthority>, Vec<PersistedDelta>);

/// Immutable receipt for the serialized graph payload selected by one
/// coherent authority open.
///
/// The receipt counts the exact snapshot bytes admitted by recovery plus only
/// the acknowledged delta bytes successfully replayed on top of that
/// snapshot. It deliberately excludes backend metadata, retired or staged
/// journal entries, source bodies, indexes, overlays, and filesystem
/// allocation overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityPayloadStats {
    snapshot_generation: Generation,
    head_generation: Generation,
    snapshot_bytes: u64,
    acknowledged_delta_count: u64,
    acknowledged_delta_bytes: u64,
    total_payload_bytes: u64,
}

impl AuthorityPayloadStats {
    fn from_recovery(
        snapshot_generation: Generation,
        head_generation: Generation,
        snapshot_bytes: usize,
        acknowledged_delta_count: usize,
        acknowledged_delta_bytes: u64,
    ) -> Result<Self, KinDbError> {
        let snapshot_bytes = u64::try_from(snapshot_bytes).map_err(|_| {
            KinDbError::StorageError("authority snapshot byte length does not fit u64".to_string())
        })?;
        let acknowledged_delta_count = u64::try_from(acknowledged_delta_count).map_err(|_| {
            KinDbError::StorageError(
                "authority acknowledged delta count does not fit u64".to_string(),
            )
        })?;
        Self::from_components(
            snapshot_generation,
            head_generation,
            snapshot_bytes,
            acknowledged_delta_count,
            acknowledged_delta_bytes,
        )
    }

    fn from_components(
        snapshot_generation: Generation,
        head_generation: Generation,
        snapshot_bytes: u64,
        acknowledged_delta_count: u64,
        acknowledged_delta_bytes: u64,
    ) -> Result<Self, KinDbError> {
        let expected_delta_count =
            head_generation
                .checked_sub(snapshot_generation)
                .ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "authority snapshot generation {snapshot_generation} exceeds head generation {head_generation}"
                    ))
                })?;
        if acknowledged_delta_count != expected_delta_count {
            return Err(KinDbError::StorageError(format!(
                "authority payload receipt counted {acknowledged_delta_count} acknowledged deltas, expected {expected_delta_count} between generations {snapshot_generation} and {head_generation}"
            )));
        }
        let total_payload_bytes = snapshot_bytes
            .checked_add(acknowledged_delta_bytes)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "authority payload byte count overflows u64: snapshot {snapshot_bytes} plus acknowledged deltas {acknowledged_delta_bytes}"
                ))
            })?;
        Ok(Self {
            snapshot_generation,
            head_generation,
            snapshot_bytes,
            acknowledged_delta_count,
            acknowledged_delta_bytes,
            total_payload_bytes,
        })
    }

    /// Generation represented by the selected immutable snapshot bytes.
    pub const fn snapshot_generation(self) -> Generation {
        self.snapshot_generation
    }

    /// Last generation acknowledged by the coherent authority view.
    pub const fn head_generation(self) -> Generation {
        self.head_generation
    }

    /// Exact serialized length of the selected snapshot bytes.
    pub const fn snapshot_bytes(self) -> u64 {
        self.snapshot_bytes
    }

    /// Number of acknowledged deltas successfully replayed during recovery.
    pub const fn acknowledged_delta_count(self) -> u64 {
        self.acknowledged_delta_count
    }

    /// Exact serialized length of acknowledged deltas successfully replayed.
    pub const fn acknowledged_delta_bytes(self) -> u64 {
        self.acknowledged_delta_bytes
    }

    /// Checked sum of selected snapshot and acknowledged delta bytes.
    pub const fn total_payload_bytes(self) -> u64 {
        self.total_payload_bytes
    }
}

/// A snapshot reconstructed from durable base bytes plus its acknowledged
/// incremental-delta chain.
#[derive(Debug)]
pub struct RecoveredSnapshot {
    pub snapshot: GraphSnapshot,
    pub generation: Generation,
    pub deltas_applied: usize,
    pub deltas_seen: usize,
    /// SHA-256 recomputed here over the exact base snapshot bytes that were
    /// deserialized, never copied from a backend's own claim about them.
    pub snapshot_sha256: String,
    /// Backend claim that the base snapshot already passed complete open-time
    /// validation. Cleared once any delta is applied, because the recovered
    /// state is then no longer the bytes the claim names.
    pub history_validation: Option<HistoryValidationProof>,
}

pub(crate) struct RecoveredRepositoryAuthority {
    pub recovered: RecoveredSnapshot,
    pub reused_complete_validation: bool,
    pub payload_stats: AuthorityPayloadStats,
}

/// Load a backend snapshot and replay its complete authoritative delta chain.
///
/// Entries outside the authority's exact `(snapshot_generation,
/// head_generation]` range are unacknowledged or stale and are ignored. Every
/// generation inside that range is mandatory, ordered, and must declare the
/// immediately preceding generation as its base. Missing prefixes, missing
/// heads, duplicates, corrupt bytes, and gaps fail closed.
pub fn load_recovered_snapshot<B: StorageBackend + ?Sized>(
    backend: &B,
    repo_id: &str,
) -> Result<Option<RecoveredSnapshot>, KinDbError> {
    load_recovered_snapshot_inner(backend, repo_id, None)
        .map(|recovered| recovered.map(|recovered| recovered.recovered))
}

/// Load repository authority while permitting an exact, durable
/// complete-validation proof to skip deterministic semantic revalidation.
///
/// General snapshot consumers continue to use [`load_recovered_snapshot`] and
/// always perform full storage admission. This narrower entrypoint is reserved
/// for [`RepositoryAuthorityManager`](crate::storage::RepositoryAuthorityManager),
/// which still revalidates every referenced immutable body after recovery.
pub(crate) fn load_recovered_repository_authority<B: StorageBackend + ?Sized>(
    backend: &B,
    repo_id: &str,
    expected_validator_version: u32,
) -> Result<Option<RecoveredRepositoryAuthority>, KinDbError> {
    load_recovered_snapshot_inner(backend, repo_id, Some(expected_validator_version))
}

fn load_recovered_snapshot_inner<B: StorageBackend + ?Sized>(
    backend: &B,
    repo_id: &str,
    expected_validator_version: Option<u32>,
) -> Result<Option<RecoveredRepositoryAuthority>, KinDbError> {
    let (loaded, raw_deltas) = backend.load_recovery_state(repo_id)?;

    let Some(authority) = loaded else {
        if raw_deltas.is_empty() {
            return Ok(None);
        }
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} has {} persisted deltas but no current snapshot authority",
            raw_deltas.len()
        )));
    };

    if authority.snapshot_generation > authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} snapshot base generation {} exceeds acknowledged head {}",
            authority.snapshot_generation, authority.head_generation
        )));
    }

    let snapshot_payload_bytes = authority.snapshot_bytes.len();
    let snapshot_sha256 = hex::encode(Sha256::digest(&authority.snapshot_bytes));
    let deltas_seen = raw_deltas.len();
    let reused_complete_validation = expected_validator_version.is_some_and(|expected| {
        authority.snapshot_generation == authority.head_generation
            && raw_deltas.is_empty()
            && authority.history_validation.as_ref().is_some_and(|proof| {
                proof.validator_version == expected
                    && proof.repository_id == repo_id
                    && proof.generation == authority.head_generation
                    && proof.snapshot_sha256 == snapshot_sha256
            })
    });
    let mut snapshot = if reused_complete_validation {
        let _span = tracing::info_span!("kindb.snapshot.reuse_exact_complete_validation").entered();
        GraphSnapshot::from_bytes_reusing_exact_validation(&authority.snapshot_bytes)?
    } else {
        GraphSnapshot::from_bytes(&authority.snapshot_bytes)?
    };
    if authority.snapshot_generation == authority.head_generation {
        let payload_stats = AuthorityPayloadStats::from_recovery(
            authority.snapshot_generation,
            authority.head_generation,
            snapshot_payload_bytes,
            0,
            0,
        )?;
        return Ok(Some(RecoveredRepositoryAuthority {
            recovered: RecoveredSnapshot {
                snapshot,
                generation: authority.head_generation,
                deltas_applied: 0,
                deltas_seen,
                snapshot_sha256,
                history_validation: authority.history_validation,
            },
            reused_complete_validation,
            payload_stats,
        }));
    }
    let mut expected_generation = checked_next_generation(
        authority.snapshot_generation,
        &format!("repo {repo_id} recovery"),
    )?;
    let mut recovered_generation = authority.snapshot_generation;
    let mut applied = 0usize;
    let mut acknowledged_delta_bytes = 0u64;
    let mut previous_generation = None;
    for (bytes, generation) in raw_deltas {
        if generation == GENERATION_INIT {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta journal contains reserved generation 0"
            )));
        }
        if previous_generation.is_some_and(|previous| generation <= previous) {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta journal is not strictly ordered: generation {generation} follows {}",
                previous_generation.expect("checked above")
            )));
        }
        previous_generation = Some(generation);

        if generation > authority.head_generation {
            // A delta staged before an authority-commit crash is not durable
            // authority. It may be overwritten by a retry at the same
            // generation and must never be attached speculatively.
            continue;
        }
        if generation != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta chain is incomplete: expected generation {expected_generation}, found {generation}"
            )));
        }
        let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(&bytes)?;
        let expected_base = generation - 1;
        if delta.base_generation != expected_base {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta generation {generation} declares base {}, expected {expected_base}",
                delta.base_generation
            )));
        }
        crate::storage::delta::apply_graph_delta(&mut snapshot, &delta)?;
        let delta_bytes = u64::try_from(bytes.len()).map_err(|_| {
            KinDbError::StorageError(format!(
                "repo {repo_id} acknowledged delta generation {generation} byte length does not fit u64"
            ))
        })?;
        acknowledged_delta_bytes = acknowledged_delta_bytes
            .checked_add(delta_bytes)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "repo {repo_id} acknowledged delta payload byte count overflows u64"
                ))
            })?;
        applied = applied.checked_add(1).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "repo {repo_id} acknowledged delta count overflows usize"
            ))
        })?;
        recovered_generation = generation;
        if generation < authority.head_generation {
            expected_generation =
                checked_next_generation(generation, &format!("repo {repo_id} recovery"))?;
        }
    }

    if recovered_generation != authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} delta chain ended at generation {recovered_generation}, acknowledged head is {}",
            authority.head_generation
        )));
    }

    let payload_stats = AuthorityPayloadStats::from_recovery(
        authority.snapshot_generation,
        authority.head_generation,
        snapshot_payload_bytes,
        applied,
        acknowledged_delta_bytes,
    )?;
    Ok(Some(RecoveredRepositoryAuthority {
        recovered: RecoveredSnapshot {
            snapshot,
            generation: authority.head_generation,
            deltas_applied: applied,
            deltas_seen,
            snapshot_sha256,
            // The recovered state is the base snapshot plus a delta chain, so no
            // claim about the base bytes describes it any more.
            history_validation: None,
        },
        reused_complete_validation: false,
        payload_stats,
    }))
}

/// Pluggable storage backend for graph snapshots and overlay state.
///
/// All methods are synchronous — the caller (daemon) can wrap in
/// `spawn_blocking` if needed. Implementations must be `Send + Sync`
/// so they can be shared across threads behind an `Arc`.
pub trait StorageBackend: Send + Sync {
    /// Whether this backend has a durable, CAS-safe incremental-delta write
    /// path. Backends must opt in; callers otherwise persist full snapshots.
    fn supports_incremental_deltas(&self) -> bool {
        false
    }

    /// Load snapshot bytes together with the persisted base and acknowledged
    /// journal-head generations. Backends with no incremental authority can
    /// use the default base=head representation.
    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        Ok(self
            .load_snapshot(repo_id)?
            .map(|(snapshot_bytes, generation)| SnapshotAuthority {
                snapshot_bytes,
                snapshot_generation: generation,
                head_generation: generation,
                history_validation: None,
            }))
    }

    /// Persist a full snapshot, optionally binding a durable record that these
    /// exact bytes already passed complete open-time validation.
    ///
    /// `history_validator_version` is `Some` only when the caller has just
    /// validated the very bytes it is handing over. Backends with nowhere to
    /// bind that record ignore it, which costs correctness nothing: their
    /// repositories simply revalidate in full on every open.
    fn save_snapshot_validated(
        &self,
        repo_id: &str,
        data: &[u8],
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        let _ = history_validator_version;
        self.save_snapshot_classified(repo_id, data, expected)
    }

    /// Bind a validation record to the snapshot a repository already holds,
    /// without rewriting it.
    ///
    /// This is how the first full validation after an upgrade, an import, or a
    /// store written by an older build pays for itself. The backend must
    /// verify that the durable snapshot still is exactly `snapshot_sha256` at
    /// exactly `generation` before binding anything, and refuse otherwise.
    ///
    /// `Ok(false)` means the backend has no durable place for the record.
    fn record_history_validation(
        &self,
        repo_id: &str,
        generation: Generation,
        snapshot_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError> {
        let _ = (repo_id, generation, snapshot_sha256, validator_version);
        Ok(false)
    }

    /// Read snapshot authority and its journal from one coherent backend view.
    /// Transactional/lock-backed implementations override this so authority
    /// cannot move between the snapshot and journal reads.
    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        let authority = self.load_snapshot_authority(repo_id)?;
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = self.load_deltas_since(repo_id, since)?;
        Ok((authority, deltas))
    }

    /// Load a repo's graph snapshot.
    ///
    /// Returns `Ok(None)` if no snapshot exists yet (new repo).
    /// Returns `Ok(Some((bytes, generation)))` on success. `generation` is
    /// always the generation represented by those exact bytes. Backends with
    /// an acknowledged delta journal must return the base generation here,
    /// not the journal head. Callers that need the acknowledged head must use
    /// [`load_snapshot_authority`](Self::load_snapshot_authority) or
    /// [`load_recovered_snapshot`].
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError>;

    /// Store immutable source bytes under their SHA-256 content identity.
    ///
    /// Implementations must validate that `data` hashes to `digest`, must
    /// never replace different bytes already stored under the same identity,
    /// and must treat an exact retry as success. Source blobs are deliberately
    /// separate from graph snapshots: snapshots retain the semantic history
    /// and its content hashes while this object namespace retains the exact
    /// bytes those hashes name.
    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        let _ = (repo_id, digest, data);
        Err(KinDbError::StorageError(
            "immutable source blob storage is not supported by this backend".to_string(),
        ))
    }

    /// Load immutable source bytes by SHA-256 content identity.
    ///
    /// Implementations must verify the returned bytes against `digest` and
    /// fail closed on corruption. `Ok(None)` means the exact bytes were never
    /// persisted; callers must not repair that gap from a filesystem or Git
    /// fallback on an authority path.
    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        let _ = (repo_id, digest);
        Err(KinDbError::StorageError(
            "immutable source blob storage is not supported by this backend".to_string(),
        ))
    }

    /// Load immutable source bytes without permitting an allocation above
    /// `max_bytes`.
    ///
    /// Implementations must inspect trusted object metadata before reading a
    /// body, reject objects larger than `max_bytes`, and also retain the
    /// backend-wide [`MAX_SOURCE_BLOB_BYTES`] safety boundary. This default is
    /// deliberately fail-closed instead of delegating to [`load_source_blob`],
    /// because a security-sensitive caller must never silently downgrade to
    /// an unbounded allocation.
    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        let _ = (repo_id, digest, max_bytes);
        Err(KinDbError::StorageError(
            "bounded immutable source blob reads are not supported by this backend".to_string(),
        ))
    }

    /// Execute integrity-checked immutable-body reads in one backend batch.
    ///
    /// The safe default preserves backend compatibility by delegating each read
    /// to [`load_source_blob_bounded`](Self::load_source_blob_bounded). Local
    /// storage overrides this to retain one repository lock across the complete
    /// operation instead of reacquiring it for every content address.
    ///
    /// The callback shape lets callers stream globally de-duplicated bodies
    /// instead of materializing their aggregate bytes in memory.
    ///
    /// Implementations must invoke `operation` exactly once. If it returns an
    /// error, the backend must propagate that failure and must not return
    /// success. Repository authority callers enforce both rules fail closed.
    fn with_verified_source_blob_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        let batch = DefaultVerifiedSourceBlobBatch {
            backend: self,
            repo_id,
        };
        operation(&batch)
    }

    /// Write many immutable bodies under one repository authority envelope.
    ///
    /// A local backend takes the repository lock once for the whole session
    /// and issues one set of durability barriers at the flush instead of a
    /// full lock-and-barrier cycle per content address. The bodies a batch
    /// publishes are exactly the bodies the same sequence of
    /// [`save_source_blob`](Self::save_source_blob) calls would publish.
    ///
    /// Implementations must invoke `operation` exactly once, must not report
    /// success when it fails, and must leave every body it accepted durable
    /// before returning `Ok`. A caller that needs an earlier durability point
    /// calls [`SourceBlobWriteBatch::flush`] inside the session.
    ///
    /// The default implementation writes each body through `save_source_blob`,
    /// which is already durable per body and makes `flush` a no-op.
    fn with_source_blob_write_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn SourceBlobWriteBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        let batch = DefaultSourceBlobWriteBatch {
            backend: self,
            repo_id,
        };
        operation(&batch)
    }

    /// Load the exact byte length of an immutable source blob.
    ///
    /// Backends should override this with a metadata-only implementation.
    /// The default remains correct for simple/test backends by performing one
    /// integrity-checked bounded read; callers never fall back to filesystem or
    /// Git metadata on an authority path.
    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError> {
        self.load_source_blob_bounded(repo_id, digest, MAX_SOURCE_BLOB_BYTES)?
            .map(|data| {
                u64::try_from(data.len()).map_err(|_| {
                    KinDbError::StorageError(
                        "immutable source blob length does not fit u64".to_string(),
                    )
                })
            })
            .transpose()
    }

    /// Save a snapshot with compare-and-swap semantics.
    ///
    /// `expected_gen` is the generation returned by the last `load_snapshot`
    /// for a journal-free snapshot. When an acknowledged journal exists, a
    /// caller promoting recovered bytes must use `RecoveredSnapshot::generation`.
    /// Passing the base generation returned with base bytes intentionally loses
    /// CAS against the later journal head. If stored authority has changed, the
    /// backend must return an error.
    ///
    /// On success returns the new generation.
    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError>;

    /// Save a snapshot while classifying whether an error is known to precede
    /// installation or may have occurred after installation.
    ///
    /// The default is deliberately conservative: legacy backends only prove
    /// success. Any error remains indeterminate until the caller reconciles
    /// exact installed bytes. Backends with a precise commit boundary should
    /// override this method.
    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        match self.save_snapshot(repo_id, data, expected_cursor.backend_generation()) {
            Ok(generation) => SnapshotSaveOutcome::Committed {
                cursor: SnapshotCursor::from_backend_generation(generation),
            },
            Err(error) => SnapshotSaveOutcome::Indeterminate(error),
        }
    }

    /// Save a delta (incremental diff from a base snapshot generation).
    ///
    /// `delta_data` is the serialized `GraphSnapshotDelta` bytes. The delta
    /// is stored alongside the base snapshot and can be loaded via
    /// `load_deltas_since`. Backends that don't support deltas can return
    /// `Err` — callers should fall back to full snapshot save.
    ///
    /// `base_gen` is the generation of the snapshot this delta was computed
    /// against. On success returns the new generation.
    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError>;

    /// Load all delta files for a repo since a given generation.
    ///
    /// Returns deltas ordered by generation (oldest first). Each entry
    /// contains the serialized delta bytes and the generation it was saved at.
    /// Callers deserialize with `GraphSnapshotDelta::from_bytes()` and apply
    /// sequentially.
    ///
    /// Returns `Ok(vec![])` if no deltas exist since the given generation.
    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError>;

    /// Compact deltas: merge all deltas into the base snapshot, run GC
    /// to remove orphaned data, and remove the delta files.
    ///
    /// After compaction, the snapshot at the returned generation contains
    /// all changes with orphaned cross-references cleaned up, and no
    /// deltas remain. For large graphs (>500K entities) this also
    /// reclaims space from accumulated orphaned relations, stale test
    /// coverage entries, and other dangling references.
    ///
    /// Default implementation loads the snapshot, applies all deltas,
    /// runs `GraphSnapshot::compact()` for GC, saves the merged snapshot,
    /// and clears the delta journal.
    fn compact_deltas(&self, repo_id: &str) -> Result<Generation, KinDbError> {
        let recovered = load_recovered_snapshot(self, repo_id)?
            .ok_or_else(|| KinDbError::StorageError("no snapshot to compact".to_string()))?;
        if recovered.deltas_seen == 0 {
            return Ok(recovered.generation);
        }
        if recovered.deltas_applied == 0 {
            self.clear_deltas(repo_id)?;
            return Ok(recovered.generation);
        }

        // GC pass: remove orphaned cross-references accumulated over deltas
        let mut snapshot = recovered.snapshot;
        snapshot.compact();

        let merged_bytes = snapshot.to_bytes()?;
        let new_gen = self.save_snapshot(repo_id, &merged_bytes, recovered.generation)?;
        if let Err(error) = self.clear_deltas(repo_id) {
            // The full snapshot authority is already committed. Returning an
            // error here would strand the caller on `recovered.generation`
            // and make its retry collide with its own successful commit.
            tracing::warn!(
                repo_id,
                generation = new_gen,
                error = %error,
                "snapshot compaction committed; deferred stale delta cleanup"
            );
        }
        Ok(new_gen)
    }

    /// Remove all delta files for a repo. Called after compaction.
    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError>;

    /// Save ephemeral overlay state (for preemption recovery).
    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError>;

    /// Load overlay state (after preemption recovery).
    ///
    /// Returns `Ok(None)` if no overlay exists for this session.
    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError>;

    /// Delete an overlay after it has been committed or is no longer needed.
    ///
    /// Returns `Ok(())` if the overlay was deleted or did not exist.
    /// This prevents overlay accumulation on remote backends like GCS.
    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError>;

    /// List all repo IDs available in storage.
    ///
    /// For local: list subdirectories in the base path that contain `authority.json`.
    /// For GCS: list top-level prefixes in the bucket under the configured prefix.
    fn list_repos(&self) -> Result<Vec<String>, KinDbError>;
}

struct DefaultVerifiedSourceBlobBatch<'a, B: StorageBackend + ?Sized> {
    backend: &'a B,
    repo_id: &'a str,
}

struct DefaultSourceBlobWriteBatch<'a, B: StorageBackend + ?Sized> {
    backend: &'a B,
    repo_id: &'a str,
}

impl<B: StorageBackend + ?Sized> SourceBlobWriteBatch for DefaultSourceBlobWriteBatch<'_, B> {
    fn save(&self, digest: [u8; 32], data: &[u8]) -> Result<(), KinDbError> {
        self.backend.save_source_blob(self.repo_id, digest, data)
    }

    fn flush(&self) -> Result<(), KinDbError> {
        Ok(())
    }
}

impl<B: StorageBackend + ?Sized> VerifiedSourceBlobBatch for DefaultVerifiedSourceBlobBatch<'_, B> {
    fn load_verified(
        &self,
        request: SourceBlobValidationRequest,
    ) -> Result<Option<VerifiedSourceBlob>, KinDbError> {
        self.backend
            .load_source_blob_bounded(self.repo_id, request.digest, request.max_bytes)?
            .map(|bytes| VerifiedSourceBlob::from_verified_bytes(request.digest, bytes))
            .transpose()
    }
}

/// Local filesystem storage backend for developer machines.
///
/// Layout under `base_path`:
/// ```text
/// {base_path}/{repo_id}/authority.json      — atomic base/head authority
/// {base_path}/{repo_id}/snapshots/GEN.kndb  — immutable snapshot versions
/// {base_path}/{repo_id}/source-blobs/sha256/HH/HASH — immutable exact source bytes
/// {base_path}/{repo_id}/overlays/{session_id}.bin — overlay state
/// ```
///
/// Snapshot and delta files are staged and fsynced before `authority.json` is
/// atomically replaced. That single authority rename is the commit point: a
/// crash before it leaves an ignored orphan, while a crash after it leaves a
/// complete base-to-head chain.
pub struct LocalFileBackend {
    base_path: PathBuf,
    storage_root_capability: parking_lot::Mutex<Option<std::sync::Arc<LocalStorageRootCapability>>>,
    repository_namespaces: parking_lot::Mutex<
        std::collections::HashMap<String, std::sync::Arc<LocalRepositoryCapability>>,
    >,
    poisoned_repository_namespaces:
        parking_lot::Mutex<std::collections::HashMap<String, LocalStorageRootIdentity>>,
    #[cfg(unix)]
    source_root_confirmed_for_process: parking_lot::Mutex<bool>,
    #[cfg(test)]
    fail_before_authority_commit: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_delta_cleanup: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    recovery_after_authority_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    compaction_before_delta_cleanup_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    cleanup_after_quarantine_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_before_authority_commit_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_after_authority_commit_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_retry_before_confirmation_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_cleanup_before_confirmation_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    delta_before_authority_commit_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    overlay_after_write_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    source_blob_after_capability_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    source_blob_before_publish_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct LocalStorageRootIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
type LocalStorageRootIdentity = WindowsSourceIdentity;

/// What the storage holds at one namespace name.
enum LocalDirectoryEntry {
    /// A real directory, with the filesystem identity that names its epoch.
    Directory(LocalStorageRootIdentity),
    /// Nothing occupies the name.
    Absent,
    /// Something occupies the name that can never be a namespace. The payload
    /// completes the refusal sentence describing what it is.
    NotADirectory(&'static str),
}

/// Why revalidating a pinned repository namespace refused.
///
/// Both variants mean the exact storage this backend bound is gone. Neither is
/// an IO fault, so a caller may name the repository identity in its answer.
#[derive(Debug)]
pub enum LocalNamespaceIdentityFault {
    /// The storage root under the namespace was replaced or detached.
    StorageRoot(KinDbError),
    /// The repository namespace itself was replaced, detached, or displaced
    /// while it was being created.
    Namespace(KinDbError),
}

impl LocalNamespaceIdentityFault {
    pub fn error(&self) -> &KinDbError {
        match self {
            Self::StorageRoot(error) | Self::Namespace(error) => error,
        }
    }

    pub fn into_error(self) -> KinDbError {
        match self {
            Self::StorageRoot(error) | Self::Namespace(error) => error,
        }
    }
}

impl fmt::Display for LocalNamespaceIdentityFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.error())
    }
}

/// The verdict of [`LocalFileBackend::probe_pinned_repository_namespace`].
///
/// Callers classify on the variant rather than on message text, so a fault that
/// says nothing about identity is never reported as a replaced repository.
#[derive(Debug)]
pub enum LocalNamespaceProbe {
    /// The retained binding still reaches the exact namespace it pinned.
    Retained,
    /// This storage holds no namespace under the repository id.
    Absent,
    /// The pinned namespace no longer holds.
    IdentityLost(LocalNamespaceIdentityFault),
    /// The probe reached no verdict about identity. An IO fault, a permission
    /// fault, or an entry occupying the namespace name that could not be
    /// inspected says nothing about whether the repository was replaced.
    Unavailable(KinDbError),
}

enum LocalStorageRootProbeFault {
    IdentityLost(LocalNamespaceIdentityFault),
    Unavailable(KinDbError),
}

struct LocalStorageRootCapability {
    /// On Windows every ancestor handle deliberately omits DELETE sharing so
    /// the process pins the complete canonical path. On Unix the retained
    /// handles keep all subsequent IO rooted in the opened namespace.
    directories: Vec<cap_std::fs::Dir>,
    identity: LocalStorageRootIdentity,
}

impl LocalStorageRootCapability {
    fn directory(&self) -> &cap_std::fs::Dir {
        self.directories
            .last()
            .expect("local storage capability always retains its root directory")
    }
}

struct LocalRepositoryCapability {
    repo_id: String,
    display_path: PathBuf,
    directory: cap_std::fs::Dir,
    identity: LocalStorageRootIdentity,
    publication_sync_pending: std::sync::atomic::AtomicBool,
    surface_directories: parking_lot::Mutex<
        std::collections::HashMap<String, std::sync::Arc<LocalSurfaceCapability>>,
    >,
    poisoned_surfaces:
        parking_lot::Mutex<std::collections::HashMap<String, LocalStorageRootIdentity>>,
    lock_identity: parking_lot::Mutex<Option<LocalRepositoryLockIdentity>>,
    lock_publication_sync_pending: std::sync::atomic::AtomicBool,
}

/// The digest-prefix directories a write batch pinned, and whose entries it
/// has published but not yet made durable.
///
/// One capability is retained per digest prefix the batch wrote into, which
/// bounds the set at the 256 possible prefixes however many bodies the batch
/// carries. A prefix is walked and namespace-confirmed once, when it is
/// pinned; every later body in that prefix publishes through the pinned
/// descriptor, and the flush re-confirms every pinned prefix before it issues
/// a barrier.
#[cfg(unix)]
#[derive(Default)]
struct DeferredSourceDurability {
    prefixes: parking_lot::Mutex<
        std::collections::BTreeMap<String, std::sync::Arc<SourceBlobCapability>>,
    >,
}

#[cfg(unix)]
impl DeferredSourceDurability {
    /// Pin a digest prefix for the rest of the session, or return the
    /// descriptor already pinned for it.
    ///
    /// The walk that opens a prefix is followed immediately by the same
    /// namespace confirmation a per-object write performs, so a capability
    /// enters the cache only after it has been checked against a fresh
    /// resolution of its own path.
    fn capability(
        &self,
        namespace: &LocalRepositoryCapability,
        prefix: &str,
    ) -> Result<std::sync::Arc<SourceBlobCapability>, KinDbError> {
        let mut prefixes = self.prefixes.lock();
        if let Some(capability) = prefixes.get(prefix) {
            return Ok(std::sync::Arc::clone(capability));
        }
        let capability = std::sync::Arc::new(open_source_blob_prefix_capability_from_repository(
            &namespace.directory,
            &namespace.display_path,
            prefix,
            true,
            false,
        )?);
        confirm_source_blob_prefix_namespace_from_repository(
            &namespace.directory,
            &namespace.display_path,
            prefix,
            &capability,
        )?;
        prefixes.insert(prefix.to_string(), std::sync::Arc::clone(&capability));
        Ok(capability)
    }

    /// Re-confirm every pinned prefix, flush the device once, then issue every
    /// outstanding barrier child before parent: each digest directory that
    /// names bodies, then the prefix chain naming those directories, then the
    /// repository directory naming the chain.
    ///
    /// The confirmations run first and as a group, so a namespace substituted
    /// at any point in the session fails the session before a single name is
    /// made durable.
    ///
    /// The device flush runs next, before the first directory barrier, so at
    /// the moment any name becomes durable every body it could name is
    /// already on stable media.
    ///
    /// The record is cleared only once every barrier succeeded, so a failed
    /// flush stays outstanding and a retry reissues it rather than reporting
    /// durability this batch never reached.
    fn flush(&self, namespace: &LocalRepositoryCapability) -> Result<(), KinDbError> {
        let mut prefixes = self.prefixes.lock();
        if prefixes.is_empty() {
            return Ok(());
        }
        for (prefix, capability) in prefixes.iter() {
            confirm_source_blob_prefix_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                prefix,
                capability,
            )?;
        }
        sync_source_blob_device(namespace)?;
        for capability in prefixes.values() {
            mmap::sync_directory_handle(&capability.leaf_dir, &capability.leaf_path)?;
        }
        sync_source_blob_chain(namespace)?;
        prefixes.clear();
        Ok(())
    }
}

/// Flush the drive's write cache once for the whole write session.
///
/// Each body reached the device behind an ordering barrier, which guarantees
/// it is persisted before anything issued afterwards but promises nothing
/// about when. This is what converts ordered into persisted, and it is issued
/// before the first directory barrier so no name can become durable ahead of
/// its bytes.
///
/// It is issued through the repository directory handle because `F_FULLFSYNC`
/// asks the drive to flush, which is a property of the device rather than of
/// the descriptor it is requested on.
#[cfg(unix)]
fn sync_source_blob_device(namespace: &LocalRepositoryCapability) -> Result<(), KinDbError> {
    let repo_dir = mmap::open_directory_handle_at(
        &namespace.directory,
        Path::new("."),
        &namespace.display_path,
    )
    .map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository capability {}: {error}",
            namespace.display_path.display()
        ))
    })?;
    record_source_device_flush();
    repo_dir.sync_all().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to flush the device before publishing names below {}: {error}",
            namespace.display_path.display()
        ))
    })
}

/// Make the `source-blobs/sha256` chain durable, child before parent.
#[cfg(unix)]
fn sync_source_blob_chain(namespace: &LocalRepositoryCapability) -> Result<(), KinDbError> {
    let repo_dir = mmap::open_directory_handle_at(
        &namespace.directory,
        Path::new("."),
        &namespace.display_path,
    )
    .map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to clone retained repository capability {}: {error}",
            namespace.display_path.display()
        ))
    })?;
    let clone_failed = |display: &Path, error: std::io::Error| {
        KinDbError::StorageError(format!(
            "failed to retain immutable source directory {} for a deferred durability barrier: {error}",
            display.display()
        ))
    };
    let mut display = namespace.display_path.clone();
    let mut parent = repo_dir
        .try_clone()
        .map_err(|error| clone_failed(&display, error))?;
    let mut chain = Vec::new();
    for component in ["source-blobs", "sha256"] {
        display.push(component);
        parent = open_source_directory_at(&parent, component, &display, false, false)?;
        chain.push((
            parent
                .try_clone()
                .map_err(|error| clone_failed(&display, error))?,
            display.clone(),
        ));
    }
    for (directory, display) in chain.iter().rev() {
        mmap::sync_directory_handle(directory, display)?;
    }
    mmap::sync_directory_handle(&repo_dir, &namespace.display_path)
}

/// When a local immutable-body write issues its durability barriers.
///
/// The body's own fsync is not part of this choice: it always precedes the
/// `linkat` that names the body, in both modes. Only the directory and
/// acknowledgement barriers move, so a batch that loses power before its
/// flush loses names, and every body it wrote reads as absent rather than
/// torn. That is the same failure class as crashing partway through a
/// sequence of per-body writes.
#[cfg(unix)]
enum LocalSourceDurability<'a> {
    /// Every barrier is issued before the write returns.
    Immediate,
    /// Directory barriers are recorded and issued at the batch's flush.
    Deferred(&'a DeferredSourceDurability),
}

#[cfg(unix)]
impl LocalSourceDurability<'_> {
    fn confirms_ancestors_inline(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    fn confirms_leaf_inline(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    /// Whether the repository namespace is re-resolved from the filesystem
    /// root around this body.
    ///
    /// A batch is already bracketed by that check: acquiring the repository
    /// lock resolves and identity-matches the namespace before the first body,
    /// and the flush confirms it again after the last. Repeating it per body
    /// re-derives an identity the session already pinned.
    fn confirms_repository_inline(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    /// Whether the digest-prefix chain is re-walked and compared against the
    /// pinned descriptor around this body.
    ///
    /// A batch confirms a prefix when it pins it and again for every pinned
    /// prefix at its flush, so the check moves to the session boundary rather
    /// than disappearing.
    fn confirms_namespace_inline(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    /// Pin the digest-prefix directory this body publishes into.
    fn capability(
        &self,
        namespace: &LocalRepositoryCapability,
        prefix: &str,
    ) -> Result<std::sync::Arc<SourceBlobCapability>, KinDbError> {
        match self {
            Self::Immediate => Ok(std::sync::Arc::new(
                open_source_blob_prefix_capability_from_repository(
                    &namespace.directory,
                    &namespace.display_path,
                    prefix,
                    true,
                    self.confirms_ancestors_inline(),
                )?,
            )),
            Self::Deferred(deferred) => deferred.capability(namespace, prefix),
        }
    }

    /// Acknowledge the inode a body actually landed on.
    ///
    /// A batch owes nothing here. A body this call published was fsynced
    /// before the `linkat` that named it. A body an earlier writer published
    /// is durable too, because a writer releases the repository lock only
    /// after its own barriers, and the bytes are re-verified against the
    /// digest before this point either way.
    fn sync_body(&self, file: &std::fs::File, display: &Path) -> Result<(), KinDbError> {
        match self {
            Self::Immediate => sync_source_file_for_ack(file, display),
            Self::Deferred(_) => Ok(()),
        }
    }

    /// Make the directory entry naming this body durable.
    ///
    /// A batch owes nothing here either: the prefix directory was retained
    /// when it was pinned, so its barrier is already outstanding and the flush
    /// issues one per prefix rather than one per body.
    fn sync_leaf(&self, capability: &SourceBlobCapability) -> Result<(), KinDbError> {
        match self {
            Self::Immediate => {
                mmap::sync_directory_handle(&capability.leaf_dir, &capability.leaf_path)
            }
            Self::Deferred(_) => Ok(()),
        }
    }

    /// How this body's bytes reach the device before the `linkat` names them.
    ///
    /// A per-object write flushes the drive's cache, because nothing later
    /// will. A batch only orders, and pays one device flush for the whole
    /// session at its flush, before any name becomes durable.
    fn body_barrier(&self) -> SourceBodyBarrier {
        match self {
            Self::Immediate => SourceBodyBarrier::FullDevice,
            Self::Deferred(_) => SourceBodyBarrier::Ordering,
        }
    }
}

/// One repository-scoped write session over a held authority lock.
struct LocalSourceBlobWriteBatch<'a> {
    backend: &'a LocalFileBackend,
    namespace: &'a LocalRepositoryCapability,
    repo_id: &'a str,
    #[cfg(unix)]
    deferred: DeferredSourceDurability,
}

impl SourceBlobWriteBatch for LocalSourceBlobWriteBatch<'_> {
    fn save(&self, digest: [u8; 32], data: &[u8]) -> Result<(), KinDbError> {
        validate_source_blob_write_request(self.repo_id, digest, data)?;
        #[cfg(unix)]
        {
            self.backend.publish_source_blob_in_namespace(
                self.namespace,
                digest,
                data,
                &LocalSourceDurability::Deferred(&self.deferred),
            )
        }
        #[cfg(windows)]
        {
            self.backend
                .publish_source_blob_in_namespace(self.namespace, digest, data)
        }
    }

    fn flush(&self) -> Result<(), KinDbError> {
        #[cfg(unix)]
        self.deferred.flush(self.namespace)?;
        self.backend.confirm_repository_visible(self.namespace)
    }
}

struct LocalVerifiedSourceBlobBatch<'a> {
    backend: &'a LocalFileBackend,
    namespace: &'a LocalRepositoryCapability,
}

impl VerifiedSourceBlobBatch for LocalVerifiedSourceBlobBatch<'_> {
    fn load_verified(
        &self,
        request: SourceBlobValidationRequest,
    ) -> Result<Option<VerifiedSourceBlob>, KinDbError> {
        self.backend
            .load_source_blob_bounded_from_namespace(
                self.namespace,
                request.digest,
                request.max_bytes,
                false,
                false,
                false,
            )?
            .map(|bytes| VerifiedSourceBlob::from_verified_bytes(request.digest, bytes))
            .transpose()
    }
}

struct LocalSurfaceCapability {
    name: String,
    display_path: PathBuf,
    directory: cap_std::fs::Dir,
    identity: LocalStorageRootIdentity,
    publication_sync_pending: std::sync::atomic::AtomicBool,
}

enum LocalDirectoryCreateOutcome {
    Published(cap_std::fs::Dir, LocalStorageRootIdentity),
    PublishedUnconfirmed {
        directory: cap_std::fs::Dir,
        identity: LocalStorageRootIdentity,
        error: KinDbError,
    },
    CompetingTarget,
    Displaced {
        identity: LocalStorageRootIdentity,
        error: KinDbError,
    },
}

fn retained_local_directory_is_empty(
    directory: &cap_std::fs::Dir,
    display_path: &Path,
) -> Result<bool, KinDbError> {
    let mut entries = directory.entries().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to inspect retained local directory {}: {error}",
            display_path.display()
        ))
    })?;
    match entries.next() {
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(KinDbError::StorageError(format!(
            "failed to inspect an entry in retained local directory {}: {error}",
            display_path.display()
        ))),
        None => Ok(true),
    }
}

fn confirm_pending_local_directory_publication(
    parent: &cap_std::fs::Dir,
    parent_display_path: &Path,
    child_display_path: &Path,
    pending: &std::sync::atomic::AtomicBool,
) -> Result<(), KinDbError> {
    if !pending.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    let parent_clone =
        mmap::open_directory_handle_at(parent, Path::new("."), parent_display_path).map_err(
            |error| {
                KinDbError::StorageError(format!(
                    "failed to clone retained parent directory {} while confirming publication of {}: {error}",
                    parent_display_path.display(),
                    child_display_path.display()
                ))
            },
        )?;
    mmap::sync_directory_handle(&parent_clone, parent_display_path)?;
    pending.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[cfg(unix)]
type LocalRepositoryLockIdentity = LocalStorageRootIdentity;

#[cfg(windows)]
type LocalRepositoryLockIdentity = WindowsSourceIdentity;

#[cfg(not(any(unix, windows)))]
type LocalRepositoryLockIdentity = LocalStorageRootIdentity;

impl std::fmt::Debug for LocalSurfaceCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSurfaceCapability")
            .field("name", &self.name)
            .field("display_path", &self.display_path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LocalRepositoryCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalRepositoryCapability")
            .field("repo_id", &self.repo_id)
            .field("display_path", &self.display_path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl LocalRepositoryCapability {
    fn display(&self, relative: &Path) -> PathBuf {
        self.display_path.join(relative)
    }

    fn is_empty(&self) -> Result<bool, KinDbError> {
        retained_local_directory_is_empty(&self.directory, &self.display_path)
    }

    fn exists(&self, relative: &Path) -> Result<bool, KinDbError> {
        match self.directory.symlink_metadata(relative) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to inspect retained repository path {}: {error}",
                self.display(relative).display()
            ))),
        }
    }

    fn read_regular_bounded(
        &self,
        relative: &Path,
        role: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, KinDbError> {
        mmap::read_regular_bounded_at(
            &self.directory,
            relative,
            &self.display_path,
            role,
            max_bytes,
        )
    }

    fn sync_parent(&self, relative: &Path) -> Result<(), KinDbError> {
        mmap::sync_parent_dir_at(&self.directory, relative, &self.display_path)
    }

    fn open_surface(&self, name: &str) -> Result<Option<LocalSurfaceCapability>, KinDbError> {
        let display_path = self.display_path.join(name);
        let Some((directory, identity)) = LocalFileBackend::bind_existing_local_directory_at(
            &self.directory,
            name.as_ref(),
            &display_path,
            LocalDirectoryBindKind::Surface,
        )?
        else {
            return Ok(None);
        };
        let publication_sync_pending =
            retained_local_directory_is_empty(&directory, &display_path)?;
        Ok(Some(LocalSurfaceCapability {
            name: name.to_string(),
            display_path,
            directory,
            identity,
            publication_sync_pending: std::sync::atomic::AtomicBool::new(publication_sync_pending),
        }))
    }

    fn surface(
        &self,
        name: &str,
        create: bool,
    ) -> Result<Option<std::sync::Arc<LocalSurfaceCapability>>, KinDbError> {
        validate_local_storage_component(name, "repository surface")?;
        let mut surfaces = self.surface_directories.lock();
        if self.poisoned_surfaces.lock().contains_key(name) {
            return Err(KinDbError::StorageError(format!(
                "local repository surface {} was displaced during creation; this backend will not bind a replacement epoch",
                self.display_path.join(name).display()
            )));
        }
        if let Some(expected) = surfaces.get(name) {
            let current = self.open_surface(name)?;
            return match current {
                Some(current) if current.identity == expected.identity => {
                    confirm_pending_local_directory_publication(
                        &self.directory,
                        &self.display_path,
                        &expected.display_path,
                        &expected.publication_sync_pending,
                    )?;
                    Ok(Some(std::sync::Arc::clone(expected)))
                }
                Some(_) => Err(KinDbError::StorageError(format!(
                    "local repository surface {} changed since this backend opened",
                    expected.display_path.display()
                ))),
                None => Err(KinDbError::StorageError(format!(
                    "local repository surface {} was detached after this backend opened",
                    expected.display_path.display()
                ))),
            };
        }

        let mut current = self.open_surface(name)?;
        if current.is_none() && create {
            let display_path = self.display_path.join(name);
            current = match LocalFileBackend::create_bound_local_directory_at(
                &self.directory,
                name.as_ref(),
                &display_path,
                LocalDirectoryBindKind::Surface,
            )? {
                LocalDirectoryCreateOutcome::Published(directory, identity) => {
                    Some(LocalSurfaceCapability {
                        name: name.to_string(),
                        display_path,
                        directory,
                        identity,
                        publication_sync_pending: std::sync::atomic::AtomicBool::new(false),
                    })
                }
                LocalDirectoryCreateOutcome::PublishedUnconfirmed {
                    directory,
                    identity,
                    error,
                } => {
                    let retained = std::sync::Arc::new(LocalSurfaceCapability {
                        name: name.to_string(),
                        display_path,
                        directory,
                        identity,
                        publication_sync_pending: std::sync::atomic::AtomicBool::new(true),
                    });
                    surfaces.insert(name.to_string(), retained);
                    return Err(error);
                }
                LocalDirectoryCreateOutcome::CompetingTarget => self.open_surface(name)?,
                LocalDirectoryCreateOutcome::Displaced { identity, error } => {
                    self.poisoned_surfaces
                        .lock()
                        .insert(name.to_string(), identity);
                    return Err(error);
                }
            };
        }
        let Some(current) = current else {
            return Ok(None);
        };
        let current = std::sync::Arc::new(current);
        surfaces.insert(name.to_string(), std::sync::Arc::clone(&current));
        if create {
            confirm_pending_local_directory_publication(
                &self.directory,
                &self.display_path,
                &current.display_path,
                &current.publication_sync_pending,
            )?;
        }
        Ok(Some(current))
    }

    fn confirm_surface_visible(&self, surface: &LocalSurfaceCapability) -> Result<(), KinDbError> {
        let current = self.open_surface(&surface.name)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local repository surface {} was detached while capability was held",
                surface.display_path.display()
            ))
        })?;
        if current.identity != surface.identity {
            return Err(KinDbError::StorageError(format!(
                "local repository surface {} changed while capability was held",
                surface.display_path.display()
            )));
        }
        Ok(())
    }
}

impl LocalSurfaceCapability {
    fn display(&self, leaf: &Path) -> PathBuf {
        self.display_path.join(leaf)
    }

    fn require_leaf(leaf: &Path) -> Result<(), KinDbError> {
        let mut components = leaf.components();
        if matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
        {
            Ok(())
        } else {
            Err(KinDbError::StorageError(format!(
                "local repository surface path must be one exact leaf: {}",
                leaf.display()
            )))
        }
    }

    fn exists(&self, leaf: &Path) -> Result<bool, KinDbError> {
        Self::require_leaf(leaf)?;
        match self.directory.symlink_metadata(leaf) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to inspect retained repository surface path {}: {error}",
                self.display(leaf).display()
            ))),
        }
    }

    fn atomic_write(&self, leaf: &Path, data: &[u8]) -> Result<(), KinDbError> {
        Self::require_leaf(leaf)?;
        mmap::atomic_write_bytes_no_magic_at(&self.directory, leaf, &self.display_path, data)
    }

    fn read_regular(&self, leaf: &Path, role: &str) -> Result<Vec<u8>, KinDbError> {
        Self::require_leaf(leaf)?;
        mmap::read_regular_file_at(&self.directory, leaf, &self.display_path, role)
    }

    fn sync(&self, leaf: &Path) -> Result<(), KinDbError> {
        Self::require_leaf(leaf)?;
        mmap::sync_parent_dir_at(&self.directory, leaf, &self.display_path)
    }
}

#[derive(Debug)]
struct LocalRepositoryLock {
    namespace: std::sync::Arc<LocalRepositoryCapability>,
    _file: std::fs::File,
    #[cfg(unix)]
    _marker_file: std::fs::File,
}

/// One existing local repository authority held beneath its exclusive
/// cross-process lock.
///
/// This is crate-private because callers need the fully validated
/// [`RepositoryAuthorityState`](crate::storage::RepositoryAuthorityState)
/// wrapper exposed by `RepositoryAuthorityManager`, not raw snapshot bytes.
#[derive(Debug)]
pub(crate) struct LocalAuthorityFreezeLock {
    repo_id: String,
    authority: SnapshotAuthority,
    lock: LocalRepositoryLock,
}

impl LocalAuthorityFreezeLock {
    pub(crate) fn authority(&self) -> &SnapshotAuthority {
        &self.authority
    }

    fn require_repository(&self, repo_id: &str) -> Result<(), KinDbError> {
        if self.repo_id == repo_id {
            Ok(())
        } else {
            Err(KinDbError::StorageError(format!(
                "local authority freeze belongs to repo {}, not {repo_id}",
                self.repo_id
            )))
        }
    }

    fn namespace(&self) -> &LocalRepositoryCapability {
        &self.lock.namespace
    }
}

const LOCAL_AUTHORITY_VERSION: u32 = 3;

/// Durable record that one exact snapshot already passed complete open-time
/// validation.
///
/// The record is content-bound: it names the SHA-256 of the exact snapshot
/// bytes it stands for, so it can never be transplanted onto different bytes,
/// a different generation, or a different repository. A reader that recomputes
/// a different digest holds no proof at all and must revalidate in full.
///
/// `validator_version` is supplied by the validator that minted the record,
/// not by storage. Any change to what open-time validation checks bumps it,
/// which refuses every previously minted record and re-establishes the proof
/// with one full validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryValidationProof {
    pub validator_version: u32,
    pub repository_id: String,
    pub generation: Generation,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalDeltaIdentity {
    generation: Generation,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalAuthorityRecord {
    version: u32,
    snapshot_generation: Generation,
    head_generation: Generation,
    snapshot_file: String,
    snapshot_sha256: String,
    /// Exact bytes acknowledged for every generation after the immutable
    /// snapshot base.
    acknowledged_deltas: Vec<LocalDeltaIdentity>,
    /// Exact journal bytes already represented by the promoted full snapshot
    /// but not necessarily removed yet. Cleanup may act only on these bytes.
    retired_deltas: Vec<LocalDeltaIdentity>,
    /// Content-bound record that the authoritative snapshot already passed
    /// complete open-time validation. Absent on records written before this
    /// field existed and on every authority that advanced through a delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history_validation: Option<HistoryValidationProof>,
}

impl LocalFileBackend {
    /// Create a new local backend rooted at `base_path`.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        let base_path = base_path.into();
        let storage_root_capability = Self::open_storage_root_capability(&base_path)
            .ok()
            .flatten()
            .map(std::sync::Arc::new);
        Self {
            base_path,
            storage_root_capability: parking_lot::Mutex::new(storage_root_capability),
            repository_namespaces: parking_lot::Mutex::new(std::collections::HashMap::new()),
            poisoned_repository_namespaces: parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            ),
            #[cfg(unix)]
            source_root_confirmed_for_process: parking_lot::Mutex::new(false),
            #[cfg(test)]
            fail_before_authority_commit: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_delta_cleanup: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            recovery_after_authority_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            compaction_before_delta_cleanup_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            cleanup_after_quarantine_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_before_authority_commit_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_after_authority_commit_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_retry_before_confirmation_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_cleanup_before_confirmation_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            delta_before_authority_commit_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            overlay_after_write_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            source_blob_after_capability_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            source_blob_before_publish_hook: parking_lot::Mutex::new(None),
        }
    }

    /// Return the base path.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    #[cfg(not(windows))]
    fn directory_identity(
        directory: &cap_std::fs::Dir,
    ) -> Result<LocalStorageRootIdentity, KinDbError> {
        use cap_fs_ext::MetadataExt;

        let metadata = directory.dir_metadata().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect retained local directory capability: {error}"
            ))
        })?;
        if !metadata.is_dir() {
            return Err(KinDbError::StorageError(
                "retained local namespace capability is not a directory".to_string(),
            ));
        }
        Ok(LocalStorageRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn directory_identity(
        directory: &cap_std::fs::Dir,
    ) -> Result<LocalStorageRootIdentity, KinDbError> {
        windows_source_directory_identity(directory)
    }

    /// Read what the storage currently holds at one namespace name.
    ///
    /// This separates the three answers the callers need to tell apart: a real
    /// directory and its filesystem identity, nothing at all, and something
    /// occupying the name that can never be a namespace. Only an inspection
    /// that could not reach a verdict is an error.
    #[cfg(not(windows))]
    fn observe_local_directory_entry(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
    ) -> Result<LocalDirectoryEntry, KinDbError> {
        use cap_fs_ext::MetadataExt;

        let metadata = match parent.symlink_metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LocalDirectoryEntry::Absent)
            }
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local directory namespace {}: {error}",
                    display_path.display()
                )))
            }
        };
        #[cfg(windows)]
        if windows_source_metadata_is_reparse(&metadata) {
            return Ok(LocalDirectoryEntry::NotADirectory("is a reparse point"));
        }
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(LocalDirectoryEntry::NotADirectory(
                "is not a real directory",
            ));
        }
        Ok(LocalDirectoryEntry::Directory(LocalStorageRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }

    #[cfg(windows)]
    fn observe_local_directory_entry(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
    ) -> Result<LocalDirectoryEntry, KinDbError> {
        let metadata = match parent.symlink_metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LocalDirectoryEntry::Absent)
            }
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local directory namespace {}: {error}",
                    display_path.display()
                )))
            }
        };
        if windows_source_metadata_is_reparse(&metadata) {
            return Ok(LocalDirectoryEntry::NotADirectory("is a reparse point"));
        }
        if !metadata.is_dir() {
            return Ok(LocalDirectoryEntry::NotADirectory(
                "is not a real directory",
            ));
        }
        let directory = Self::open_local_directory_at(parent, component, display_path)?;
        Ok(LocalDirectoryEntry::Directory(Self::directory_identity(
            &directory,
        )?))
    }

    /// The identity of a real directory at one namespace name.
    ///
    /// An entry occupying the name with something that is not a directory is a
    /// refusal here: callers binding a namespace must not treat it as absent.
    fn local_directory_entry_identity(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
    ) -> Result<Option<LocalStorageRootIdentity>, KinDbError> {
        match Self::observe_local_directory_entry(parent, component, display_path)? {
            LocalDirectoryEntry::Directory(identity) => Ok(Some(identity)),
            LocalDirectoryEntry::Absent => Ok(None),
            LocalDirectoryEntry::NotADirectory(reason) => Err(KinDbError::StorageError(format!(
                "local directory namespace {} {reason}",
                display_path.display()
            ))),
        }
    }

    /// Open one existing descendant directory and prove that the entry seen
    /// before the no-follow open, the retained handle, and the entry visible
    /// afterwards are all the same namespace epoch.
    fn bind_existing_local_directory_at(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
        kind: LocalDirectoryBindKind,
    ) -> Result<Option<(cap_std::fs::Dir, LocalStorageRootIdentity)>, KinDbError> {
        let Some(before) = Self::local_directory_entry_identity(parent, component, display_path)?
        else {
            return Ok(None);
        };
        run_local_directory_after_preopen_hook(kind);
        let directory = if matches!(kind, LocalDirectoryBindKind::Staging) {
            Self::open_staging_local_directory_at(parent, component, display_path)?
        } else {
            Self::open_local_directory_at(parent, component, display_path)?
        };
        let opened = Self::directory_identity(&directory)?;
        let after = Self::local_directory_entry_identity(parent, component, display_path)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local directory namespace {} was detached while its retained capability was opened",
                    display_path.display()
                ))
            })?;
        if before != opened || after != opened {
            return Err(KinDbError::StorageError(format!(
                "local directory namespace {} changed while its retained capability was opened",
                display_path.display()
            )));
        }
        Ok(Some((directory, opened)))
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    fn rename_local_directory_no_replace(
        parent: &cap_std::fs::Dir,
        source: &std::ffi::OsStr,
        target: &std::ffi::OsStr,
    ) -> Result<bool, KinDbError> {
        use std::os::unix::ffi::OsStrExt;

        let source = CString::new(source.as_bytes()).map_err(|_| {
            KinDbError::StorageError("staged local directory name contains NUL".to_string())
        })?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            KinDbError::StorageError("local directory name contains NUL".to_string())
        })?;
        // SAFETY: both names are single NUL-terminated components and both
        // directory descriptors are the same retained parent capability.
        let result = unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(KinDbError::StorageError(format!(
                "failed to publish retained local directory without replacement: {error}"
            )))
        }
    }

    /// Rename one directory entry onto a name the kernel must refuse to
    /// overwrite, reporting the C convention of `0` for success and `-1` with
    /// `errno` set for failure.
    ///
    /// `libc` declares the `renameat2` wrapper only for the environments whose
    /// C library exports one, which on Linux is glibc and Bionic. Every other
    /// Linux environment, musl above all, issues the same kernel call through
    /// `syscall` instead. Both routes reach one kernel entry point with one
    /// flag, so `RENAME_NOREPLACE` is enforced by the kernel rather than by the
    /// C library, and the no-replace publication guarantee does not vary with
    /// the environment a build targets. A kernel too old to implement
    /// `renameat2` fails the call loudly on both routes; it never degrades to a
    /// rename that would replace the winner of a publication race.
    #[cfg(any(target_os = "android", all(target_os = "linux", target_env = "gnu")))]
    unsafe fn renameat2_no_replace(
        source_directory: libc::c_int,
        source_name: *const libc::c_char,
        target_directory: libc::c_int,
        target_name: *const libc::c_char,
    ) -> libc::c_int {
        unsafe {
            libc::renameat2(
                source_directory,
                source_name,
                target_directory,
                target_name,
                libc::RENAME_NOREPLACE as libc::c_uint,
            )
        }
    }

    #[cfg(all(target_os = "linux", not(target_env = "gnu")))]
    unsafe fn renameat2_no_replace(
        source_directory: libc::c_int,
        source_name: *const libc::c_char,
        target_directory: libc::c_int,
        target_name: *const libc::c_char,
    ) -> libc::c_int {
        // `syscall` is variadic, so it reads every argument at full register
        // width. Widen each descriptor and the flag word explicitly rather than
        // letting an `int`-sized argument leave the upper half of its register
        // undefined.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_directory as libc::c_long,
                source_name,
                target_directory as libc::c_long,
                target_name,
                libc::RENAME_NOREPLACE as libc::c_long,
            )
        };
        if result == 0 {
            0
        } else {
            -1
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn rename_local_directory_no_replace(
        parent: &cap_std::fs::Dir,
        source: &std::ffi::OsStr,
        target: &std::ffi::OsStr,
    ) -> Result<bool, KinDbError> {
        use std::os::unix::ffi::OsStrExt;

        let source = CString::new(source.as_bytes()).map_err(|_| {
            KinDbError::StorageError("staged local directory name contains NUL".to_string())
        })?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            KinDbError::StorageError("local directory name contains NUL".to_string())
        })?;
        // SAFETY: both names are single NUL-terminated components and both
        // directory descriptors are the same retained parent capability.
        let result = unsafe {
            Self::renameat2_no_replace(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(KinDbError::StorageError(format!(
                "failed to publish retained local directory without replacement: {error}"
            )))
        }
    }

    #[cfg(windows)]
    fn rename_local_directory_no_replace(
        parent: &cap_std::fs::Dir,
        source: &std::ffi::OsStr,
        target: &std::ffi::OsStr,
    ) -> Result<bool, KinDbError> {
        match parent.rename(source, parent, target) {
            Ok(()) => Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists
                        | std::io::ErrorKind::DirectoryNotEmpty
                        | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                // Windows rename does not replace an existing directory.
                // PermissionDenied is also the result when a competing
                // retained no-delete-share handle already owns the target.
                Ok(false)
            }
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to publish retained Windows local directory without replacement: {error}"
            ))),
        }
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            target_os = "linux",
            target_os = "android"
        ))
    ))]
    fn rename_local_directory_no_replace(
        _parent: &cap_std::fs::Dir,
        _source: &std::ffi::OsStr,
        _target: &std::ffi::OsStr,
    ) -> Result<bool, KinDbError> {
        Err(KinDbError::StorageError(
            "secure no-replace local directory publication is unavailable on this platform; create the repository namespace out of band or use the GCS backend"
                .to_string(),
        ))
    }

    #[cfg(not(any(unix, windows)))]
    fn rename_local_directory_no_replace(
        _parent: &cap_std::fs::Dir,
        _source: &std::ffi::OsStr,
        _target: &std::ffi::OsStr,
    ) -> Result<bool, KinDbError> {
        Err(KinDbError::StorageError(
            "secure no-replace local directory publication is unavailable on this platform; use the GCS backend"
                .to_string(),
        ))
    }

    /// Create one descendant directory under an unpredictable staging name,
    /// retain that exact handle, and atomically publish it without replacing a
    /// competing target.
    fn create_bound_local_directory_at(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
        kind: LocalDirectoryBindKind,
    ) -> Result<LocalDirectoryCreateOutcome, KinDbError> {
        let staging_name = format!(".kin-create-{}", uuid::Uuid::new_v4().as_hyphenated());
        let staging_display = display_path.with_file_name(&staging_name);
        parent.create_dir(&staging_name).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to create randomized local directory staging namespace {}: {error}",
                staging_display.display()
            ))
        })?;
        let (directory, identity) = Self::bind_existing_local_directory_at(
            parent,
            staging_name.as_ref(),
            &staging_display,
            LocalDirectoryBindKind::Staging,
        )?
        .ok_or_else(|| {
            KinDbError::StorageError(format!(
                "randomized local directory staging namespace {} disappeared during creation",
                staging_display.display()
            ))
        })?;
        let staging_clone =
            mmap::open_directory_handle_at(&directory, Path::new("."), &staging_display).map_err(
                |error| {
                    KinDbError::StorageError(format!(
                        "failed to clone randomized local directory staging capability {}: {error}",
                        staging_display.display()
                    ))
                },
            )?;
        mmap::sync_directory_handle(&staging_clone, &staging_display)?;
        // The flush-only clone is no longer part of the retained capability.
        // Drop it before publication: on Windows, a capability-relative clone
        // may omit FILE_SHARE_DELETE and would otherwise block the rename of
        // the very staging directory it just made durable. `directory` was
        // opened through the staging path above with delete sharing enabled,
        // so it remains the identity-pinned handle across publication.
        drop(staging_clone);
        if !Self::rename_local_directory_no_replace(parent, staging_name.as_ref(), component)? {
            tracing::warn!(
                path = %staging_display.display(),
                target = %display_path.display(),
                "preserved an unlinked randomized directory stage after a competing namespace won publication"
            );
            return Ok(LocalDirectoryCreateOutcome::CompetingTarget);
        }
        let parent_display = display_path.parent().unwrap_or_else(|| Path::new("."));
        let publication_sync_error =
            match mmap::open_directory_handle_at(parent, Path::new("."), parent_display) {
                Ok(parent_clone) => {
                    mmap::sync_directory_handle(&parent_clone, parent_display).err()
                }
                Err(error) => Some(KinDbError::StorageError(format!(
                    "failed to clone retained local parent directory for publication sync: {error}"
                ))),
            };
        // Deterministic adversarial tests replace the just-published target
        // here. Production has no hook.
        run_local_directory_after_preopen_hook(kind);
        let visible = match Self::local_directory_entry_identity(parent, component, display_path) {
            Ok(Some(visible)) => visible,
            Ok(None) => {
                return Ok(LocalDirectoryCreateOutcome::Displaced {
                    identity,
                    error: KinDbError::StorageError(format!(
                        "newly published local directory namespace {} was detached before admission",
                        display_path.display()
                    )),
                })
            }
            Err(error) => {
                return Ok(LocalDirectoryCreateOutcome::Displaced {
                    identity,
                    error: KinDbError::StorageError(format!(
                        "newly published local directory namespace {} could not be confirmed before admission: {error}",
                        display_path.display()
                    )),
                })
            }
        };
        if visible != identity {
            return Ok(LocalDirectoryCreateOutcome::Displaced {
                identity,
                error: KinDbError::StorageError(format!(
                    "newly published local directory namespace {} was replaced before admission",
                    display_path.display()
                )),
            });
        }
        let (retained, retained_identity) =
            match Self::bind_existing_local_directory_at(parent, component, display_path, kind) {
                Ok(Some(retained)) => retained,
                Ok(None) => {
                    return Ok(LocalDirectoryCreateOutcome::Displaced {
                        identity,
                        error: KinDbError::StorageError(format!(
                            "newly published local directory namespace {} disappeared before its final retained handle was opened",
                            display_path.display()
                        )),
                    })
                }
                Err(error) => {
                    return Ok(LocalDirectoryCreateOutcome::Displaced {
                        identity,
                        error: KinDbError::StorageError(format!(
                            "newly published local directory namespace {} could not be rebound to its final retained handle: {error}",
                            display_path.display()
                        )),
                    })
                }
            };
        if retained_identity != identity {
            return Ok(LocalDirectoryCreateOutcome::Displaced {
                identity,
                error: KinDbError::StorageError(format!(
                    "newly published local directory namespace {} changed before its final retained handle was opened",
                    display_path.display()
                )),
            });
        }
        match publication_sync_error {
            Some(error) => Ok(LocalDirectoryCreateOutcome::PublishedUnconfirmed {
                directory: retained,
                identity: retained_identity,
                error,
            }),
            None => Ok(LocalDirectoryCreateOutcome::Published(
                retained,
                retained_identity,
            )),
        }
    }

    #[cfg(unix)]
    fn visible_directory_identity(
        metadata: &std::fs::Metadata,
    ) -> Option<LocalStorageRootIdentity> {
        use std::os::unix::fs::MetadataExt;

        Some(LocalStorageRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn visible_directory_identity(
        _metadata: &std::fs::Metadata,
    ) -> Option<LocalStorageRootIdentity> {
        // `MetadataExt::file_index` exposes only the legacy 64-bit file
        // index. ReFS and other Windows filesystems may require the complete
        // `FILE_ID_128`, so visible path metadata must never be treated as an
        // authoritative namespace identity. Retained handles omit
        // `FILE_SHARE_DELETE`, and every identity comparison uses
        // `GetFileInformationByHandleEx(FileIdInfo)` instead.
        None
    }

    #[cfg(not(any(unix, windows)))]
    fn visible_directory_identity(
        _metadata: &std::fs::Metadata,
    ) -> Option<LocalStorageRootIdentity> {
        None
    }

    fn open_local_directory_at(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
    ) -> Result<cap_std::fs::Dir, KinDbError> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};

        #[cfg(windows)]
        validate_windows_source_component(component)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .maybe_dir(true);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let file = parent.open_with(component, &options).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open retained local directory {} without following links: {error}",
                display_path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect retained local directory {}: {error}",
                display_path.display()
            ))
        })?;
        #[cfg(windows)]
        if windows_source_metadata_is_reparse(&metadata) {
            return Err(KinDbError::StorageError(format!(
                "retained local directory {} is a reparse point",
                display_path.display()
            )));
        }
        if !metadata.is_dir() {
            return Err(KinDbError::StorageError(format!(
                "retained local namespace {} is not a directory",
                display_path.display()
            )));
        }
        Ok(cap_std::fs::Dir::from_std_file(file.into_std()))
    }

    fn open_staging_local_directory_at(
        parent: &cap_std::fs::Dir,
        component: &std::ffi::OsStr,
        display_path: &Path,
    ) -> Result<cap_std::fs::Dir, KinDbError> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            validate_windows_source_component(component)?;
            let _ = parent;
            let ambient_path = if display_path.is_absolute() {
                display_path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| {
                        KinDbError::StorageError(format!(
                            "failed to resolve randomized local directory staging namespace {}: {error}",
                            display_path.display()
                        ))
                    })?
                    .join(display_path)
            };

            // cap-std deliberately strips FILE_SHARE_DELETE whenever
            // `maybe_dir(true)` is set, even if the caller requested it. That
            // is correct for a retained sandbox capability but makes a
            // randomized staging directory block its own publication rename.
            // Open this one transient staging handle through CreateFile with
            // delete sharing, no leaf reparse traversal, and verify its full
            // FILE_ID_128 against the parent-relative observations before and
            // after this call in `bind_existing_local_directory_at`.
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let file = options.open(&ambient_path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to open randomized local directory staging namespace {} without following links: {error}",
                    display_path.display()
                ))
            })?;
            let metadata = file.metadata().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect randomized local directory staging namespace {}: {error}",
                    display_path.display()
                ))
            })?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(KinDbError::StorageError(format!(
                    "randomized local directory staging namespace {} is a reparse point",
                    display_path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(KinDbError::StorageError(format!(
                    "randomized local directory staging namespace {} is not a directory",
                    display_path.display()
                )));
            }
            return Ok(cap_std::fs::Dir::from_std_file(file));
        }

        #[cfg(not(windows))]
        {
            Self::open_local_directory_at(parent, component, display_path)
        }
    }

    fn open_storage_root_capability(
        path: &Path,
    ) -> Result<Option<LocalStorageRootCapability>, KinDbError> {
        let visible = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local storage root {}: {error}",
                    path.display()
                )))
            }
        };
        if visible.file_type().is_symlink() || !visible.is_dir() {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} is not a real directory",
                path.display()
            )));
        }
        let visible_identity = Self::visible_directory_identity(&visible);
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to resolve local storage root {}: {error}",
                path.display()
            ))
        })?;
        let ambient_root = canonical
            .ancestors()
            .last()
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local storage root has no filesystem root: {}",
                    canonical.display()
                ))
            })?;
        let relative = canonical.strip_prefix(ambient_root).map_err(|_| {
            KinDbError::StorageError(format!(
                "local storage root is not beneath its filesystem root: {}",
                canonical.display()
            ))
        })?;
        let root = cap_std::fs::Dir::open_ambient_dir(ambient_root, cap_std::ambient_authority())
            .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open local filesystem root {}: {error}",
                ambient_root.display()
            ))
        })?;
        let mut directories = vec![root];
        let mut display = ambient_root.to_path_buf();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(KinDbError::StorageError(format!(
                    "local storage root contains an unsupported component: {}",
                    canonical.display()
                )));
            };
            display.push(name);
            let next = Self::open_local_directory_at(
                directories
                    .last()
                    .expect("filesystem root capability was inserted"),
                name,
                &display,
            )?;
            directories.push(next);
        }
        let identity = Self::directory_identity(
            directories
                .last()
                .expect("local storage capability retains its root"),
        )?;
        if visible_identity.is_some_and(|visible| visible != identity) {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} changed while its retained capability was opened",
                path.display()
            )));
        }

        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to resolve current directory for local storage root: {error}"
                    ))
                })?
                .join(path)
        };
        if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
            let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to resolve local storage root parent {}: {error}",
                    parent.display()
                ))
            })?;
            let parent_capability =
                cap_std::fs::Dir::open_ambient_dir(&canonical_parent, cap_std::ambient_authority())
                    .map_err(|error| {
                        KinDbError::StorageError(format!(
                            "failed to open local storage root parent {}: {error}",
                            canonical_parent.display()
                        ))
                    })?;
            let reopened = Self::open_local_directory_at(&parent_capability, name, &absolute)?;
            if Self::directory_identity(&reopened)? != identity {
                return Err(KinDbError::StorageError(format!(
                    "local storage root {} changed before its retained capability was pinned",
                    path.display()
                )));
            }
        }
        let post_visible = std::fs::symlink_metadata(path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to recheck local storage root {} after pinning: {error}",
                path.display()
            ))
        })?;
        if post_visible.file_type().is_symlink() || !post_visible.is_dir() {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} changed to a non-directory or link while being pinned",
                path.display()
            )));
        }
        if Self::visible_directory_identity(&post_visible)
            .is_some_and(|visible| visible != identity)
        {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} changed while being pinned",
                path.display()
            )));
        }
        Ok(Some(LocalStorageRootCapability {
            directories,
            identity,
        }))
    }

    /// Confirm and return the exact storage-root capability first observed by
    /// this backend. A newly appearing root may be bound only if this process
    /// has never observed an earlier root epoch.
    fn storage_root_capability(
        &self,
    ) -> Result<Option<std::sync::Arc<LocalStorageRootCapability>>, KinDbError> {
        let current = Self::open_storage_root_capability(&self.base_path)?;
        let mut expected = self.storage_root_capability.lock();
        match (expected.as_ref(), current) {
            (Some(expected), Some(current)) if expected.identity == current.identity => {
                Ok(Some(std::sync::Arc::clone(expected)))
            }
            (Some(_), Some(_)) => Err(KinDbError::StorageError(format!(
                "local storage root {} changed since this backend opened; refusing to bind a replacement repository namespace",
                self.base_path.display()
            ))),
            (Some(_), None) => Err(KinDbError::StorageError(format!(
                "local storage root {} was detached after this backend opened",
                self.base_path.display()
            ))),
            (None, Some(current)) => {
                let current = std::sync::Arc::new(current);
                *expected = Some(std::sync::Arc::clone(&current));
                Ok(Some(current))
            }
            (None, None) => Ok(None),
        }
    }

    /// Report whether this backend still reaches the exact repository
    /// namespace it pinned, with no side effects on authority.
    ///
    /// This acquires no repository lock, decodes no snapshot, and finalizes no
    /// quarantine, so a caller revalidating a binding pays a metadata read
    /// rather than a full authority load. It answers the identity question
    /// only: a truncated snapshot, a missing lock file, or a quarantined state
    /// on an intact namespace does not change the identity answer from
    /// [`LocalNamespaceProbe::Retained`]. A fault that prevents the identity
    /// itself from being inspected is [`LocalNamespaceProbe::Unavailable`].
    ///
    /// Ordering matches the authority reads. The first probe on a fresh backend
    /// is what takes the pin, so a swap landing before it becomes the baseline
    /// rather than a refusal, and a long-lived process must probe once at
    /// startup and again on every later bind.
    pub fn probe_pinned_repository_namespace(&self, repo_id: &str) -> LocalNamespaceProbe {
        if let Err(error) = validate_source_blob_repo_id(repo_id) {
            return LocalNamespaceProbe::Unavailable(error);
        }
        let (pinned, namespace_poisoned) = {
            let namespaces = self.repository_namespaces.lock();
            let namespace_poisoned = self
                .poisoned_repository_namespaces
                .lock()
                .contains_key(repo_id);
            (namespaces.get(repo_id).cloned(), namespace_poisoned)
        };
        if namespace_poisoned {
            let display_path = pinned.as_ref().map_or_else(
                || self.base_path.join(repo_id),
                |expected| expected.display_path.clone(),
            );
            return LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(
                KinDbError::StorageError(format!(
                    "local repository namespace {} was displaced during creation; this backend will not bind a replacement epoch",
                    display_path.display()
                )),
            ));
        }
        let Some(expected) = pinned else {
            // Nothing is pinned yet, and the first read is what takes the pin.
            // Bind through the capability path so the probe claims the same
            // epoch a later authority read will, and report presence: with no
            // identity claimed there is no identity to have lost.
            return match self.repository_capability(repo_id, false) {
                Ok(Some(_)) => LocalNamespaceProbe::Retained,
                Ok(None) => LocalNamespaceProbe::Absent,
                Err(error)
                    if self
                        .poisoned_repository_namespaces
                        .lock()
                        .contains_key(repo_id) =>
                {
                    LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(error))
                }
                Err(error) => LocalNamespaceProbe::Unavailable(error),
            };
        };

        let root = match self.revalidate_pinned_storage_root() {
            Ok(Some(root)) => root,
            Ok(None) => {
                return LocalNamespaceProbe::Unavailable(KinDbError::StorageError(format!(
                    "local storage root {} holds a pinned repository namespace but reports no bound root",
                    self.base_path.display()
                )))
            }
            Err(LocalStorageRootProbeFault::IdentityLost(fault)) => {
                return LocalNamespaceProbe::IdentityLost(fault)
            }
            Err(LocalStorageRootProbeFault::Unavailable(error)) => {
                return LocalNamespaceProbe::Unavailable(error)
            }
        };

        let observed = Self::observe_local_directory_entry(
            root.directory(),
            repo_id.as_ref(),
            &expected.display_path,
        );
        match observed {
            Ok(LocalDirectoryEntry::Directory(identity)) if identity == expected.identity => {
                LocalNamespaceProbe::Retained
            }
            Ok(LocalDirectoryEntry::Directory(_)) => {
                LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(
                    KinDbError::StorageError(format!(
                        "local repository namespace {} changed since this backend opened; refusing replacement authority",
                        expected.display_path.display()
                    )),
                ))
            }
            Ok(LocalDirectoryEntry::Absent) => {
                LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(
                    KinDbError::StorageError(format!(
                        "local repository namespace {} was detached after this backend opened",
                        expected.display_path.display()
                    )),
                ))
            }
            // A namespace name now occupied by a file, a symlink, or a reparse
            // point is the pinned directory gone, which is a structural
            // replacement rather than a fault this probe could not read.
            Ok(LocalDirectoryEntry::NotADirectory(reason)) => {
                LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(
                    KinDbError::StorageError(format!(
                        "local repository namespace {} {reason} after this backend opened",
                        expected.display_path.display()
                    )),
                ))
            }
            Err(error) => LocalNamespaceProbe::Unavailable(error),
        }
    }

    /// Compare the storage root this backend pinned against the one the path
    /// reaches now, distinguishing a replaced or detached root from a root that
    /// could not be inspected at all.
    fn revalidate_pinned_storage_root(
        &self,
    ) -> std::result::Result<
        Option<std::sync::Arc<LocalStorageRootCapability>>,
        LocalStorageRootProbeFault,
    > {
        let current = match Self::open_storage_root_capability(&self.base_path) {
            Ok(current) => current,
            Err(error) => {
                let expected = self.storage_root_capability.lock().clone();
                return Err(self.classify_storage_root_open_error(expected.as_deref(), error));
            }
        };
        let expected = self.storage_root_capability.lock();
        match (expected.as_ref(), current) {
            (Some(expected), Some(current)) if expected.identity == current.identity => {
                Ok(Some(std::sync::Arc::clone(expected)))
            }
            (Some(_), Some(_)) => Err(LocalStorageRootProbeFault::IdentityLost(
                LocalNamespaceIdentityFault::StorageRoot(KinDbError::StorageError(format!(
                    "local storage root {} changed since this backend opened; refusing to bind a replacement repository namespace",
                    self.base_path.display()
                ))),
            )),
            (Some(_), None) => Err(LocalStorageRootProbeFault::IdentityLost(
                LocalNamespaceIdentityFault::StorageRoot(KinDbError::StorageError(format!(
                    "local storage root {} was detached after this backend opened",
                    self.base_path.display()
                ))),
            )),
            (None, _) => Ok(None),
        }
    }

    /// Classify a failed ambient reopen by observing what the root path names
    /// now. A missing, linked, non-directory, or identity-different path is a
    /// structural replacement of a root this backend pinned. If the path still
    /// names the pinned directory, or cannot itself be inspected, the reopen
    /// error says nothing conclusive about identity and remains unavailable.
    fn classify_storage_root_open_error(
        &self,
        expected: Option<&LocalStorageRootCapability>,
        error: KinDbError,
    ) -> LocalStorageRootProbeFault {
        let Some(expected) = expected else {
            return LocalStorageRootProbeFault::Unavailable(error);
        };
        let visible = match std::fs::symlink_metadata(&self.base_path) {
            Ok(visible) => visible,
            Err(observation_error) if observation_error.kind() == std::io::ErrorKind::NotFound => {
                return LocalStorageRootProbeFault::IdentityLost(
                    LocalNamespaceIdentityFault::StorageRoot(KinDbError::StorageError(format!(
                        "local storage root {} was detached after this backend opened",
                        self.base_path.display()
                    ))),
                )
            }
            Err(_) => return LocalStorageRootProbeFault::Unavailable(error),
        };
        if visible.file_type().is_symlink() || !visible.is_dir() {
            return LocalStorageRootProbeFault::IdentityLost(
                LocalNamespaceIdentityFault::StorageRoot(KinDbError::StorageError(format!(
                    "local storage root {} changed to a non-directory or link since this backend opened; refusing replacement authority",
                    self.base_path.display()
                ))),
            );
        }
        if Self::visible_directory_identity(&visible)
            .is_some_and(|identity| identity != expected.identity)
        {
            return LocalStorageRootProbeFault::IdentityLost(
                LocalNamespaceIdentityFault::StorageRoot(KinDbError::StorageError(format!(
                    "local storage root {} changed since this backend opened; refusing to bind a replacement repository namespace",
                    self.base_path.display()
                ))),
            );
        }
        LocalStorageRootProbeFault::Unavailable(error)
    }

    fn open_repository_from_root(
        root: &LocalStorageRootCapability,
        repo_id: &str,
        base_path: &Path,
    ) -> Result<Option<LocalRepositoryCapability>, KinDbError> {
        let display_path = base_path.join(repo_id);
        let Some((directory, identity)) = Self::bind_existing_local_directory_at(
            root.directory(),
            repo_id.as_ref(),
            &display_path,
            LocalDirectoryBindKind::Repository,
        )?
        else {
            return Ok(None);
        };
        let publication_sync_pending =
            retained_local_directory_is_empty(&directory, &display_path)?;
        Ok(Some(LocalRepositoryCapability {
            repo_id: repo_id.to_string(),
            display_path,
            directory,
            identity,
            publication_sync_pending: std::sync::atomic::AtomicBool::new(publication_sync_pending),
            surface_directories: parking_lot::Mutex::new(std::collections::HashMap::new()),
            poisoned_surfaces: parking_lot::Mutex::new(std::collections::HashMap::new()),
            lock_identity: parking_lot::Mutex::new(None),
            lock_publication_sync_pending: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    fn reject_repository_identity_alias(
        root: &LocalStorageRootCapability,
        repo_id: &str,
        identity: LocalStorageRootIdentity,
        base_path: &Path,
    ) -> Result<(), KinDbError> {
        for entry in root.directory().entries().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to scan local storage root {} for repository aliases: {error}",
                base_path.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect local repository alias candidate: {error}"
                ))
            })?;
            let name = entry.file_name();
            if name == std::ffi::OsStr::new(repo_id) {
                continue;
            }
            let file_type = entry.file_type().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect local repository alias candidate {}: {error}",
                    base_path.join(&name).display()
                ))
            })?;
            if !file_type.is_dir() {
                continue;
            }
            let candidate_identity = match Self::bind_existing_local_directory_at(
                root.directory(),
                &name,
                &base_path.join(&name),
                LocalDirectoryBindKind::Repository,
            ) {
                Ok(Some((_candidate, identity))) => identity,
                Ok(None) => continue,
                Err(error) => {
                    return Err(KinDbError::StorageError(format!(
                        "failed closed while checking repository alias candidate {}: {error}",
                        base_path.join(&name).display()
                    )))
                }
            };
            if candidate_identity == identity {
                return Err(KinDbError::StorageError(format!(
                    "repository id {repo_id:?} aliases existing directory name {:?} on this filesystem; exact repository identities may not share one storage namespace",
                    name
                )));
            }
        }
        Ok(())
    }

    fn repository_capability(
        &self,
        repo_id: &str,
        create: bool,
    ) -> Result<Option<std::sync::Arc<LocalRepositoryCapability>>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let Some(root) = self.storage_root_capability()? else {
            if create {
                return Err(KinDbError::StorageError(format!(
                    "local storage root {} is unavailable; refusing to recreate a detached authority namespace",
                    self.base_path.display()
                )));
            }
            return Ok(None);
        };
        let mut namespaces = self.repository_namespaces.lock();
        if self
            .poisoned_repository_namespaces
            .lock()
            .contains_key(repo_id)
        {
            return Err(KinDbError::StorageError(format!(
                "local repository namespace {} was displaced during creation; this backend will not bind a replacement epoch",
                self.base_path.join(repo_id).display()
            )));
        }
        if let Some(expected) = namespaces.get(repo_id) {
            let current = Self::open_repository_from_root(&root, repo_id, &self.base_path)?;
            match current {
                Some(current) if current.identity == expected.identity => {
                    confirm_pending_local_directory_publication(
                        root.directory(),
                        &self.base_path,
                        &expected.display_path,
                        &expected.publication_sync_pending,
                    )?;
                    return Ok(Some(std::sync::Arc::clone(expected)))
                }
                Some(_) => {
                    return Err(KinDbError::StorageError(format!(
                        "local repository namespace {} changed since this backend opened; refusing replacement authority",
                        expected.display_path.display()
                    )))
                }
                None => {
                    return Err(KinDbError::StorageError(format!(
                        "local repository namespace {} was detached after this backend opened",
                        expected.display_path.display()
                    )))
                }
            }
        }

        let mut current = Self::open_repository_from_root(&root, repo_id, &self.base_path)?;
        if current.is_none() && create {
            let display_path = self.base_path.join(repo_id);
            current = match Self::create_bound_local_directory_at(
                root.directory(),
                repo_id.as_ref(),
                &display_path,
                LocalDirectoryBindKind::Repository,
            )? {
                LocalDirectoryCreateOutcome::Published(directory, identity) => {
                    Some(LocalRepositoryCapability {
                        repo_id: repo_id.to_string(),
                        display_path,
                        directory,
                        identity,
                        publication_sync_pending: std::sync::atomic::AtomicBool::new(false),
                        surface_directories: parking_lot::Mutex::new(
                            std::collections::HashMap::new(),
                        ),
                        poisoned_surfaces: parking_lot::Mutex::new(std::collections::HashMap::new()),
                        lock_identity: parking_lot::Mutex::new(None),
                        lock_publication_sync_pending: std::sync::atomic::AtomicBool::new(false),
                    })
                }
                LocalDirectoryCreateOutcome::PublishedUnconfirmed {
                    directory,
                    identity,
                    error,
                } => {
                    let retained = std::sync::Arc::new(LocalRepositoryCapability {
                        repo_id: repo_id.to_string(),
                        display_path,
                        directory,
                        identity,
                        publication_sync_pending: std::sync::atomic::AtomicBool::new(true),
                        surface_directories: parking_lot::Mutex::new(
                            std::collections::HashMap::new(),
                        ),
                        poisoned_surfaces: parking_lot::Mutex::new(std::collections::HashMap::new()),
                        lock_identity: parking_lot::Mutex::new(None),
                        lock_publication_sync_pending: std::sync::atomic::AtomicBool::new(false),
                    });
                    namespaces.insert(repo_id.to_string(), retained);
                    return Err(error);
                }
                LocalDirectoryCreateOutcome::CompetingTarget => {
                    Self::open_repository_from_root(&root, repo_id, &self.base_path)?
                }
                LocalDirectoryCreateOutcome::Displaced { identity, error } => {
                    self.poisoned_repository_namespaces
                        .lock()
                        .insert(repo_id.to_string(), identity);
                    return Err(error);
                }
            };
        }
        let Some(current) = current else {
            return Ok(None);
        };
        if let Some((existing_id, _)) = namespaces.iter().find(|(existing_id, expected)| {
            existing_id.as_str() != repo_id && expected.identity == current.identity
        }) {
            return Err(KinDbError::StorageError(format!(
                "repository ids {repo_id:?} and {existing_id:?} resolve to the same retained storage namespace"
            )));
        }
        Self::reject_repository_identity_alias(&root, repo_id, current.identity, &self.base_path)?;
        let current = std::sync::Arc::new(current);
        namespaces.insert(repo_id.to_string(), std::sync::Arc::clone(&current));
        if create {
            confirm_pending_local_directory_publication(
                root.directory(),
                &self.base_path,
                &current.display_path,
                &current.publication_sync_pending,
            )?;
        }
        Ok(Some(current))
    }

    fn confirm_repository_visible(
        &self,
        namespace: &LocalRepositoryCapability,
    ) -> Result<(), KinDbError> {
        record_repository_visibility_confirmation();
        let root = self.storage_root_capability()?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local storage root {} disappeared while repository capability was held",
                self.base_path.display()
            ))
        })?;
        let current = Self::open_repository_from_root(&root, &namespace.repo_id, &self.base_path)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local repository namespace {} was detached while capability was held",
                    namespace.display_path.display()
                ))
            })?;
        if current.identity != namespace.identity {
            return Err(KinDbError::StorageError(format!(
                "local repository namespace {} changed while capability was held",
                namespace.display_path.display()
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    fn authority_path(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("authority.json")
    }

    fn authority_relative_path() -> &'static Path {
        Path::new("authority.json")
    }

    #[cfg(test)]
    fn snapshots_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("snapshots")
    }

    fn snapshots_surface_name() -> &'static str {
        "snapshots"
    }

    #[cfg(test)]
    fn versioned_snapshot_path(&self, repo_id: &str, generation: Generation) -> PathBuf {
        self.snapshots_dir(repo_id)
            .join(format!("{generation:020}.kndb"))
    }

    fn versioned_snapshot_leaf(generation: Generation) -> PathBuf {
        PathBuf::from(format!("{generation:020}.kndb"))
    }

    #[cfg(all(test, unix))]
    fn overlay_path(&self, repo_id: &str, session_id: &str) -> PathBuf {
        self.base_path
            .join(repo_id)
            .join("overlays")
            .join(format!("{session_id}.bin"))
    }

    #[cfg(test)]
    fn source_blob_path(&self, repo_id: &str, digest: [u8; 32]) -> Result<PathBuf, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let digest = hex::encode(digest);
        Ok(self
            .base_path
            .join(repo_id)
            .join("source-blobs")
            .join("sha256")
            .join(&digest[..2])
            .join(digest))
    }

    #[cfg(test)]
    fn deltas_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("deltas")
    }

    fn deltas_surface_name() -> &'static str {
        "deltas"
    }

    #[cfg(test)]
    fn delta_path(&self, repo_id: &str, gen: Generation) -> PathBuf {
        self.deltas_dir(repo_id).join(format!("{gen:020}.kndd"))
    }

    fn delta_leaf(generation: Generation) -> PathBuf {
        PathBuf::from(format!("{generation:020}.kndd"))
    }

    fn overlays_surface_name() -> &'static str {
        "overlays"
    }

    fn overlay_leaf(session_id: &str) -> Result<PathBuf, KinDbError> {
        validate_local_storage_component(session_id, "overlay session id")?;
        if session_id.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(KinDbError::StorageError(
                "overlay session id must use canonical lowercase ASCII".to_string(),
            ));
        }
        let leaf = format!("{session_id}.bin");
        validate_local_storage_component(&leaf, "overlay session id")?;
        if leaf.len() > mmap::MAX_ATOMIC_DESTINATION_LEAF_BYTES {
            return Err(KinDbError::StorageError(
                "overlay session id exceeds the portable atomic recovery-staging filename budget"
                    .to_string(),
            ));
        }
        Ok(PathBuf::from(leaf))
    }

    fn existing_repository_path(&self, repo_id: &str) -> Result<Option<PathBuf>, KinDbError> {
        Ok(self
            .repository_capability(repo_id, false)?
            .map(|namespace| namespace.display_path.clone()))
    }

    fn open_repository_lock(
        namespace: &LocalRepositoryCapability,
        create: bool,
    ) -> Result<std::fs::File, KinDbError> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};

        let lock_path = namespace.display_path.join(".lock");
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .create(create)
            .read(true)
            .write(true)
            .truncate(false)
            .follow(FollowSymlinks::No)
            .maybe_dir(false);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let lock_file = namespace
            .directory
            .open_with(".lock", &options)
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to open lock file {}: {error}",
                    lock_path.display()
                ))
            })?;
        let opened_metadata = lock_file.metadata().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect opened local repository authority lock {}: {error}",
                lock_path.display()
            ))
        })?;
        #[cfg(windows)]
        if windows_source_metadata_is_reparse(&opened_metadata) {
            return Err(KinDbError::StorageError(format!(
                "opened local repository authority lock {} is a reparse point",
                lock_path.display()
            )));
        }
        if !opened_metadata.is_file() {
            return Err(KinDbError::StorageError(format!(
                "opened local repository authority lock {} is not a regular file",
                lock_path.display()
            )));
        }
        Ok(lock_file.into_std())
    }

    #[cfg(unix)]
    fn repository_lock_identity(
        lock_file: &std::fs::File,
    ) -> Result<LocalRepositoryLockIdentity, KinDbError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = lock_file.metadata().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect repository lock identity: {error}"
            ))
        })?;
        Ok(LocalStorageRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn repository_lock_identity(
        lock_file: &std::fs::File,
    ) -> Result<LocalRepositoryLockIdentity, KinDbError> {
        windows_source_file_identity(lock_file)
    }

    #[cfg(not(any(unix, windows)))]
    fn repository_lock_identity(
        _lock_file: &std::fs::File,
    ) -> Result<LocalRepositoryLockIdentity, KinDbError> {
        Err(KinDbError::StorageError(
            "secure local repository locking is unavailable on this platform; use the GCS backend"
                .to_string(),
        ))
    }

    fn pin_repository_lock_identity(
        namespace: &LocalRepositoryCapability,
        lock_file: &std::fs::File,
    ) -> Result<(), KinDbError> {
        let observed = Self::repository_lock_identity(lock_file)?;
        let mut expected = namespace.lock_identity.lock();
        match *expected {
            Some(expected) if expected == observed => Ok(()),
            Some(_) => Err(KinDbError::StorageError(format!(
                "local repository authority lock {} changed since this repository namespace was retained",
                namespace.display_path.join(".lock").display()
            ))),
            None => {
                *expected = Some(observed);
                namespace
                    .lock_publication_sync_pending
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }
    }

    fn confirm_repository_lock_publication(
        namespace: &LocalRepositoryCapability,
    ) -> Result<(), KinDbError> {
        if !namespace
            .lock_publication_sync_pending
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        mmap::sync_parent_dir_at(
            &namespace.directory,
            Path::new(".lock"),
            &namespace.display_path,
        )?;
        namespace
            .lock_publication_sync_pending
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    #[cfg(unix)]
    fn repository_lock_target(
        namespace: &LocalRepositoryCapability,
        _marker_file: &std::fs::File,
    ) -> Result<std::fs::File, KinDbError> {
        mmap::open_directory_handle_at(
            &namespace.directory,
            Path::new("."),
            &namespace.display_path,
        )
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to clone retained repository directory {} for locking: {error}",
                namespace.display_path.display()
            ))
        })
    }

    #[cfg(windows)]
    fn repository_lock_target(
        _namespace: &LocalRepositoryCapability,
        marker_file: &std::fs::File,
    ) -> Result<std::fs::File, KinDbError> {
        marker_file.try_clone().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to clone retained repository lock handle: {error}"
            ))
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn repository_lock_target(
        _namespace: &LocalRepositoryCapability,
        _marker_file: &std::fs::File,
    ) -> Result<std::fs::File, KinDbError> {
        Err(KinDbError::StorageError(
            "secure local repository locking is unavailable on this platform; use the GCS backend"
                .to_string(),
        ))
    }

    fn acquire_lock(&self, repo_id: &str) -> Result<LocalRepositoryLock, KinDbError> {
        let namespace = self.repository_capability(repo_id, true)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local repository authority directory {} disappeared during initialization",
                self.base_path.join(repo_id).display()
            ))
        })?;
        let lock_path = namespace.display_path.join(".lock");
        let lock_file = Self::open_repository_lock(&namespace, true)?;
        Self::pin_repository_lock_identity(&namespace, &lock_file)?;
        Self::confirm_repository_lock_publication(&namespace)?;
        let lock_target = Self::repository_lock_target(&namespace, &lock_file)?;
        use fs2::FileExt;
        lock_target.lock_exclusive().map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to acquire exclusive lock on {}: {e}",
                lock_path.display()
            ))
        })?;
        self.confirm_existing_lock_visible(&namespace)?;
        Ok(LocalRepositoryLock {
            namespace,
            _file: lock_target,
            #[cfg(unix)]
            _marker_file: lock_file,
        })
    }

    fn acquire_existing_lock(&self, repo_id: &str) -> Result<LocalRepositoryLock, KinDbError> {
        self.acquire_existing_lock_with_access(repo_id, LocalRepositoryLockAccess::Exclusive)
    }

    /// Take the repository authority lock without excluding other readers.
    ///
    /// Only an entry point that creates nothing, renames nothing and deletes
    /// nothing may use this. A shared holder still excludes every writer,
    /// because every mutation takes the exclusive lock, so what a shared
    /// reader can observe is bounded by the publication protocol rather than
    /// by mutual exclusion.
    fn acquire_existing_shared_lock(
        &self,
        repo_id: &str,
    ) -> Result<LocalRepositoryLock, KinDbError> {
        self.acquire_existing_lock_with_access(repo_id, LocalRepositoryLockAccess::Shared)
    }

    fn acquire_existing_lock_with_access(
        &self,
        repo_id: &str,
        access: LocalRepositoryLockAccess,
    ) -> Result<LocalRepositoryLock, KinDbError> {
        let namespace = self
            .repository_capability(repo_id, false)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local repository authority directory {} is unavailable for existing-authority access",
                    self.base_path.join(repo_id).display()
                ))
            })?;
        let lock_path = namespace.display_path.join(".lock");
        let lock_metadata = namespace
            .directory
            .symlink_metadata(".lock")
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "existing local repository authority lock {} is unavailable: {error}",
                    lock_path.display()
                ))
            })?;
        if lock_metadata.file_type().is_symlink() || !lock_metadata.is_file() {
            return Err(KinDbError::StorageError(format!(
                "existing local repository authority lock {} is not a regular file",
                lock_path.display()
            )));
        }
        let lock_file = Self::open_repository_lock(&namespace, false)?;
        Self::pin_repository_lock_identity(&namespace, &lock_file)?;
        Self::confirm_repository_lock_publication(&namespace)?;
        let lock_target = Self::repository_lock_target(&namespace, &lock_file)?;
        // Named through `fs2::FileExt` rather than by method call: `std`'s
        // `File` grew inherent `lock_shared`, `try_lock_shared` and `unlock`
        // methods that shadow this trait's, so an unqualified call would take
        // one lock through `std` and its exclusive counterpart, which `std`
        // does not provide under that name, through `fs2`.
        let acquired = match access {
            LocalRepositoryLockAccess::Exclusive => fs2::FileExt::lock_exclusive(&lock_target),
            LocalRepositoryLockAccess::Shared => fs2::FileExt::lock_shared(&lock_target),
        };
        acquired.map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to acquire existing local repository authority lock {}: {error}",
                lock_path.display()
            ))
        })?;
        self.confirm_existing_lock_visible(&namespace)?;
        Ok(LocalRepositoryLock {
            namespace,
            _file: lock_target,
            #[cfg(unix)]
            _marker_file: lock_file,
        })
    }

    /// Whether taking the repository authority lock at `access` would block
    /// right now, against the same lock target a real acquisition uses.
    ///
    /// This is how the exclusion property is asserted without a stopwatch:
    /// a blocking acquisition can only be observed by waiting for it, and a
    /// wait that is long enough to mean something is long enough to be flaky.
    #[cfg(test)]
    fn repository_lock_would_block(
        &self,
        repo_id: &str,
        access: LocalRepositoryLockAccess,
    ) -> Result<bool, KinDbError> {
        let namespace = self.repository_capability(repo_id, false)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local repository authority directory {} is unavailable for a lock probe",
                self.base_path.join(repo_id).display()
            ))
        })?;
        let lock_file = Self::open_repository_lock(&namespace, false)?;
        let lock_target = Self::repository_lock_target(&namespace, &lock_file)?;
        let attempt = match access {
            LocalRepositoryLockAccess::Exclusive => fs2::FileExt::try_lock_exclusive(&lock_target),
            LocalRepositoryLockAccess::Shared => fs2::FileExt::try_lock_shared(&lock_target),
        };
        match attempt {
            Ok(()) => {
                fs2::FileExt::unlock(&lock_target)
                    .map_err(|error| KinDbError::StorageError(error.to_string()))?;
                Ok(false)
            }
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(true),
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to probe the local repository authority lock: {error}"
            ))),
        }
    }

    fn acquire_lock_for_initialization(
        &self,
        repo_id: &str,
    ) -> Result<LocalRepositoryLock, KinDbError> {
        let initialize = match self.repository_capability(repo_id, false)? {
            Some(namespace) => namespace.is_empty()?,
            None => true,
        };
        if initialize {
            self.acquire_lock(repo_id)
        } else {
            self.acquire_existing_lock(repo_id)
        }
    }

    fn confirm_existing_lock_visible(
        &self,
        namespace: &LocalRepositoryCapability,
    ) -> Result<(), KinDbError> {
        let lock_path = namespace.display_path.join(".lock");
        let visible = namespace
            .directory
            .symlink_metadata(".lock")
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "local repository authority namespace changed while acquiring {}: {error}",
                    lock_path.display()
                ))
            })?;
        if visible.file_type().is_symlink() || !visible.is_file() {
            return Err(KinDbError::StorageError(format!(
                "local repository authority namespace replaced lock {}",
                lock_path.display()
            )));
        }
        let visible_file = Self::open_repository_lock(namespace, false)?;
        Self::pin_repository_lock_identity(namespace, &visible_file).map_err(|_| {
            KinDbError::StorageError(format!(
                "local repository authority lock {} changed while Kin waited",
                lock_path.display()
            ))
        })?;
        self.confirm_repository_visible(namespace)
    }

    pub(crate) fn freeze_existing_authority(
        &self,
        repo_id: &str,
    ) -> Result<LocalAuthorityFreezeLock, KinDbError> {
        let lock = self.acquire_existing_lock(repo_id)?;
        let authority = self
            .load_authority_unlocked(&lock.namespace)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "repo {repo_id} has no existing local snapshot authority to freeze"
                ))
            })?;
        if authority.snapshot_generation != authority.head_generation {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has incremental journal authority at generation {} above snapshot {}; repository freeze requires one complete full snapshot",
                authority.head_generation, authority.snapshot_generation
            )));
        }
        self.confirm_existing_lock_visible(&lock.namespace)?;
        Ok(LocalAuthorityFreezeLock {
            repo_id: repo_id.to_string(),
            authority,
            lock,
        })
    }

    pub(crate) fn load_source_blob_bounded_while_frozen(
        &self,
        freeze: &LocalAuthorityFreezeLock,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        freeze.require_repository(repo_id)?;
        validate_source_blob_repo_id(repo_id)?;
        self.load_source_blob_bounded_from_namespace(
            freeze.namespace(),
            digest,
            max_bytes,
            false,
            true,
            true,
        )
    }

    pub(crate) fn with_verified_source_blob_batch_while_frozen(
        &self,
        freeze: &LocalAuthorityFreezeLock,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        freeze.require_repository(repo_id)?;
        validate_source_blob_repo_id(repo_id)?;
        self.with_verified_source_blob_batch_from_namespace(freeze.namespace(), operation)
    }

    fn with_verified_source_blob_batch_from_namespace(
        &self,
        namespace: &LocalRepositoryCapability,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        self.confirm_existing_lock_visible(namespace)?;
        let batch = LocalVerifiedSourceBlobBatch {
            backend: self,
            namespace,
        };
        let operation_result = operation(&batch);
        let identity_result = self.confirm_existing_lock_visible(namespace);
        match identity_result {
            Ok(()) => operation_result,
            Err(error) => Err(error),
        }
    }

    fn load_source_blob_bounded_from_namespace(
        &self,
        namespace: &LocalRepositoryCapability,
        digest: [u8; 32],
        max_bytes: u64,
        create_missing_ancestors: bool,
        confirm_repository_each_read: bool,
        verify_digest_in_reader: bool,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (
                namespace,
                digest,
                max_bytes,
                create_missing_ancestors,
                confirm_repository_each_read,
                verify_digest_in_reader,
            );
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(windows)]
        {
            if confirm_repository_each_read {
                self.confirm_repository_visible(namespace)?;
            }
            let capability = open_windows_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                create_missing_ancestors,
            )?;
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                max_bytes,
                false,
            )?
            else {
                if confirm_repository_each_read {
                    self.confirm_repository_visible(namespace)?;
                }
                return Ok(None);
            };
            if verify_digest_in_reader {
                verify_source_blob_digest(
                    digest,
                    &data.data,
                    &capability.leaf_path.display().to_string(),
                )?;
            }
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            if confirm_repository_each_read {
                self.confirm_repository_visible(namespace)?;
            }
            return Ok(Some(data.data));
        }
        #[cfg(unix)]
        {
            if confirm_repository_each_read {
                self.confirm_repository_visible(namespace)?;
            }
            let capability = open_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                create_missing_ancestors,
                false,
            )?;
            confirm_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_source_file_at(&capability.leaf_dir, &digest_hex, max_bytes)?
            else {
                if confirm_repository_each_read {
                    self.confirm_repository_visible(namespace)?;
                }
                return Ok(None);
            };
            if verify_digest_in_reader {
                verify_source_blob_digest(
                    digest,
                    &data.data,
                    &capability.leaf_path.display().to_string(),
                )?;
            }
            confirm_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            if confirm_repository_each_read {
                self.confirm_repository_visible(namespace)?;
            }
            Ok(Some(data.data))
        }
    }

    fn snapshot_file_name(generation: Generation) -> String {
        format!("{generation:020}.kndb")
    }

    fn snapshot_digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[cfg(test)]
    fn atomic_write(path: &Path, data: &[u8]) -> Result<(), KinDbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create test directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        mmap::atomic_write_bytes_no_magic(path, data)
    }

    fn file_digest(surface: &LocalSurfaceCapability, leaf: &Path) -> Result<String, KinDbError> {
        LocalSurfaceCapability::require_leaf(leaf)?;
        let display = surface.display(leaf);
        let mut file = mmap::open_regular_nofollow_at(
            &surface.directory,
            leaf,
            &surface.display_path,
            "digest source",
        )?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read {} for digest verification: {error}",
                    display.display()
                ))
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn validate_delta_identities(record: &LocalAuthorityRecord) -> Result<(), KinDbError> {
        let expected_count = record
            .head_generation
            .checked_sub(record.snapshot_generation)
            .ok_or_else(|| {
                KinDbError::StorageError("local authority generation range underflow".to_string())
            })?;
        let expected_count = usize::try_from(expected_count).map_err(|_| {
            KinDbError::StorageError(
                "local authority delta range does not fit in memory".to_string(),
            )
        })?;
        if record.acknowledged_deltas.len() != expected_count {
            return Err(KinDbError::StorageError(format!(
                "local authority generation range {}..={} declares {} acknowledged delta identities; expected {expected_count}",
                record.snapshot_generation.saturating_add(1),
                record.head_generation,
                record.acknowledged_deltas.len()
            )));
        }
        for (offset, identity) in record.acknowledged_deltas.iter().enumerate() {
            let offset = Generation::try_from(offset).map_err(|_| {
                KinDbError::StorageError("local authority delta offset overflow".to_string())
            })?;
            let expected_generation = record
                .snapshot_generation
                .checked_add(offset)
                .and_then(|generation| generation.checked_add(1))
                .ok_or_else(|| {
                    KinDbError::StorageError(
                        "local authority delta generation overflow".to_string(),
                    )
                })?;
            if identity.generation != expected_generation {
                return Err(KinDbError::StorageError(format!(
                    "local authority delta identity {} names generation {}, expected {expected_generation}",
                    offset, identity.generation
                )));
            }
            if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
                return Err(KinDbError::StorageError(format!(
                    "local authority delta generation {} has an invalid SHA-256 digest",
                    identity.generation
                )));
            }
        }
        let mut bound_generations: std::collections::HashSet<Generation> = record
            .acknowledged_deltas
            .iter()
            .map(|identity| identity.generation)
            .collect();
        for identity in &record.retired_deltas {
            if identity.generation == GENERATION_INIT {
                return Err(KinDbError::StorageError(
                    "local authority has a retired delta at reserved generation 0".to_string(),
                ));
            }
            if identity.generation >= record.snapshot_generation {
                return Err(KinDbError::StorageError(format!(
                    "local authority retired delta generation {} is not older than snapshot generation {}",
                    identity.generation, record.snapshot_generation
                )));
            }
            if !bound_generations.insert(identity.generation) {
                return Err(KinDbError::StorageError(format!(
                    "local authority binds delta generation {} more than once",
                    identity.generation
                )));
            }
            if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
                return Err(KinDbError::StorageError(format!(
                    "local authority retired delta generation {} has an invalid SHA-256 digest",
                    identity.generation
                )));
            }
        }
        Ok(())
    }

    fn validate_acknowledged_deltas_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let repo_id = &namespace.repo_id;
        let deltas = namespace.surface(Self::deltas_surface_name(), false)?;
        for (index, identity) in record.acknowledged_deltas.iter().enumerate() {
            let leaf = Self::delta_leaf(identity.generation);
            let exists = match deltas.as_ref() {
                Some(surface) => surface.exists(&leaf)?,
                None => false,
            };
            if !exists {
                let mut next_present = None;
                for next in &record.acknowledged_deltas[index + 1..] {
                    let next_leaf = Self::delta_leaf(next.generation);
                    let next_exists = match deltas.as_ref() {
                        Some(surface) => surface.exists(&next_leaf)?,
                        None => false,
                    };
                    if next_exists {
                        next_present = Some(next.generation);
                        break;
                    }
                }
                if let Some(next_generation) = next_present {
                    return Err(KinDbError::StorageError(format!(
                        "repo {repo_id} delta chain is incomplete: expected generation {}, found {}",
                        identity.generation, next_generation
                    )));
                }
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} delta chain ended at generation {}, acknowledged head is {}",
                    identity.generation - 1,
                    record.head_generation
                )));
            }
            let surface = deltas
                .as_ref()
                .expect("an acknowledged delta was confirmed present");
            let digest = Self::file_digest(surface, &leaf).map_err(|error| {
                KinDbError::StorageError(format!(
                    "acknowledged delta generation {} for repo {repo_id} is unavailable: {error}",
                    identity.generation
                ))
            })?;
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "acknowledged delta digest mismatch for repo {repo_id} generation {}: expected {}, found {digest}; committed journal bytes changed",
                    identity.generation, identity.sha256
                )));
            }
        }
        if let Some(deltas) = deltas {
            namespace.confirm_surface_visible(&deltas)?;
        }
        Ok(())
    }

    fn validate_loaded_acknowledged_deltas(
        repo_id: &str,
        record: &LocalAuthorityRecord,
        deltas: &[(Vec<u8>, Generation)],
    ) -> Result<(), KinDbError> {
        for identity in &record.acknowledged_deltas {
            let Some((bytes, _)) = deltas
                .iter()
                .find(|(_, generation)| *generation == identity.generation)
            else {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} delta chain ended before acknowledged generation {}",
                    identity.generation
                )));
            };
            let digest = Self::snapshot_digest(bytes);
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "acknowledged delta digest mismatch for repo {repo_id} generation {} while loading recovery bytes: expected {}, found {digest}; committed journal bytes changed",
                    identity.generation, identity.sha256
                )));
            }
        }
        Ok(())
    }

    fn validate_loaded_residual_deltas(
        repo_id: &str,
        record: &LocalAuthorityRecord,
        deltas: &[PersistedDelta],
    ) -> Result<(), KinDbError> {
        for (bytes, generation) in deltas {
            if let Some(identity) = record
                .acknowledged_deltas
                .iter()
                .find(|identity| identity.generation == *generation)
            {
                let digest = Self::snapshot_digest(bytes);
                if digest != identity.sha256 {
                    return Err(KinDbError::StorageError(format!(
                        "acknowledged delta digest mismatch for repo {repo_id} generation {generation} while loading recovery bytes: expected {}, found {digest}",
                        identity.sha256
                    )));
                }
                continue;
            }
            if let Some(identity) = record
                .retired_deltas
                .iter()
                .find(|identity| identity.generation == *generation)
            {
                let digest = Self::snapshot_digest(bytes);
                if digest != identity.sha256 {
                    return Err(KinDbError::StorageError(format!(
                        "retired delta digest mismatch for repo {repo_id} generation {generation}: expected {}, found {digest}; retired bytes changed after full promotion",
                        identity.sha256
                    )));
                }
                continue;
            }
            if *generation <= record.head_generation {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} authority head {} has an unbound residual delta at generation {generation}; recovery is fail-closed",
                    record.head_generation
                )));
            }
        }
        Ok(())
    }

    fn validate_residual_deltas_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let deltas = self.load_deltas_since_unlocked(namespace, GENERATION_INIT)?;
        Self::validate_loaded_residual_deltas(&namespace.repo_id, record, &deltas)
    }

    fn finalize_retired_quarantines_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let repo_id = &namespace.repo_id;
        let Some(deltas) = namespace.surface(Self::deltas_surface_name(), false)? else {
            return Ok(());
        };
        let quarantined = load_quarantined_deltas_at(&deltas.directory, &deltas.display_path)?;
        for artifact in &quarantined {
            let Some(identity) = record
                .retired_deltas
                .iter()
                .find(|identity| identity.generation == artifact.generation)
            else {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has an unbound quarantined delta at generation {}; recovery is fail-closed",
                    artifact.generation
                )));
            };
            if identity.sha256 != artifact.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} quarantined delta identity mismatch at generation {}: authority binds {}, quarantine binds {}; recovery is fail-closed",
                    artifact.generation, identity.sha256, artifact.sha256
                )));
            }
        }
        for artifact in &quarantined {
            delete_quarantined_delta_exact_at(&deltas.directory, artifact, &deltas.display_path)?;
        }
        namespace.confirm_surface_visible(&deltas)?;
        Ok(())
    }

    fn reject_unbound_staged_deltas_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<(), KinDbError> {
        let repo_id = &namespace.repo_id;
        let head_generation = record.map_or(GENERATION_INIT, |record| record.head_generation);
        let deltas = self.load_deltas_since_unlocked(namespace, GENERATION_INIT)?;
        if let Some((_, generation)) = deltas
            .iter()
            .find(|(_, generation)| *generation > head_generation)
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has a staged unacknowledged delta at generation {generation} above authority head {head_generation}; full promotion was not committed and may be retried after the staged writer resolves"
            )));
        }
        Ok(())
    }

    fn capture_delta_identities_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        identities: &[LocalDeltaIdentity],
        required: bool,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let repo_id = &namespace.repo_id;
        let deltas = namespace.surface(Self::deltas_surface_name(), false)?;
        let mut captured = Vec::new();
        for identity in identities {
            let leaf = Self::delta_leaf(identity.generation);
            let exists = match deltas.as_ref() {
                Some(surface) => surface.exists(&leaf)?,
                None => false,
            };
            let bytes = match exists {
                true => deltas
                    .as_ref()
                    .expect("a present delta has a retained surface")
                    .read_regular(&leaf, "authority-bound delta")?,
                false if !required => continue,
                false => {
                    return Err(KinDbError::StorageError(format!(
                        "failed to capture authority-bound delta {} for repo {repo_id}: object is missing",
                        namespace
                            .display_path
                            .join(Self::deltas_surface_name())
                            .join(&leaf)
                            .display()
                    )))
                }
            };
            let digest = Self::snapshot_digest(&bytes);
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "authority-bound delta digest mismatch for repo {repo_id} generation {} before full promotion: expected {}, found {digest}",
                    identity.generation, identity.sha256
                )));
            }
            captured.push((bytes, identity.generation));
        }
        if let Some(deltas) = deltas {
            namespace.confirm_surface_visible(&deltas)?;
        }
        Ok(captured)
    }

    fn capture_authority_bound_deltas_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let Some(record) = record else {
            return Ok(Vec::new());
        };
        let mut captured =
            self.capture_delta_identities_unlocked(namespace, &record.acknowledged_deltas, true)?;
        captured.extend(self.capture_delta_identities_unlocked(
            namespace,
            &record.retired_deltas,
            false,
        )?);
        Ok(captured)
    }

    fn delta_identities(captured: &[PersistedDelta]) -> Vec<LocalDeltaIdentity> {
        captured
            .iter()
            .map(|(bytes, generation)| LocalDeltaIdentity {
                generation: *generation,
                sha256: Self::snapshot_digest(bytes),
            })
            .collect()
    }

    fn clear_exact_captured_deltas_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        captured: &[PersistedDelta],
    ) -> bool {
        let repo_id = &namespace.repo_id;
        let deltas = match namespace.surface(Self::deltas_surface_name(), false) {
            Ok(Some(deltas)) => deltas,
            Ok(None) if captured.is_empty() => {
                return self
                    .load_deltas_since_unlocked(namespace, GENERATION_INIT)
                    .is_ok_and(|remaining| remaining.is_empty())
            }
            Ok(None) => {
                tracing::warn!(
                    repo_id,
                    "journal promotion committed but the retained delta surface is missing"
                );
                return false;
            }
            Err(error) => {
                tracing::warn!(repo_id, error = %error, "journal promotion committed but the retained delta surface is unavailable");
                return false;
            }
        };
        let mut complete = true;
        for (captured_bytes, generation) in captured {
            let leaf = Self::delta_leaf(*generation);
            let path = deltas.display(&leaf);
            let captured_sha256 = Self::snapshot_digest(captured_bytes);
            let quarantine_leaf = quarantine_delta_path(&leaf, *generation, &captured_sha256);
            let quarantine_path = deltas.display(&quarantine_leaf);
            match deltas
                .directory
                .rename(&leaf, &deltas.directory, &quarantine_leaf)
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %path.display(), error = %error, "journal promotion committed; could not quarantine captured delta for cleanup");
                    continue;
                }
            }
            if let Err(error) = deltas.sync(&quarantine_leaf) {
                complete = false;
                tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; quarantined delta rename could not be made durable");
                continue;
            }
            #[cfg(test)]
            if let Some(hook) = self.cleanup_after_quarantine_hook.lock().take() {
                hook();
            }
            match quarantined_file_matches_at(
                &deltas.directory,
                &quarantine_leaf,
                &deltas.display_path,
                &captured_sha256,
                captured_bytes.len() as u64,
            ) {
                Ok(true) => match deltas.directory.remove_file(&quarantine_leaf) {
                    Ok(()) => {
                        if let Err(error) = deltas.sync(&quarantine_leaf) {
                            complete = false;
                            tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; could not fsync captured-delta cleanup");
                        }
                    }
                    Err(error) => {
                        complete = false;
                        tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; deferred quarantined captured-delta cleanup");
                    }
                },
                Ok(false) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %path.display(), quarantine = %quarantine_path.display(), "journal promotion preserved a delta that changed after capture");
                }
                Err(error) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; could not verify quarantined captured delta for cleanup");
                }
            }
        }
        if let Err(error) = namespace.confirm_surface_visible(&deltas) {
            tracing::warn!(repo_id, error = %error, "journal promotion committed but the delta surface changed during cleanup");
            complete = false;
        }
        match self.load_deltas_since_unlocked(namespace, GENERATION_INIT) {
            Ok(remaining) if remaining.is_empty() => complete,
            Ok(remaining) => {
                tracing::warn!(repo_id, remaining = remaining.len(), "journal promotion committed with residual journal artifacts; recovery remains fail-closed");
                false
            }
            Err(error) => {
                tracing::warn!(repo_id, error = %error, "journal promotion committed; could not verify journal drain");
                false
            }
        }
    }

    fn read_authority_record_raw_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let relative = Self::authority_relative_path();
        let path = namespace.display(relative);
        if !namespace.exists(relative)? {
            return Ok(None);
        }
        mmap::confirm_installed_write_at(&namespace.directory, relative, &namespace.display_path)?;
        let bytes = namespace.read_regular_bounded(relative, "local authority", 1024 * 1024)?;
        Self::decode_authority_record(&namespace.repo_id, &path, &bytes).map(Some)
    }

    fn decode_authority_record(
        repo_id: &str,
        path: &Path,
        bytes: &[u8],
    ) -> Result<LocalAuthorityRecord, KinDbError> {
        let record: LocalAuthorityRecord = serde_json::from_slice(bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "invalid local authority {}: {error}",
                path.display()
            ))
        })?;
        if record.version != LOCAL_AUTHORITY_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported local authority version {} in {}",
                record.version,
                path.display()
            )));
        }
        if record.snapshot_generation > record.head_generation {
            return Err(KinDbError::StorageError(format!(
                "local authority for repo {repo_id} has snapshot generation {} above head {}",
                record.snapshot_generation, record.head_generation
            )));
        }
        let expected_file = Self::snapshot_file_name(record.snapshot_generation);
        if record.snapshot_file != expected_file {
            return Err(KinDbError::StorageError(format!(
                "local authority for repo {repo_id} references noncanonical snapshot file {}",
                record.snapshot_file
            )));
        }
        Self::validate_delta_identities(&record)?;
        Ok(record)
    }

    fn read_authority_record_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let record = self.read_authority_record_raw_unlocked(namespace)?;
        let Some(record) = record else {
            return Ok(None);
        };
        self.validate_acknowledged_deltas_unlocked(namespace, &record)?;
        self.validate_residual_deltas_unlocked(namespace, &record)?;
        Ok(Some(record))
    }

    fn read_authoritative_snapshot_bytes_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<Vec<u8>, KinDbError> {
        let repo_id = &namespace.repo_id;
        let snapshots = namespace
            .surface(Self::snapshots_surface_name(), false)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "authoritative snapshot surface is missing for repo {repo_id}"
                ))
            })?;
        let leaf = Path::new(&record.snapshot_file);
        let snapshot_bytes = snapshots.read_regular(leaf, "authoritative snapshot")?;
        let digest = Self::snapshot_digest(&snapshot_bytes);
        if digest != record.snapshot_sha256 {
            return Err(KinDbError::StorageError(format!(
                "authoritative snapshot digest mismatch for repo {repo_id}: expected {}, found {digest}",
                record.snapshot_sha256
            )));
        }
        // Payload decoding and structural admission belong to
        // `load_recovered_snapshot`, which is the shared recovery boundary for
        // every backend. Decoding here would throw the validated value away
        // and make local recovery deserialize and validate the same exact
        // content-addressed bytes twice before repository open can use them.
        namespace.confirm_surface_visible(&snapshots)?;
        Ok(snapshot_bytes)
    }

    fn clear_superseded_snapshots_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        keep_generation: Generation,
    ) -> Result<(), KinDbError> {
        let Some(snapshots) = namespace.surface(Self::snapshots_surface_name(), false)? else {
            return Ok(());
        };
        for entry in snapshots.directory.entries().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local snapshot directory {}: {error}",
                snapshots.display_path.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read local snapshot entry in {}: {error}",
                    snapshots.display_path.display()
                ))
            })?;
            let file_name = entry.file_name();
            let leaf = PathBuf::from(&file_name);
            let display = snapshots.display(&leaf);
            let Some(generation) = Path::new(&file_name)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<Generation>().ok())
            else {
                continue;
            };
            if Path::new(&file_name)
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("kndb")
                || Path::new(&file_name)
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(Self::snapshot_file_name(generation).as_str())
                || generation >= keep_generation
            {
                continue;
            }
            snapshots.directory.remove_file(&leaf).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to remove superseded local snapshot {}: {error}",
                    display.display()
                ))
            })?;
        }
        #[cfg(test)]
        if let Some(hook) = self.snapshot_cleanup_before_confirmation_hook.lock().take() {
            hook();
        }
        snapshots.sync(Path::new(&Self::snapshot_file_name(keep_generation)))?;
        namespace.confirm_surface_visible(&snapshots)?;
        Ok(())
    }

    fn load_authority_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        let repo_id = &namespace.repo_id;
        let Some(record) = self.read_authority_record_unlocked(namespace)? else {
            let quarantines = match namespace.surface(Self::deltas_surface_name(), false)? {
                Some(deltas) => {
                    let quarantines =
                        load_quarantined_deltas_at(&deltas.directory, &deltas.display_path)?;
                    namespace.confirm_surface_visible(&deltas)?;
                    quarantines
                }
                None => Vec::new(),
            };
            if !quarantines.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has {} quarantined deltas but no current snapshot authority; recovery is fail-closed",
                    quarantines.len()
                )));
            }
            let deltas = self.load_deltas_since_unlocked(namespace, GENERATION_INIT)?;
            if !deltas.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has {} deltas but no current snapshot authority; recovery is fail-closed",
                    deltas.len()
                )));
            }
            return Ok(None);
        };

        let snapshot_bytes = self.read_authoritative_snapshot_bytes_unlocked(namespace, &record)?;
        let snapshots = namespace
            .surface(Self::snapshots_surface_name(), false)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "authoritative snapshot surface is missing for repo {repo_id}"
                ))
            })?;
        // Cleanup is downstream of both authority-directory durability and
        // exact authoritative payload verification.
        self.finalize_retired_quarantines_unlocked(namespace, &record)?;
        if let Err(error) =
            self.clear_superseded_snapshots_unlocked(namespace, record.snapshot_generation)
        {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        namespace.confirm_surface_visible(&snapshots)?;
        self.confirm_repository_visible(namespace)?;
        Ok(Some(SnapshotAuthority {
            snapshot_bytes,
            snapshot_generation: record.snapshot_generation,
            head_generation: record.head_generation,
            history_validation: record.history_validation,
        }))
    }

    fn write_authority_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            KinDbError::StorageError(format!("failed to encode local authority: {error}"))
        })?;
        let relative = Self::authority_relative_path();
        let path = namespace.display(relative);
        match mmap::atomic_write_bytes_no_magic_outcome_at(
            &namespace.directory,
            relative,
            &namespace.display_path,
            &bytes,
        )? {
            AtomicWriteOutcome::Durable => Ok(()),
            AtomicWriteOutcome::InstalledButUnconfirmed(error) => {
                Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                    "local authority {} was installed but its durability or exact post-install verification is unconfirmed: {error}",
                    path.display()
                )))
            }
        }
    }

    fn load_deltas_since_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let Some(deltas) = namespace.surface(Self::deltas_surface_name(), false)? else {
            return Ok(Vec::new());
        };

        let mut entries: Vec<(Generation, PathBuf)> = Vec::new();
        for entry in deltas.directory.entries().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read deltas directory {}: {error}",
                deltas.display_path.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!("failed to read delta entry: {error}"))
            })?;
            let file_name = entry.file_name();
            let leaf = PathBuf::from(&file_name);
            let display = deltas.display(&leaf);
            if is_quarantine_delta_name(Path::new(&file_name)) {
                continue;
            }
            if Path::new(&file_name)
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("kndd")
            {
                continue;
            }
            let stem = Path::new(&file_name)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "delta authority {} has a non-UTF8 generation",
                        display.display()
                    ))
                })?;
            let generation = stem.parse::<Generation>().map_err(|error| {
                KinDbError::StorageError(format!(
                    "delta authority {} has an invalid generation: {error}",
                    display.display()
                ))
            })?;
            let canonical_name = format!("{generation:020}.kndd");
            if generation == GENERATION_INIT
                || Path::new(&file_name)
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(canonical_name.as_str())
            {
                return Err(KinDbError::StorageError(format!(
                    "delta authority {} has a reserved or noncanonical generation",
                    display.display()
                )));
            }
            if generation > since_gen {
                entries.push((generation, leaf));
            }
        }
        entries.sort_by_key(|(generation, _)| *generation);

        let loaded: Result<Vec<_>, _> = entries
            .into_iter()
            .map(|(generation, leaf)| {
                deltas
                    .read_regular(&leaf, "local delta")
                    .map(|bytes| (bytes, generation))
            })
            .collect();
        let loaded = loaded?;
        namespace.confirm_surface_visible(&deltas)?;
        Ok(loaded)
    }

    /// Persist one complete snapshot while the caller holds this repository's
    /// exclusive local authority lock.
    ///
    /// Keeping lock acquisition outside this helper lets the ordinary storage
    /// API drop the lock on return while the repository-authority API can
    /// return the exact same lock as a held successor freeze.
    fn save_snapshot_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        data: &[u8],
        expected_gen: Generation,
        history_validator_version: Option<u32>,
    ) -> Result<Generation, KinDbError> {
        let repo_id = &namespace.repo_id;
        let current = self.load_authority_unlocked(namespace)?;
        let current_record = self.read_authority_record_raw_unlocked(namespace)?;
        match (current.as_ref(), current_record.as_ref()) {
            (Some(authority), Some(record))
                if authority.snapshot_generation == record.snapshot_generation
                    && authority.head_generation == record.head_generation
                    && Self::snapshot_digest(&authority.snapshot_bytes)
                        == record.snapshot_sha256 => {}
            (None, None) => {}
            _ => {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} snapshot authority changed while preparing full promotion"
                )));
            }
        }
        let current_gen = current
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.head_generation);
        let requested_digest = Self::snapshot_digest(data);
        if let Some(record) = current_record.as_ref() {
            let retry_generation = expected_gen.checked_add(1);
            if retry_generation == Some(record.head_generation)
                && record.snapshot_generation == record.head_generation
                && record.snapshot_sha256 == requested_digest
                && current.as_ref().is_some_and(|authority| {
                    authority.snapshot_generation == record.snapshot_generation
                        && authority.head_generation == record.head_generation
                        && Self::snapshot_digest(&authority.snapshot_bytes) == requested_digest
                })
            {
                // Exact serialized-content retries are idempotent after an
                // authority rename whose directory sync result was uncertain.
                // Re-sync the authority directory and re-confirm both retained
                // namespace epochs before accepting.
                #[cfg(test)]
                if let Some(hook) = self.snapshot_retry_before_confirmation_hook.lock().take() {
                    hook();
                }
                let snapshots = namespace
                    .surface(Self::snapshots_surface_name(), false)
                    .map_err(|error| {
                        KinDbError::SnapshotPersistenceIndeterminate(format!(
                            "repo {repo_id} exact snapshot retry refers to an already-committed generation, but its retained snapshot surface could not be confirmed: {error}"
                        ))
                    })?
                    .ok_or_else(|| {
                        KinDbError::SnapshotPersistenceIndeterminate(format!(
                            "repo {repo_id} exact snapshot retry refers to an already-committed generation, but its retained snapshot surface is missing"
                        ))
                    })?;
                namespace
                    .sync_parent(Self::authority_relative_path())
                    .map_err(|error| {
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "local authority {} is installed but durability remains unconfirmed: {error}",
                        namespace.display(Self::authority_relative_path()).display()
                    ))
                })?;
                if let Err(error) = namespace
                    .confirm_surface_visible(&snapshots)
                    .and_then(|()| self.confirm_repository_visible(namespace))
                {
                    return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "repo {repo_id} exact snapshot retry refers to committed generation {}, but final namespace confirmation failed: {error}",
                        record.head_generation
                    )));
                }
                return Ok(record.head_generation);
            }
        }
        self.reject_unbound_staged_deltas_unlocked(namespace, current_record.as_ref())?;
        if current_gen != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_gen} \
                 (another writer committed since last load)"
            )));
        }

        // Validate the bytes without re-serializing — from_bytes proves the
        // data round-trips, then we write the *original* bytes to disk.
        let _snapshot = GraphSnapshot::from_bytes(data)?;
        let new_gen = checked_next_generation(current_gen, "local snapshot")?;
        let snapshots = namespace
            .surface(Self::snapshots_surface_name(), true)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "snapshot surface disappeared while creating repo {repo_id}"
                ))
            })?;
        let versioned_leaf = Self::versioned_snapshot_leaf(new_gen);
        snapshots.atomic_write(&versioned_leaf, data)?;

        #[cfg(test)]
        if self
            .fail_before_authority_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KinDbError::StorageError(
                "injected crash before local snapshot authority commit".to_string(),
            ));
        }

        #[cfg(test)]
        if let Some(hook) = self.snapshot_before_authority_commit_hook.lock().take() {
            hook();
        }

        let captured_for_cleanup =
            self.capture_authority_bound_deltas_unlocked(namespace, current_record.as_ref())?;
        self.reject_unbound_staged_deltas_unlocked(namespace, current_record.as_ref())?;
        if self.capture_authority_bound_deltas_unlocked(namespace, current_record.as_ref())?
            != captured_for_cleanup
            || self.read_authority_record_raw_unlocked(namespace)? != current_record
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} authority or journal changed during full promotion; authority was not committed"
            )));
        }
        namespace.confirm_surface_visible(&snapshots)?;

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: requested_digest.clone(),
            acknowledged_deltas: Vec::new(),
            retired_deltas: Self::delta_identities(&captured_for_cleanup),
            history_validation: history_validator_version.map(|validator_version| {
                HistoryValidationProof {
                    validator_version,
                    repository_id: repo_id.clone(),
                    generation: new_gen,
                    snapshot_sha256: requested_digest,
                }
            }),
        };
        self.write_authority_unlocked(namespace, &record)?;
        #[cfg(test)]
        if let Some(hook) = self.snapshot_after_authority_commit_hook.lock().take() {
            hook();
        }
        if let Err(error) = self.clear_superseded_snapshots_unlocked(namespace, new_gen) {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        if let Err(error) = namespace
            .confirm_surface_visible(&snapshots)
            .and_then(|()| self.confirm_repository_visible(namespace))
        {
            return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                "repo {repo_id} snapshot authority committed generation {new_gen}, but post-commit namespace confirmation failed: {error}"
            )));
        }
        Ok(new_gen)
    }

    fn save_snapshot_locked(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
        history_validator_version: Option<u32>,
    ) -> Result<Generation, KinDbError> {
        let lock = if expected_gen == GENERATION_INIT {
            self.acquire_lock_for_initialization(repo_id)?
        } else {
            self.acquire_existing_lock(repo_id)?
        };
        self.save_snapshot_unlocked(
            &lock.namespace,
            data,
            expected_gen,
            history_validator_version,
        )
    }

    /// Persist a local full-snapshot CAS and return the same still-held
    /// repository lock that protected its commit point.
    pub(crate) fn save_snapshot_and_freeze(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> Result<(SnapshotCursor, LocalAuthorityFreezeLock), KinDbError> {
        let expected_gen = expected_cursor.backend_generation();
        let lock = if expected_gen == GENERATION_INIT {
            self.acquire_lock_for_initialization(repo_id)?
        } else {
            self.acquire_existing_lock(repo_id)?
        };
        let generation = self.save_snapshot_unlocked(
            &lock.namespace,
            data,
            expected_gen,
            history_validator_version,
        )?;
        let cursor = SnapshotCursor::from_backend_generation(generation);
        let authority = SnapshotAuthority {
            snapshot_bytes: data.to_vec(),
            snapshot_generation: generation,
            head_generation: generation,
            history_validation: history_validator_version.map(|validator_version| {
                HistoryValidationProof {
                    validator_version,
                    repository_id: repo_id.to_string(),
                    generation,
                    snapshot_sha256: hex::encode(Sha256::digest(data)),
                }
            }),
        };
        Ok((
            cursor,
            LocalAuthorityFreezeLock {
                repo_id: repo_id.to_string(),
                authority,
                lock,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_snapshot_before_authority_commit(&self) {
        self.fail_before_authority_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_snapshot_parent_sync_after_install(&self) {
        self.set_snapshot_before_authority_commit_hook(|| {
            // Authority candidate publication and exact candidate claim consume
            // two parent syncs; fail after the destination rename installed it.
            mmap::fail_parent_sync_after(2);
        });
    }

    #[cfg(test)]
    fn fail_next_delta_cleanup(&self) {
        self.fail_delta_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn set_recovery_after_authority_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.recovery_after_authority_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_compaction_before_delta_cleanup_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.compaction_before_delta_cleanup_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_cleanup_after_quarantine_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.cleanup_after_quarantine_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn set_snapshot_before_authority_commit_hook(
        &self,
        hook: impl FnOnce() + Send + 'static,
    ) {
        *self.snapshot_before_authority_commit_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(all(test, unix))]
    fn set_snapshot_after_authority_commit_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.snapshot_after_authority_commit_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(all(test, unix))]
    fn set_snapshot_retry_before_confirmation_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.snapshot_retry_before_confirmation_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(all(test, unix))]
    fn set_snapshot_cleanup_before_confirmation_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.snapshot_cleanup_before_confirmation_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_delta_before_authority_commit_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.delta_before_authority_commit_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(all(test, unix))]
    fn set_overlay_after_write_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.overlay_after_write_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(all(test, unix))]
    fn set_source_blob_after_capability_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.source_blob_after_capability_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_source_blob_before_publish_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.source_blob_before_publish_hook.lock() = Some(Box::new(hook));
    }

    /// Publish one already-validated body inside a held repository lock.
    ///
    /// `durability` decides when this body's directory and acknowledgement
    /// barriers are issued. The body's own pre-link fsync is never deferred,
    /// so a directory entry can never become durable ahead of the bytes it
    /// names and a lost barrier reads the body as absent rather than torn.
    #[cfg(unix)]
    fn publish_source_blob_in_namespace(
        &self,
        namespace: &LocalRepositoryCapability,
        digest: [u8; 32],
        data: &[u8],
        durability: &LocalSourceDurability<'_>,
    ) -> Result<(), KinDbError> {
        if durability.confirms_repository_inline() {
            self.confirm_repository_visible(namespace)?;
        }
        let digest_hex = hex::encode(digest);
        let capability = durability.capability(namespace, &digest_hex[..2])?;
        #[cfg(test)]
        if let Some(hook) = self.source_blob_after_capability_hook.lock().take() {
            hook();
        }

        if let Some(existing) =
            read_source_file_at(&capability.leaf_dir, &digest_hex, MAX_SOURCE_BLOB_BYTES)?
        {
            verify_source_blob_digest(
                digest,
                &existing.data,
                &capability.leaf_path.display().to_string(),
            )?;
            if existing.data != data {
                return Err(KinDbError::StorageError(format!(
                    "immutable source blob collision below {}",
                    capability.leaf_path.display()
                )));
            }
            if durability.confirms_namespace_inline() {
                confirm_source_blob_namespace_from_repository(
                    &namespace.directory,
                    &namespace.display_path,
                    digest,
                    &capability,
                )?;
            }
            durability.sync_body(&existing.file, &capability.leaf_path.join(&digest_hex))?;
            durability.sync_leaf(&capability)?;
            if durability.confirms_repository_inline() {
                self.confirm_repository_visible(namespace)?;
            }
            return Ok(());
        }

        #[cfg(test)]
        if let Some(hook) = self.source_blob_before_publish_hook.lock().take() {
            hook();
        }

        // Re-walk without creating anything and compare the directory
        // identity to the pinned handle. A substituted ancestor is rejected
        // before publication; all writes remain relative to the old handle.
        if durability.confirms_namespace_inline() {
            confirm_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
        }

        let _published = publish_source_file_at(
            &capability.leaf_dir,
            &digest_hex,
            data,
            durability.confirms_leaf_inline(),
            durability.body_barrier(),
        )?;
        let installed =
            read_source_file_at(&capability.leaf_dir, &digest_hex, MAX_SOURCE_BLOB_BYTES)?
                .ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "immutable source blob disappeared after publication below {}",
                        capability.leaf_path.display()
                    ))
                })?;
        verify_source_blob_digest(
            digest,
            &installed.data,
            &capability.leaf_path.display().to_string(),
        )?;
        if installed.data != data {
            return Err(KinDbError::StorageError(format!(
                "immutable source blob changed while installing below {}",
                capability.leaf_path.display()
            )));
        }
        // `linkat` may have lost a no-clobber race to an identical object.
        // Confirm the inode actually selected at the target name, then
        // reconfirm its directory entry in file-before-directory order.
        durability.sync_body(&installed.file, &capability.leaf_path.join(&digest_hex))?;
        durability.sync_leaf(&capability)?;
        if durability.confirms_repository_inline() {
            self.confirm_repository_visible(namespace)?;
        }
        Ok(())
    }

    /// Publish one already-validated body inside a held repository lock.
    #[cfg(windows)]
    fn publish_source_blob_in_namespace(
        &self,
        namespace: &LocalRepositoryCapability,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        self.confirm_repository_visible(namespace)?;
        let capability = open_windows_source_blob_capability_from_repository(
            &namespace.directory,
            &namespace.display_path,
            digest,
            true,
        )?;
        #[cfg(test)]
        if let Some(hook) = self.source_blob_after_capability_hook.lock().take() {
            hook();
        }
        confirm_windows_source_blob_namespace_from_repository(
            &namespace.directory,
            &namespace.display_path,
            digest,
            &capability,
        )?;
        let digest_hex = hex::encode(digest);

        if let Some(existing) = read_windows_source_file_at(
            capability.leaf_dir(),
            std::ffi::OsStr::new(&digest_hex),
            MAX_SOURCE_BLOB_BYTES,
            true,
        )? {
            verify_source_blob_digest(
                digest,
                &existing.data,
                &capability.leaf_path.display().to_string(),
            )?;
            if existing.data != data {
                return Err(KinDbError::StorageError(format!(
                    "immutable source blob collision below {}",
                    capability.leaf_path.display()
                )));
            }
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            sync_source_file_for_ack(&existing.file, &capability.leaf_path.join(&digest_hex))?;
            capability.sync_leaf_publication()?;
            self.confirm_repository_visible(namespace)?;
            return Ok(());
        }

        #[cfg(test)]
        if let Some(hook) = self.source_blob_before_publish_hook.lock().take() {
            hook();
        }
        confirm_windows_source_blob_namespace_from_repository(
            &namespace.directory,
            &namespace.display_path,
            digest,
            &capability,
        )?;
        let published_identity = publish_windows_source_file_at(
            capability.leaf_dir(),
            &capability.leaf_path,
            &digest_hex,
            data,
        )?;
        let installed = read_windows_source_file_at(
            capability.leaf_dir(),
            std::ffi::OsStr::new(&digest_hex),
            MAX_SOURCE_BLOB_BYTES,
            true,
        )?
        .ok_or_else(|| {
            KinDbError::StorageError(format!(
                "immutable source blob disappeared after Windows publication below {}",
                capability.leaf_path.display()
            ))
        })?;
        verify_source_blob_digest(
            digest,
            &installed.data,
            &capability.leaf_path.display().to_string(),
        )?;
        if installed.data != data {
            return Err(KinDbError::StorageError(format!(
                "immutable source blob changed while installing below {}",
                capability.leaf_path.display()
            )));
        }
        if let Some(published_identity) = published_identity {
            let installed_identity = windows_source_file_identity(&installed.file)?;
            if installed_identity != published_identity {
                return Err(KinDbError::StorageError(format!(
                    "immutable source blob was replaced after Windows publication below {}",
                    capability.leaf_path.display()
                )));
            }
        }
        confirm_windows_source_blob_namespace_from_repository(
            &namespace.directory,
            &namespace.display_path,
            digest,
            &capability,
        )?;
        sync_source_file_for_ack(&installed.file, &capability.leaf_path.join(&digest_hex))?;
        capability.sync_leaf_publication()?;
        self.confirm_repository_visible(namespace)?;
        Ok(())
    }
}

impl StorageBackend for LocalFileBackend {
    fn supports_incremental_deltas(&self) -> bool {
        true
    }

    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        Ok(self
            .load_snapshot_authority(repo_id)?
            .map(|authority| (authority.snapshot_bytes, authority.snapshot_generation)))
    }

    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        validate_source_blob_write_request(repo_id, digest, data)?;
        #[cfg(unix)]
        prepare_source_trust_root(
            &self.base_path,
            true,
            &self.source_root_confirmed_for_process,
        )?;
        #[cfg(any(unix, windows))]
        let authority_lock = self.acquire_lock_for_initialization(repo_id)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (repo_id, digest, data);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(unix)]
        {
            self.publish_source_blob_in_namespace(
                &authority_lock.namespace,
                digest,
                data,
                &LocalSourceDurability::Immediate,
            )
        }
        #[cfg(windows)]
        {
            self.publish_source_blob_in_namespace(&authority_lock.namespace, digest, data)
        }
    }

    fn with_source_blob_write_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn SourceBlobWriteBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        #[cfg(unix)]
        prepare_source_trust_root(
            &self.base_path,
            true,
            &self.source_root_confirmed_for_process,
        )?;
        #[cfg(any(unix, windows))]
        let authority_lock = self.acquire_lock_for_initialization(repo_id)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (repo_id, operation);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(any(unix, windows))]
        {
            let batch = LocalSourceBlobWriteBatch {
                backend: self,
                namespace: &authority_lock.namespace,
                repo_id,
                #[cfg(unix)]
                deferred: DeferredSourceDurability::default(),
            };
            // A failing session never reports durability, so its outstanding
            // barriers stay unissued and its bodies stay unreachable.
            operation(&batch)?;
            batch.flush()
        }
    }

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.load_source_blob_bounded(repo_id, digest, MAX_SOURCE_BLOB_BYTES)
    }

    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        #[cfg(any(unix, windows))]
        let authority_lock = self.acquire_existing_shared_lock(repo_id)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (repo_id, digest, max_bytes);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(windows)]
        {
            let namespace = &authority_lock.namespace;
            self.confirm_repository_visible(namespace)?;
            let Some(capability) = open_existing_windows_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
            )?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                max_bytes,
                false,
            )?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            self.confirm_repository_visible(namespace)?;
            return Ok(Some(data.data));
        }
        #[cfg(unix)]
        {
            // Preserve the historical read contract (a missing object returns
            // None) while still opening every component capability-relatively.
            let namespace = &authority_lock.namespace;
            self.confirm_repository_visible(namespace)?;
            let Some(capability) = open_existing_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
            )?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            let digest_hex = hex::encode(digest);
            let Some(data) = read_source_file_at(&capability.leaf_dir, &digest_hex, max_bytes)?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            confirm_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            self.confirm_repository_visible(namespace)?;
            Ok(Some(data.data))
        }
    }

    fn with_verified_source_blob_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Err(KinDbError::StorageError(format!(
                "local repository {repo_id} is absent during immutable source batch access"
            )));
        }
        #[cfg(any(unix, windows))]
        let authority_lock = self.acquire_existing_shared_lock(repo_id)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = operation;
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(any(unix, windows))]
        {
            let namespace = &authority_lock.namespace;
            self.with_verified_source_blob_batch_from_namespace(namespace, operation)
        }
    }

    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        #[cfg(any(unix, windows))]
        let authority_lock = self.acquire_existing_shared_lock(repo_id)?;
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (repo_id, digest);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(windows)]
        {
            let namespace = &authority_lock.namespace;
            self.confirm_repository_visible(namespace)?;
            let Some(capability) = open_existing_windows_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
            )?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            let digest_hex = hex::encode(digest);
            let opened = open_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                false,
            )?;
            let byte_len = opened.as_ref().map(|(_, byte_len)| *byte_len);
            confirm_windows_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            self.confirm_repository_visible(namespace)?;
            return Ok(byte_len);
        }
        #[cfg(unix)]
        {
            let namespace = &authority_lock.namespace;
            self.confirm_repository_visible(namespace)?;
            let Some(capability) = open_existing_source_blob_capability_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
            )?
            else {
                self.confirm_repository_visible(namespace)?;
                return Ok(None);
            };
            let digest_hex = hex::encode(digest);
            let byte_len = open_source_file_at(&capability.leaf_dir, &digest_hex)?
                .map(|(_, byte_len)| byte_len);
            confirm_source_blob_namespace_from_repository(
                &namespace.directory,
                &namespace.display_path,
                digest,
                &capability,
            )?;
            self.confirm_repository_visible(namespace)?;
            Ok(byte_len)
        }
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        // Exclusive despite the name: `load_authority_unlocked` finalizes
        // retired quarantines, which deletes quarantined delta artifacts, and
        // clears superseded snapshots. An authority load is a recovery step,
        // not a read.
        let lock = self.acquire_existing_lock(repo_id)?;
        let authority = self.load_authority_unlocked(&lock.namespace)?;
        self.confirm_repository_visible(&lock.namespace)?;
        Ok(authority)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok((None, Vec::new()));
        }
        // Exclusive: this finalizes retired quarantines directly as well as
        // through the authority load.
        let lock = self.acquire_existing_lock(repo_id)?;
        let authority = self.load_authority_unlocked(&lock.namespace)?;
        let authority_record = self.read_authority_record_raw_unlocked(&lock.namespace)?;
        match (authority.as_ref(), authority_record.as_ref()) {
            (Some(authority), Some(record))
                if authority.snapshot_generation == record.snapshot_generation
                    && authority.head_generation == record.head_generation
                    && Self::snapshot_digest(&authority.snapshot_bytes)
                        == record.snapshot_sha256 => {}
            (None, None) => {}
            _ => {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} snapshot authority changed while loading recovery state"
                )));
            }
        }
        #[cfg(test)]
        if let Some(hook) = self.recovery_after_authority_hook.lock().take() {
            hook();
        }
        if let Some(record) = authority_record.as_ref() {
            self.finalize_retired_quarantines_unlocked(&lock.namespace, record)?;
        }
        let all_deltas = self.load_deltas_since_unlocked(&lock.namespace, GENERATION_INIT)?;
        if let Some(record) = authority_record.as_ref() {
            Self::validate_loaded_residual_deltas(repo_id, record, &all_deltas)?;
            Self::validate_loaded_acknowledged_deltas(repo_id, record, &all_deltas)?;
        }
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = all_deltas
            .into_iter()
            .filter(|(_, generation)| *generation > since)
            .collect();
        self.confirm_repository_visible(&lock.namespace)?;
        Ok((authority, deltas))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        self.save_snapshot_locked(repo_id, data, expected_gen, None)
    }

    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        self.save_snapshot_validated(repo_id, data, expected_cursor, None)
    }

    fn save_snapshot_validated(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        match self.save_snapshot_locked(
            repo_id,
            data,
            expected_cursor.backend_generation(),
            history_validator_version,
        ) {
            Ok(generation) => SnapshotSaveOutcome::Committed {
                cursor: SnapshotCursor::from_backend_generation(generation),
            },
            Err(error @ KinDbError::SnapshotPersistenceIndeterminate(_)) => {
                SnapshotSaveOutcome::Indeterminate(error)
            }
            Err(error) => SnapshotSaveOutcome::NotCommitted(error),
        }
    }

    fn record_history_validation(
        &self,
        repo_id: &str,
        generation: Generation,
        snapshot_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError> {
        let lock = self.acquire_existing_lock(repo_id)?;
        let namespace = &lock.namespace;
        let Some(mut record) = self.read_authority_record_raw_unlocked(namespace)? else {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no authority record to bind a history validation to"
            )));
        };
        // Bind only to the exact durable state that was validated. Anything
        // else means the repository moved underneath the validator and the
        // record would vouch for bytes nobody checked.
        if record.snapshot_generation != generation
            || record.head_generation != generation
            || record.snapshot_sha256 != snapshot_sha256
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} authority moved to generation {} while binding a history validation for generation {generation}",
                record.head_generation
            )));
        }
        let proof = HistoryValidationProof {
            validator_version,
            repository_id: repo_id.to_string(),
            generation,
            snapshot_sha256: snapshot_sha256.to_string(),
        };
        if record.history_validation.as_ref() == Some(&proof) {
            return Ok(true);
        }
        record.history_validation = Some(proof);
        self.write_authority_unlocked(namespace, &record)?;
        self.confirm_repository_visible(namespace)?;
        Ok(true)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let lock = self.acquire_existing_lock(repo_id)?;
        let namespace = &lock.namespace;
        let _ = self.load_authority_unlocked(namespace)?;
        let Some(mut record) = self.read_authority_record_unlocked(namespace)? else {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no atomic local snapshot authority; persist a full snapshot before deltas"
            )));
        };
        let current_gen = record.head_generation;
        let requested_digest = Self::snapshot_digest(delta_data);
        if base_gen.checked_add(1) == Some(current_gen)
            && record.acknowledged_deltas.last().is_some_and(|identity| {
                identity.generation == current_gen && identity.sha256 == requested_digest
            })
        {
            let deltas = namespace
                .surface(Self::deltas_surface_name(), false)
                .map_err(|error| {
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "repo {repo_id} exact delta retry refers to committed generation {current_gen}, but its retained delta surface could not be confirmed: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "repo {repo_id} acknowledged committed delta {current_gen} but its retained surface is missing"
                    ))
                })?;
            let installed = deltas
                .read_regular(
                    &Self::delta_leaf(current_gen),
                    "idempotent local delta retry",
                )
                .map_err(|error| {
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "repo {repo_id} committed delta {current_gen} could not be verified for an exact retry: {error}"
                    ))
                })?;
            if installed == delta_data {
                namespace
                    .sync_parent(Self::authority_relative_path())
                    .map_err(|error| {
                        KinDbError::SnapshotPersistenceIndeterminate(format!(
                            "repo {repo_id} committed delta {current_gen} is installed but authority durability remains unconfirmed: {error}"
                        ))
                    })?;
                if let Err(error) = namespace
                    .confirm_surface_visible(&deltas)
                    .and_then(|()| self.confirm_repository_visible(namespace))
                {
                    return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "repo {repo_id} exact delta retry refers to committed generation {current_gen}, but final namespace confirmation failed: {error}"
                    )));
                }
                return Ok(current_gen);
            }
        }
        if current_gen != base_gen {
            return Err(KinDbError::StorageError(format!(
                "delta base generation mismatch for repo {repo_id}: expected {base_gen}, found {current_gen}"
            )));
        }

        let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(delta_data)?;
        if delta.base_generation != base_gen {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta payload declares base {}, expected {base_gen}",
                delta.base_generation
            )));
        }
        let new_gen = checked_next_generation(current_gen, "local delta")?;
        let deltas = namespace
            .surface(Self::deltas_surface_name(), true)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "delta surface disappeared while writing repo {repo_id}"
                ))
            })?;
        let delta_leaf = Self::delta_leaf(new_gen);
        deltas.atomic_write(&delta_leaf, delta_data)?;
        #[cfg(test)]
        if let Some(hook) = self.delta_before_authority_commit_hook.lock().take() {
            hook();
        }
        record.version = LOCAL_AUTHORITY_VERSION;
        // Authority now advances past the snapshot the validation record was
        // bound to, so that record no longer describes this repository.
        record.history_validation = None;
        record
            .retired_deltas
            .retain(|identity| identity.generation != new_gen);
        record.acknowledged_deltas.push(LocalDeltaIdentity {
            generation: new_gen,
            sha256: requested_digest,
        });
        record.head_generation = new_gen;
        namespace.confirm_surface_visible(&deltas)?;
        self.write_authority_unlocked(namespace, &record)?;
        if let Err(error) = namespace
            .confirm_surface_visible(&deltas)
            .and_then(|()| self.confirm_repository_visible(namespace))
        {
            return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                "repo {repo_id} delta authority committed generation {new_gen}, but post-commit namespace confirmation failed: {error}"
            )));
        }
        Ok(new_gen)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(Vec::new());
        }
        let lock = self.acquire_existing_lock(repo_id)?;
        let _ = self.load_authority_unlocked(&lock.namespace)?;
        let deltas = self.load_deltas_since_unlocked(&lock.namespace, since_gen)?;
        self.confirm_repository_visible(&lock.namespace)?;
        Ok(deltas)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(());
        }
        let lock = self.acquire_existing_lock(repo_id)?;
        let namespace = &lock.namespace;
        let _ = self.load_authority_unlocked(namespace)?;
        #[cfg(test)]
        if let Some(hook) = self.compaction_before_delta_cleanup_hook.lock().take() {
            hook();
        }
        let record = self.read_authority_record_unlocked(namespace)?;
        let Some(record) = record else {
            if self
                .load_deltas_since_unlocked(namespace, GENERATION_INIT)?
                .is_empty()
            {
                return Ok(());
            }
            return Err(KinDbError::StorageError(format!(
                "refusing to clear unbound deltas for repo {repo_id} without atomic authority"
            )));
        };
        if record.snapshot_generation != record.head_generation {
            return Err(KinDbError::StorageError(format!(
                "refusing to clear authoritative deltas for repo {repo_id}: snapshot generation {}, head {}",
                record.snapshot_generation, record.head_generation
            )));
        }
        #[cfg(test)]
        if self
            .fail_delta_cleanup
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KinDbError::StorageError(
                "injected local delta cleanup failure".to_string(),
            ));
        }
        let captured =
            self.capture_delta_identities_unlocked(namespace, &record.retired_deltas, false)?;
        if !self.clear_exact_captured_deltas_unlocked(namespace, &captured) {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta cleanup left residual journal artifacts; recovery remains fail-closed"
            )));
        }
        self.confirm_repository_visible(namespace)?;
        Ok(())
    }

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        let leaf = Self::overlay_leaf(session_id)?;
        let lock = self.acquire_existing_lock(repo_id)?;
        let overlays = lock
            .namespace
            .surface(Self::overlays_surface_name(), true)?
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "overlay surface disappeared while writing repo {repo_id}"
                ))
            })?;
        overlays.atomic_write(&leaf, data)?;
        #[cfg(test)]
        if let Some(hook) = self.overlay_after_write_hook.lock().take() {
            hook();
        }
        lock.namespace.confirm_surface_visible(&overlays)?;
        self.confirm_repository_visible(&lock.namespace)
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        let leaf = Self::overlay_leaf(session_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        let lock = self.acquire_existing_lock(repo_id)?;
        let Some(overlays) = lock
            .namespace
            .surface(Self::overlays_surface_name(), false)?
        else {
            self.confirm_repository_visible(&lock.namespace)?;
            return Ok(None);
        };
        if !overlays.exists(&leaf)? {
            lock.namespace.confirm_surface_visible(&overlays)?;
            self.confirm_repository_visible(&lock.namespace)?;
            return Ok(None);
        }
        let data = overlays.read_regular(&leaf, "local overlay")?;
        lock.namespace.confirm_surface_visible(&overlays)?;
        self.confirm_repository_visible(&lock.namespace)?;
        Ok(Some(data))
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        let leaf = Self::overlay_leaf(session_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(());
        }
        let lock = self.acquire_existing_lock(repo_id)?;
        let Some(overlays) = lock
            .namespace
            .surface(Self::overlays_surface_name(), false)?
        else {
            self.confirm_repository_visible(&lock.namespace)?;
            return Ok(());
        };
        if !overlays.exists(&leaf)? {
            lock.namespace.confirm_surface_visible(&overlays)?;
            self.confirm_repository_visible(&lock.namespace)?;
            return Ok(());
        }
        overlays.directory.remove_file(&leaf).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to delete overlay {}: {error}",
                overlays.display(&leaf).display()
            ))
        })?;
        overlays.sync(&leaf)?;
        lock.namespace.confirm_surface_visible(&overlays)?;
        self.confirm_repository_visible(&lock.namespace)
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        let Some(root) = self.storage_root_capability()? else {
            return Ok(Vec::new());
        };
        let entries = root.directory().entries().map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read base directory {}: {e}",
                self.base_path.display()
            ))
        })?;
        let mut repos = Vec::new();
        let mut seen_identities = std::collections::HashMap::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                KinDbError::StorageError(format!("failed to read directory entry: {e}"))
            })?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if validate_source_blob_repo_id(&name).is_err() {
                continue;
            }
            // A storage root legitimately holds the engine's snapshot, vector,
            // index, and generation files beside the repository namespaces, and
            // a regular file is never a namespace. Skipping those keeps the
            // bind below unchanged, so an entry that could still claim a
            // namespace, a symlink or any other non-directory, is refused
            // rather than quietly dropped from the listing.
            let file_type = entry.file_type().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect local storage root entry {}: {error}",
                    self.base_path.join(&name).display()
                ))
            })?;
            if file_type.is_file() {
                continue;
            }
            let Some(candidate) = Self::open_repository_from_root(&root, &name, &self.base_path)?
            else {
                continue;
            };
            if !candidate.exists(Self::authority_relative_path())? {
                continue;
            }
            // Listing is visibility discovery only. In particular, do not run
            // recovery confirmation here: that can remove an atomic-write
            // marker and is authority mutation that belongs under the
            // repository lock. The first real authority read performs that
            // recovery before trusting the record.
            let authority_path = candidate.display(Self::authority_relative_path());
            let authority_bytes = candidate.read_regular_bounded(
                Self::authority_relative_path(),
                "local authority",
                1024 * 1024,
            )?;
            Self::decode_authority_record(&name, &authority_path, &authority_bytes)?;

            let namespaces = self.repository_namespaces.lock();
            if let Some(expected) = namespaces.get(&name) {
                if expected.identity != candidate.identity {
                    return Err(KinDbError::StorageError(format!(
                        "local repository namespace {} changed while listing repositories",
                        expected.display_path.display()
                    )));
                }
            } else if let Some((existing_id, _)) = namespaces
                .iter()
                .find(|(_, expected)| expected.identity == candidate.identity)
            {
                return Err(KinDbError::StorageError(format!(
                    "repository ids {name:?} and {existing_id:?} resolve to the same retained storage namespace"
                )));
            }
            drop(namespaces);
            self.confirm_repository_visible(&candidate)?;
            if let Some(existing_id) = seen_identities.insert(candidate.identity, name.clone()) {
                return Err(KinDbError::StorageError(format!(
                    "repository ids {name:?} and {existing_id:?} resolve to the same transiently discovered storage namespace"
                )));
            }
            repos.push(name);
        }
        repos.sort();
        Ok(repos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
                    "test repository fixture contains unsupported entry {}",
                    source_path.display()
                );
            }
        }
    }

    #[cfg(unix)]
    fn test_directory_bytes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn collect(
            root: &Path,
            cursor: &Path,
            files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in std::fs::read_dir(cursor).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    collect(root, &path, files);
                } else if file_type.is_file() {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(path).unwrap(),
                    );
                }
            }
        }

        let mut files = std::collections::BTreeMap::new();
        collect(root, root, &mut files);
        files
    }

    #[cfg(unix)]
    fn assert_repository_namespace_rejected<T: std::fmt::Debug>(result: Result<T, KinDbError>) {
        let error = result.expect_err("a retained backend must reject a replacement repository");
        assert!(
            (error.to_string().contains("repository namespace")
                || error.to_string().contains("repository surface"))
                && (error.to_string().contains("changed")
                    || error.to_string().contains("detached")),
            "unexpected descendant-namespace error: {error}"
        );
    }

    struct RecoveryFixtureBackend {
        snapshot_bytes: Vec<u8>,
        snapshot_generation: Generation,
        head_generation: Generation,
        deltas: Vec<PersistedDelta>,
    }

    impl StorageBackend for RecoveryFixtureBackend {
        fn load_recovery_state(&self, _repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
            Ok((
                Some(SnapshotAuthority {
                    snapshot_bytes: self.snapshot_bytes.clone(),
                    snapshot_generation: self.snapshot_generation,
                    head_generation: self.head_generation,
                    history_validation: None,
                }),
                self.deltas.clone(),
            ))
        }

        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            unreachable!("the coherent recovery fixture overrides load_recovery_state")
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            _data: &[u8],
            _expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            unreachable!("the coherent recovery fixture overrides load_recovery_state")
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            unreachable!("the coherent recovery fixture is read-only")
        }
    }

    fn recovered_payload_stats<B: StorageBackend + ?Sized>(
        backend: &B,
        repo_id: &str,
    ) -> Result<AuthorityPayloadStats, KinDbError> {
        load_recovered_repository_authority(backend, repo_id, 0)?
            .map(|recovered| recovered.payload_stats)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "repo {repo_id} has no persisted authority payload"
                ))
            })
    }

    #[test]
    fn authority_payload_stats_constructor_checks_generation_count_and_overflow() {
        let inverted = AuthorityPayloadStats::from_components(3, 2, 1, 0, 0)
            .expect_err("an inverted authority range must not produce a receipt");
        assert!(inverted
            .to_string()
            .contains("snapshot generation 3 exceeds head generation 2"));

        let wrong_count = AuthorityPayloadStats::from_components(1, 3, 1, 1, 1)
            .expect_err("the receipt count must name every contiguous generation");
        assert!(wrong_count
            .to_string()
            .contains("counted 1 acknowledged deltas, expected 2"));

        let overflow = AuthorityPayloadStats::from_components(1, 1, u64::MAX, 0, 1)
            .expect_err("the checked total must refuse u64 overflow");
        assert!(overflow
            .to_string()
            .contains("authority payload byte count overflows u64"));
    }

    #[test]
    fn malformed_acknowledged_chains_return_no_payload_receipt() {
        let snapshot_bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let valid = crate::storage::delta::GraphSnapshotDelta::empty(1)
            .to_bytes()
            .unwrap();
        let wrong_base = crate::storage::delta::GraphSnapshotDelta::empty(0)
            .to_bytes()
            .unwrap();

        let fixtures = [
            (
                "wrong-base",
                RecoveryFixtureBackend {
                    snapshot_bytes: snapshot_bytes.clone(),
                    snapshot_generation: 1,
                    head_generation: 2,
                    deltas: vec![(wrong_base, 2)],
                },
                "declares base 0, expected 1",
            ),
            (
                "duplicate",
                RecoveryFixtureBackend {
                    snapshot_bytes: snapshot_bytes.clone(),
                    snapshot_generation: 1,
                    head_generation: 3,
                    deltas: vec![(valid.clone(), 2), (valid.clone(), 2)],
                },
                "delta journal is not strictly ordered",
            ),
            (
                "corrupt",
                RecoveryFixtureBackend {
                    snapshot_bytes,
                    snapshot_generation: 1,
                    head_generation: 2,
                    deltas: vec![(vec![0xff, 0x00, 0xff], 2)],
                },
                "delta",
            ),
        ];

        for (name, backend, expected) in fixtures {
            let error = recovered_payload_stats(&backend, name)
                .expect_err("malformed acknowledged bytes must not produce any receipt");
            assert!(
                error.to_string().to_lowercase().contains(expected),
                "unexpected {name} recovery error: {error}"
            );
        }
    }

    struct UnboundedOnlyBackend;

    impl StorageBackend for UnboundedOnlyBackend {
        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            unreachable!("snapshot methods are not used by this fixture")
        }

        fn load_source_blob(
            &self,
            _repo_id: &str,
            _digest: [u8; 32],
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            panic!("the bounded default must not downgrade to the unbounded method")
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            _data: &[u8],
            _expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            unreachable!("snapshot methods are not used by this fixture")
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            unreachable!("delta methods are not used by this fixture")
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            unreachable!("delta methods are not used by this fixture")
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            unreachable!("delta methods are not used by this fixture")
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            unreachable!("overlay methods are not used by this fixture")
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            unreachable!("overlay methods are not used by this fixture")
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            unreachable!("overlay methods are not used by this fixture")
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            unreachable!("repo listing is not used by this fixture")
        }
    }

    fn source_digest(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn initialize_local_repository_namespace(backend: &LocalFileBackend, repo_id: &str) {
        drop(
            backend
                .acquire_lock(repo_id)
                .expect("test repository namespace must initialize"),
        );
    }

    fn collect_store_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(
            directory: &Path,
            root: &Path,
            out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    walk(&path, root, out);
                } else {
                    out.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(&path).unwrap(),
                    );
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn local_source_blob_batch_writes_the_same_store_content_as_per_object_writes() {
        let bodies: Vec<Vec<u8>> = (0..24)
            .map(|i| format!("parity body {i} with enough bytes to differ").into_bytes())
            .collect();
        let digests: Vec<[u8; 32]> = bodies.iter().map(|body| source_digest(body)).collect();

        let per_object_dir = TempDir::new().unwrap();
        let per_object = LocalFileBackend::new(per_object_dir.path());
        for (digest, body) in digests.iter().zip(&bodies) {
            per_object
                .save_source_blob("repo-a", *digest, body)
                .unwrap();
        }

        let batched_dir = TempDir::new().unwrap();
        let batched = LocalFileBackend::new(batched_dir.path());
        batched
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                for (digest, body) in digests.iter().zip(&bodies) {
                    batch.save(*digest, body)?;
                }
                Ok(())
            })
            .expect("a batch publishes every body it accepted");

        let written_per_object =
            collect_store_tree(&per_object_dir.path().join("repo-a").join("source-blobs"));
        let written_by_batch =
            collect_store_tree(&batched_dir.path().join("repo-a").join("source-blobs"));
        assert_eq!(
            written_per_object, written_by_batch,
            "a batch must publish the same bytes at the same content addresses"
        );
        assert_eq!(written_by_batch.len(), bodies.len());

        // Durability is promised when the batch returns, so a backend that
        // never saw the session reads every body back.
        let reopened = LocalFileBackend::new(batched_dir.path());
        for (digest, body) in digests.iter().zip(&bodies) {
            assert_eq!(
                reopened.load_source_blob("repo-a", *digest).unwrap(),
                Some(body.clone())
            );
        }
    }

    /// The prefix a capability is keyed by is the same two hex characters the
    /// digest directory has always been named after.
    #[cfg(unix)]
    #[test]
    fn source_blob_prefix_is_the_first_two_digest_hex_characters() {
        for seed in 0u32..512 {
            let digest = source_digest(format!("prefix equivalence {seed}").as_bytes());
            assert_eq!(source_blob_prefix(digest), hex::encode(digest)[..2]);
        }
    }

    /// Bodies whose digests land in exactly `prefixes` digest-prefix
    /// directories, `per_prefix` bodies in each.
    #[cfg(unix)]
    fn bodies_sharing_digest_prefixes(prefixes: usize, per_prefix: usize) -> Vec<Vec<u8>> {
        let mut grouped: std::collections::BTreeMap<u8, Vec<Vec<u8>>> =
            std::collections::BTreeMap::new();
        let mut candidate = 0u32;
        while grouped
            .values()
            .filter(|bodies| bodies.len() >= per_prefix)
            .count()
            < prefixes
        {
            let body = format!("prefix fixture body {candidate}").into_bytes();
            let entry = grouped.entry(source_digest(&body)[0]).or_default();
            if entry.len() < per_prefix {
                entry.push(body);
            }
            candidate += 1;
            assert!(
                candidate < 1_000_000,
                "digest prefix search did not converge"
            );
        }
        grouped
            .into_values()
            .filter(|bodies| bodies.len() >= per_prefix)
            .take(prefixes)
            .flatten()
            .collect()
    }

    /// The per-object envelope is two full repository re-resolutions and two
    /// digest-prefix walks per body; a write session pays a fixed envelope
    /// instead, whatever it carries.
    ///
    /// Both counters are load-independent proxies for syscalls: a repository
    /// confirmation is roughly twenty of them, including two `realpath` calls
    /// and a directory-stream read, and a prefix walk is an `openat` per chain
    /// component. Reverting either hoist puts the batch back on the per-object
    /// numbers this test also pins.
    #[cfg(unix)]
    #[test]
    fn local_source_blob_batch_amortizes_the_per_object_envelope() {
        const PREFIXES: usize = 2;
        const PER_PREFIX: usize = 12;
        let bodies = bodies_sharing_digest_prefixes(PREFIXES, PER_PREFIX);
        let digests: Vec<[u8; 32]> = bodies.iter().map(|body| source_digest(body)).collect();
        assert_eq!(bodies.len(), PREFIXES * PER_PREFIX);
        assert_eq!(
            digests
                .iter()
                .map(|digest| digest[0])
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            PREFIXES
        );

        let batched_dir = TempDir::new().unwrap();
        let batched = LocalFileBackend::new(batched_dir.path());
        reset_source_envelope_counters();
        batched
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                for (digest, body) in digests.iter().zip(&bodies) {
                    batch.save(*digest, body)?;
                }
                Ok(())
            })
            .expect("a batch publishes every body it accepted");
        let (batched_confirmations, batched_walks) = source_envelope_counters();

        // Two confirmations bracket the whole session: acquiring the
        // repository lock ends in `confirm_existing_lock_visible`, which
        // confirms the namespace under the held lock, and the flush confirms
        // it again after the last body.
        assert_eq!(
            batched_confirmations, 2,
            "a write session must re-resolve the repository twice, not twice per body"
        );
        // Two walks to pin and confirm each prefix, one more per prefix to
        // re-confirm it at the flush.
        assert_eq!(
            batched_walks,
            (PREFIXES * 3) as u64,
            "a write session must walk each digest prefix a fixed number of times"
        );

        let per_object_dir = TempDir::new().unwrap();
        let per_object = LocalFileBackend::new(per_object_dir.path());
        reset_source_envelope_counters();
        for (digest, body) in digests.iter().zip(&bodies) {
            per_object
                .save_source_blob("repo-a", *digest, body)
                .unwrap();
        }
        let (per_object_confirmations, per_object_walks) = source_envelope_counters();
        assert_eq!(
            per_object_confirmations,
            (bodies.len() * 3) as u64,
            "the per-object contract still re-resolves the repository around every body"
        );
        assert_eq!(
            per_object_walks,
            (bodies.len() * 2) as u64,
            "the per-object contract still walks and re-confirms the prefix per body"
        );

        // Amortizing the envelope may not change what either path stores.
        assert_eq!(
            collect_store_tree(&batched_dir.path().join("repo-a").join("source-blobs")),
            collect_store_tree(&per_object_dir.path().join("repo-a").join("source-blobs")),
        );
    }

    /// A write session flushes the drive's cache once, not once per body.
    ///
    /// On Apple platforms `File::sync_all` is `fcntl(F_FULLFSYNC)`, a full
    /// device cache flush, and it was the single largest cost left inside the
    /// per-body write. A session issues `F_BARRIERFSYNC` per body instead,
    /// which orders that body ahead of the `linkat` naming it, and one
    /// `F_FULLFSYNC` before it makes any name durable.
    ///
    /// Elsewhere `fsync` is already the strongest barrier available, so the
    /// per-body flush stays and this test pins that it stayed.
    #[cfg(unix)]
    #[test]
    fn local_source_blob_batch_flushes_the_device_once_per_session() {
        const PREFIXES: usize = 2;
        const PER_PREFIX: usize = 12;
        let bodies = bodies_sharing_digest_prefixes(PREFIXES, PER_PREFIX);
        let digests: Vec<[u8; 32]> = bodies.iter().map(|body| source_digest(body)).collect();

        let batched_dir = TempDir::new().unwrap();
        let batched = LocalFileBackend::new(batched_dir.path());
        reset_source_barrier_counters();
        batched
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                for (digest, body) in digests.iter().zip(&bodies) {
                    batch.save(*digest, body)?;
                }
                Ok(())
            })
            .expect("a batch publishes every body it accepted");
        let (batched_flushes, batched_barriers) = source_barrier_counters();

        #[cfg(target_vendor = "apple")]
        {
            assert_eq!(
                batched_barriers,
                bodies.len() as u64,
                "every body must still be ordered ahead of the name that points at it"
            );
            assert_eq!(
                batched_flushes, 1,
                "a session must flush the device once, before it makes any name durable"
            );
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            assert_eq!(
                batched_barriers, 0,
                "only Apple platforms offer an ordering barrier below a full flush"
            );
            assert_eq!(
                batched_flushes,
                bodies.len() as u64 + 1,
                "elsewhere each body keeps its own flush, plus the session's"
            );
        }

        let per_object_dir = TempDir::new().unwrap();
        let per_object = LocalFileBackend::new(per_object_dir.path());
        reset_source_barrier_counters();
        for (digest, body) in digests.iter().zip(&bodies) {
            per_object
                .save_source_blob("repo-a", *digest, body)
                .unwrap();
        }
        let (per_object_flushes, per_object_barriers) = source_barrier_counters();
        assert_eq!(
            per_object_barriers, 0,
            "the per-object contract must never weaken a body barrier to an ordering one"
        );
        assert_eq!(
            per_object_flushes,
            (bodies.len() * 2) as u64,
            "the per-object contract still flushes the device for the staged body and its acknowledgement"
        );

        // A weaker per-body barrier may not change what the session stores.
        assert_eq!(
            collect_store_tree(&batched_dir.path().join("repo-a").join("source-blobs")),
            collect_store_tree(&per_object_dir.path().join("repo-a").join("source-blobs")),
        );
        let reopened = LocalFileBackend::new(batched_dir.path());
        for (digest, body) in digests.iter().zip(&bodies) {
            assert_eq!(
                reopened.load_source_blob("repo-a", *digest).unwrap(),
                Some(body.clone())
            );
        }
    }

    /// The session envelope is fixed, so carrying more bodies through the same
    /// prefixes costs nothing more.
    #[cfg(unix)]
    #[test]
    fn local_source_blob_batch_envelope_does_not_grow_with_body_count() {
        let mut counters = Vec::new();
        for per_prefix in [4usize, 16] {
            let bodies = bodies_sharing_digest_prefixes(2, per_prefix);
            let digests: Vec<[u8; 32]> = bodies.iter().map(|body| source_digest(body)).collect();
            let dir = TempDir::new().unwrap();
            let backend = LocalFileBackend::new(dir.path());
            reset_source_envelope_counters();
            backend
                .with_source_blob_write_batch("repo-a", &mut |batch| {
                    for (digest, body) in digests.iter().zip(&bodies) {
                        batch.save(*digest, body)?;
                    }
                    Ok(())
                })
                .unwrap();
            counters.push((bodies.len(), source_envelope_counters()));
        }
        assert_ne!(counters[0].0, counters[1].0);
        assert_eq!(
            counters[0].1, counters[1].1,
            "a session that carries four times the bodies must pay the same envelope"
        );
    }

    #[test]
    fn local_source_blob_batch_and_per_object_writes_interoperate() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let shared = b"a body both paths publish";
        let shared_digest = source_digest(shared);
        let fresh = b"a body only the batch publishes";
        let fresh_digest = source_digest(fresh);

        backend
            .save_source_blob("repo-a", shared_digest, shared)
            .unwrap();
        backend
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                // An exact repeat of an already-published body is success, and
                // repeating it inside one session is too.
                batch.save(shared_digest, shared)?;
                batch.save(shared_digest, shared)?;
                batch.save(fresh_digest, fresh)
            })
            .expect("an exact repeat is success on both paths");

        let reopened = LocalFileBackend::new(dir.path());
        assert_eq!(
            reopened.load_source_blob("repo-a", shared_digest).unwrap(),
            Some(shared.to_vec())
        );
        assert_eq!(
            reopened.load_source_blob("repo-a", fresh_digest).unwrap(),
            Some(fresh.to_vec())
        );
        backend
            .save_source_blob("repo-a", fresh_digest, fresh)
            .expect("a per-object retry of a batched body is success");
    }

    #[test]
    fn local_source_blob_batch_validates_every_body_like_a_single_write() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let error = backend
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                batch.save(source_digest(b"claimed"), b"actual")
            })
            .expect_err("a batch must refuse a body that does not match its digest");
        assert!(error.to_string().contains("digest mismatch"), "{error}");

        // A body already at a taken identity is refused for the same reason a
        // single write refuses it: the bytes are not the ones that identity
        // names.
        let data = b"first bytes at this identity";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();
        let replaced = backend
            .with_source_blob_write_batch("repo-a", &mut |batch| batch.save(digest, b"other bytes"))
            .expect_err("a batch must never replace bytes already at an identity");
        assert!(
            replaced.to_string().contains("digest mismatch"),
            "{replaced}"
        );
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec()),
            "the refused write must leave the published body untouched"
        );

        let invalid = backend
            .with_source_blob_write_batch("../escape", &mut |_| Ok(()))
            .expect_err("a batch must validate its repository id before taking a lock");
        assert!(invalid.to_string().contains("invalid repo id"), "{invalid}");
    }

    #[test]
    fn local_source_blob_batch_reports_a_failed_session_as_failure() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"written before the session aborts";
        let digest = source_digest(data);
        let error = backend
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                batch.save(digest, data)?;
                Err(KinDbError::StorageError(
                    "caller aborted the session".to_string(),
                ))
            })
            .expect_err("a failed session must never report success");
        assert!(error.to_string().contains("caller aborted the session"));
    }

    #[test]
    fn source_blob_batch_default_writes_through_the_per_object_path() {
        let error = UnboundedOnlyBackend
            .with_source_blob_write_batch("repo-a", &mut |batch| batch.save([0; 32], b"body"))
            .expect_err("the default batch delegates to save_source_blob");
        assert!(
            error
                .to_string()
                .contains("immutable source blob storage is not supported"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_batch_holds_the_repository_lock_across_the_session() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        initialize_local_repository_namespace(&backend, "repo-a");

        let bodies: Vec<Vec<u8>> = (0..8)
            .map(|i| format!("exclusion body {i}").into_bytes())
            .collect();
        let digests: Vec<[u8; 32]> = bodies.iter().map(|body| source_digest(body)).collect();
        let probe = digests[0];
        let base = dir.path().to_path_buf();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let mut reader = None;

        backend
            .with_source_blob_write_batch("repo-a", &mut |batch| {
                for (digest, body) in digests.iter().zip(&bodies) {
                    batch.save(*digest, body)?;
                }
                let base = base.clone();
                let finished_tx = finished_tx.clone();
                let started_tx = started_tx.clone();
                reader = Some(std::thread::spawn(move || {
                    let competing = LocalFileBackend::new(&base);
                    started_tx.send(()).unwrap();
                    finished_tx
                        .send(competing.load_source_blob("repo-a", probe))
                        .unwrap();
                }));
                started_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("the competing reader reaches its load");
                assert!(
                    finished_rx
                        .recv_timeout(std::time::Duration::from_millis(200))
                        .is_err(),
                    "a reader must wait on the repository lock the batch holds"
                );
                Ok(())
            })
            .expect("a batch publishes every body it accepted");

        let observed = finished_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the reader proceeds once the batch releases the lock")
            .expect("the reader observes a complete store");
        assert_eq!(observed, Some(bodies[0].clone()));
        reader.unwrap().join().unwrap();
    }

    /// Readers of one repository stop excluding each other; writers still
    /// exclude everyone.
    ///
    /// Every acquisition here goes through the real lock target, and the
    /// unheld case is the control: the probe is able to report "free", so a
    /// report of "would block" carries information.
    #[test]
    fn source_blob_readers_share_the_repository_lock_and_writers_still_exclude_them() {
        use LocalRepositoryLockAccess::{Exclusive, Shared};

        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let body = b"a body two readers want at once";
        let digest = source_digest(body);
        backend.save_source_blob("repo-a", digest, body).unwrap();

        assert!(
            !backend
                .repository_lock_would_block("repo-a", Shared)
                .unwrap(),
            "nothing is held, so a shared acquisition is free"
        );
        assert!(
            !backend
                .repository_lock_would_block("repo-a", Exclusive)
                .unwrap(),
            "nothing is held, so an exclusive acquisition is free"
        );

        let reader = backend.acquire_existing_shared_lock("repo-a").unwrap();
        assert!(
            !backend
                .repository_lock_would_block("repo-a", Shared)
                .unwrap(),
            "a second reader must not wait on the first"
        );
        assert!(
            backend
                .repository_lock_would_block("repo-a", Exclusive)
                .unwrap(),
            "a writer must still wait on a reader"
        );
        // A second reader really can complete a read while the first holds.
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(body.to_vec())
        );
        drop(reader);

        let writer = backend.acquire_existing_lock("repo-a").unwrap();
        assert!(
            backend
                .repository_lock_would_block("repo-a", Shared)
                .unwrap(),
            "a reader must still wait on a writer"
        );
        assert!(
            backend
                .repository_lock_would_block("repo-a", Exclusive)
                .unwrap(),
            "a writer must still wait on a writer"
        );
        drop(writer);
    }

    /// A read creates nothing, so it may be taken under a shared lock.
    ///
    /// A repository that has never stored a body has no
    /// `source-blobs/sha256/HH` chain. Reading used to mint that chain, which
    /// is a mutation, and was the only reason a lookup needed the exclusive
    /// lock. The GCS backend answers the same trait methods without creating
    /// anything, so directory creation was never part of the read contract.
    #[test]
    fn source_blob_read_of_a_repository_without_bodies_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        initialize_local_repository_namespace(&backend, "repo-a");
        let source_blobs = dir.path().join("repo-a").join("source-blobs");
        assert!(!source_blobs.exists());

        let digest = source_digest(b"a body this repository never stored");
        assert_eq!(backend.load_source_blob("repo-a", digest).unwrap(), None);
        assert!(
            !source_blobs.exists(),
            "a lookup must not mint the digest-prefix chain"
        );
        assert_eq!(backend.source_blob_len("repo-a", digest).unwrap(), None);
        assert!(
            !source_blobs.exists(),
            "a length probe must not mint the digest-prefix chain"
        );
        assert_eq!(
            backend
                .load_source_blob_bounded("repo-a", digest, 16)
                .unwrap(),
            None
        );
        assert!(!source_blobs.exists());

        // A repository that does hold bodies still answers a missing one with
        // None rather than an error.
        let stored = b"a body this repository does store";
        let stored_digest = source_digest(stored);
        backend
            .save_source_blob("repo-a", stored_digest, stored)
            .unwrap();
        assert_eq!(
            backend.load_source_blob("repo-a", stored_digest).unwrap(),
            Some(stored.to_vec())
        );
        assert_eq!(backend.load_source_blob("repo-a", digest).unwrap(), None);
    }

    /// A symlinked or non-directory ancestor is still a refusal, not absence.
    #[cfg(unix)]
    #[test]
    fn source_blob_read_still_refuses_a_symlinked_prefix_rather_than_reporting_absence() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let body = b"a body below a substituted prefix";
        let digest = source_digest(body);
        backend.save_source_blob("repo-a", digest, body).unwrap();

        let prefix = dir
            .path()
            .join("repo-a")
            .join("source-blobs")
            .join("sha256")
            .join(&hex::encode(digest)[..2]);
        std::fs::remove_dir_all(&prefix).unwrap();
        symlink(outside.path(), &prefix).unwrap();

        let error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("a symlinked digest prefix must fail closed, not read as absent");
        assert!(
            error.to_string().contains("refusing symlinked"),
            "unexpected substituted-prefix error: {error}"
        );
    }

    #[test]
    fn bounded_source_blob_default_fails_closed_without_calling_unbounded_load() {
        let error = UnboundedOnlyBackend
            .load_source_blob_bounded("repo-a", [0; 32], 4)
            .expect_err("backends must explicitly implement bounded reads");
        assert!(error
            .to_string()
            .contains("bounded immutable source blob reads are not supported"));
    }

    #[test]
    fn local_source_blob_roundtrips_retries_and_reports_missing() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"immutable source bytes";
        let digest = source_digest(data);

        assert!(backend
            .load_source_blob("repo-a", digest)
            .unwrap()
            .is_none());
        backend.save_source_blob("repo-a", digest, data).unwrap();
        backend.save_source_blob("repo-a", digest, data).unwrap();
        drop(backend);
        let reopened = LocalFileBackend::new(dir.path());
        assert_eq!(
            reopened.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
        assert_eq!(
            reopened.source_blob_len("repo-a", digest).unwrap(),
            Some(data.len() as u64)
        );
        assert!(reopened
            .load_source_blob("repo-b", digest)
            .unwrap()
            .is_none());
        assert!(reopened
            .source_blob_len("repo-b", digest)
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_existing_object_retry_fsyncs_the_pinned_file() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"existing immutable source";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();

        fail_source_file_sync_once();
        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("an existing object retry must fsync its pinned file before ack");
        assert!(error
            .to_string()
            .contains("injected immutable source file fsync failure"));

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("the retry is acknowledged after file and directory confirmation");
    }

    #[test]
    fn local_source_blob_honors_caller_limit_before_allocating_body() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"bounded source bytes";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();

        let error = backend
            .load_source_blob_bounded("repo-a", digest, data.len() as u64 - 1)
            .expect_err("metadata above the caller's limit must fail before reading");
        assert!(matches!(
            error,
            KinDbError::SourceBlobReadLimitExceeded {
                actual_bytes,
                max_bytes
            } if actual_bytes == data.len() as u64 && max_bytes == data.len() as u64 - 1
        ));
        assert_eq!(
            backend
                .load_source_blob_bounded("repo-a", digest, data.len() as u64)
                .unwrap(),
            Some(data.to_vec())
        );
    }

    #[test]
    fn local_source_blob_rejects_wrong_digest_corruption_and_unsafe_repo_id() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"expected";
        let digest = source_digest(data);

        let wrong_digest_error = backend
            .save_source_blob("repo-a", source_digest(b"different"), data)
            .expect_err("write identity must bind the exact bytes");
        assert!(wrong_digest_error.to_string().contains("digest mismatch"));

        for repo_id in ["", ".", "..", "../escape", "owner/repo"] {
            let error = backend
                .load_source_blob(repo_id, digest)
                .expect_err("repo id must not control an object path");
            assert!(error.to_string().contains("invalid repo id"));
        }

        initialize_local_repository_namespace(&backend, "repo-a");
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        LocalFileBackend::atomic_write(&path, b"corrupt").unwrap();
        let read_error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("corrupt immutable bytes must fail closed");
        assert!(read_error.to_string().contains("digest mismatch"));
        let retry_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("a write retry must not replace corrupt authority");
        assert!(retry_error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn source_blob_repo_ids_have_one_portable_windows_meaning() {
        for repo_id in [
            "CON",
            "con.txt",
            "PRN",
            "AUX.log",
            "nul",
            "CLOCK$",
            "COM1",
            "com9.cache",
            "LPT1",
            "lpt9.txt",
            "repo.",
            "repo ",
        ] {
            let error = validate_source_blob_repo_id(repo_id)
                .expect_err("Windows device aliases and normalized names must be rejected");
            assert!(
                error.to_string().contains("invalid repo id"),
                "unexpected validation error for {repo_id:?}: {error}"
            );
        }
        for repo_id in ["console", "com0", "com10", "lpt0", "lpt10", "repo.name"] {
            validate_source_blob_repo_id(repo_id)
                .unwrap_or_else(|error| panic!("portable repo id {repo_id:?} rejected: {error}"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_symlink_object_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"source";
        let digest = source_digest(data);
        initialize_local_repository_namespace(&backend, "repo-a");
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do not replace").unwrap();
        symlink(&victim, &path).unwrap();

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("symlink source object must fail closed");
        assert!(error.to_string().contains("immutable source blob"));
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not replace");
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_fifo_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let digest = source_digest(b"fifo must not be read");
        initialize_local_repository_namespace(&backend, "repo-a");
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path_c` is a live NUL-terminated path and the parent exists.
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);

        let error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("a FIFO must be rejected without a blocking open");
        assert!(error
            .to_string()
            .contains("non-regular immutable source blob"));
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_every_symlinked_storage_ancestor() {
        use std::os::unix::fs::symlink;

        let data = b"source";
        let digest = source_digest(data);
        let digest_hex = hex::encode(digest);
        for ancestor in ["repo", "source-blobs", "sha256", "prefix"] {
            let dir = TempDir::new().unwrap();
            let outside = TempDir::new().unwrap();
            let backend = LocalFileBackend::new(dir.path());
            let repo = dir.path().join("repo-a");
            let source_blobs = repo.join("source-blobs");
            let sha256 = source_blobs.join("sha256");
            let prefix = sha256.join(&digest_hex[..2]);
            if ancestor != "repo" {
                initialize_local_repository_namespace(&backend, "repo-a");
            }
            let link_path = match ancestor {
                "repo" => repo,
                "source-blobs" => source_blobs,
                "sha256" => {
                    std::fs::create_dir_all(&source_blobs).unwrap();
                    sha256
                }
                "prefix" => {
                    std::fs::create_dir_all(&sha256).unwrap();
                    prefix
                }
                _ => unreachable!(),
            };
            symlink(outside.path(), &link_path).unwrap();

            let error = backend
                .save_source_blob("repo-a", digest, data)
                .expect_err("a symlinked object ancestor must fail closed");
            assert!(
                error.to_string().contains("symlinked or non-directory")
                    || error.to_string().contains("not a real directory"),
                "unexpected error for {ancestor}: {error}"
            );
            assert_eq!(
                std::fs::read_dir(outside.path()).unwrap().count(),
                0,
                "the {ancestor} symlink target must remain untouched"
            );
        }
    }

    #[test]
    fn local_source_blob_rejects_oversized_sparse_object_before_reading() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let digest = [42; 32];
        initialize_local_repository_namespace(&backend, "repo-a");
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_SOURCE_BLOB_BYTES + 1).unwrap();
        // Windows immutable-source reads deliberately refuse an incompatible
        // live writer instead of reading a potentially torn body. Close this
        // fixture's setup handle so the assertion reaches the intended
        // pre-allocation size gate on every platform.
        drop(file);

        let error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("oversized source object must fail before allocation");
        assert!(error.to_string().contains("safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_fixed_allocation_detects_growth_after_metadata() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"fixed allocation";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        set_source_file_after_metadata_hook(move || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, b"!").unwrap();
        });

        let error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("growth beyond the pinned descriptor length must fail closed");
        assert!(error.to_string().contains("changed length while reading"));
        assert!(error.to_string().contains("allocation safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn local_verified_batch_refuses_repository_displacement_at_final_boundary() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"batch-pinned immutable source";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();

        let repo = dir.path().join("repo-a");
        let displaced_repo = dir.path().join("repo-a-displaced");
        let outside_path = outside.path().to_path_buf();
        set_source_file_after_metadata_hook(move || {
            std::fs::rename(&repo, &displaced_repo).unwrap();
            symlink(outside_path, repo).unwrap();
        });

        let mut operation = |batch: &dyn VerifiedSourceBlobBatch| {
            let body = batch
                .load_verified(SourceBlobValidationRequest {
                    digest,
                    max_bytes: data.len() as u64,
                })?
                .expect("the retained capability still reaches the exact body");
            assert_eq!(body.bytes(), data);
            Ok(())
        };
        let error = backend
            .with_verified_source_blob_batch("repo-a", &mut operation)
            .expect_err("batch success must wait for final repository identity confirmation");
        assert!(
            error.to_string().contains("not a real directory")
                || error.to_string().contains("changed")
                || error.to_string().contains("detached"),
            "unexpected batch displacement error: {error}"
        );
    }

    #[test]
    fn local_source_blob_never_clobbers_object_created_during_publish_race() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"expected immutable bytes";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        let raced_path = path.clone();
        backend.set_source_blob_before_publish_hook(move || {
            std::fs::write(&raced_path, b"non-cooperating writer").unwrap();
        });

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("a racing different object must be preserved and rejected");
        assert!(error.to_string().contains("digest mismatch"));
        assert_eq!(std::fs::read(path).unwrap(), b"non-cooperating writer");
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_fsyncs_identical_object_that_wins_publish_race() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"identical racing immutable bytes";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        let raced_path = path.clone();
        backend.set_source_blob_before_publish_hook(move || {
            std::fs::write(raced_path, data).unwrap();
            fail_source_file_sync_once();
        });

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("the identical race winner must be fsynced before acknowledgement");
        assert!(error
            .to_string()
            .contains("injected immutable source file fsync failure"));
        assert_eq!(std::fs::read(&path).unwrap(), data);

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("retry confirms the identical race winner through the pinned descriptor");
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_repo_displacement_after_capability_open() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"pinned lock source";
        let digest = source_digest(data);
        let repo = dir.path().join("repo-a");
        let displaced_repo = dir.path().join("repo-a-displaced");
        let outside_path = outside.path().to_path_buf();
        backend.set_source_blob_after_capability_hook(move || {
            std::fs::rename(&repo, &displaced_repo).unwrap();
            symlink(outside_path, repo).unwrap();
        });

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("a substituted repo ancestor must fail closed");
        assert!(
            error.to_string().contains("not a real directory"),
            "unexpected substituted-repository error: {error}"
        );
        assert_eq!(
            std::fs::read_dir(outside.path()).unwrap().count(),
            0,
            "neither .lock nor source bytes may be created through the substituted repo path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_existing_retry_rejects_displaced_namespace() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"existing pinned source";
        let digest = source_digest(data);
        backend.save_source_blob("repo-a", digest, data).unwrap();

        let repo = dir.path().join("repo-a");
        let displaced_repo = dir.path().join("repo-a-displaced");
        let outside_path = outside.path().to_path_buf();
        backend.set_source_blob_after_capability_hook(move || {
            std::fs::rename(&repo, &displaced_repo).unwrap();
            symlink(outside_path, repo).unwrap();
        });

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("existing-object retry must revalidate its configured namespace");
        assert!(
            error.to_string().contains("not a real directory"),
            "unexpected existing-object displacement error: {error}"
        );
        assert_eq!(
            std::fs::read_dir(outside.path()).unwrap().count(),
            0,
            "an existing-object acknowledgement must not accept substituted authority"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_confirms_new_trust_root_parent_directory() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("new-storage-root");
        std::fs::create_dir(&base).unwrap();
        let backend = LocalFileBackend::new(&base);
        let data = b"durable trust root";
        let digest = source_digest(data);

        mmap::fail_parent_sync_after(0);
        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("new trust root must not be acknowledged before parent fsync");
        assert!(error
            .to_string()
            .contains("injected parent-directory fsync failure"));

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("retry confirms the new trust root and object");
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_retry_reconfirms_every_new_trust_root_ancestor() {
        let dir = TempDir::new().unwrap();
        let base = dir
            .path()
            .join("source-root-one")
            .join("source-root-two")
            .join("source-root-three");
        std::fs::create_dir_all(&base).unwrap();
        let backend = LocalFileBackend::new(&base);
        let data = b"nested durable trust root";
        let digest = source_digest(data);

        mmap::fail_parent_sync_after(1);
        backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("the first failed ancestor confirmation must abort publication");

        // All three paths now exist, but the retry must replay a complete root
        // confirmation rather than treating path visibility as durability.
        mmap::fail_parent_sync_after(2);
        let retry_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("retry must reconfirm every previously-created ancestor");
        assert!(retry_error
            .to_string()
            .contains("injected parent-directory fsync failure"));

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("publication succeeds only after the full ancestor chain is durable");
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_trust_root_reconfirms_visible_ancestors_after_process_restart() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("restart-root-one").join("restart-root-two");
        std::fs::create_dir_all(&base).unwrap();

        let first_process_confirmation = parking_lot::Mutex::new(false);
        mmap::fail_parent_sync_after(0);
        prepare_source_trust_root(&base, true, &first_process_confirmation)
            .expect_err("the first process leaves visible but unconfirmed directories");
        assert!(base.is_dir());

        // A new backend process has no in-memory retry ledger. It must still
        // attempt a complete ancestry confirmation before acknowledging data.
        let restarted_process_confirmation = parking_lot::Mutex::new(false);
        mmap::fail_parent_sync_after(0);
        let restarted_error =
            prepare_source_trust_root(&base, true, &restarted_process_confirmation)
                .expect_err("restart must not infer durability from path existence");
        assert!(restarted_error
            .to_string()
            .contains("injected parent-directory fsync failure"));

        prepare_source_trust_root(&base, true, &restarted_process_confirmation)
            .expect("restart confirms the complete visible ancestry on retry");
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_ancestor_symlink_substituted_before_publish() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"expected immutable bytes";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        let prefix = path.parent().unwrap().to_path_buf();
        let raced_prefix = prefix.clone();
        let outside_path = outside.path().to_path_buf();
        backend.set_source_blob_before_publish_hook(move || {
            std::fs::remove_dir(&raced_prefix).unwrap();
            symlink(outside_path, raced_prefix).unwrap();
        });

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("an ancestor swapped after validation must fail closed");
        assert!(error.to_string().contains("symlinked or non-directory"));
        assert_eq!(
            std::fs::read_dir(outside.path()).unwrap().count(),
            0,
            "the substituted ancestor target must remain untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_retry_reconfirms_failed_publication_directory_sync() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"durable immutable source bytes";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();

        // Keep this test focused on the object-entry confirmation after the
        // once-per-process trust-root ancestry proof.
        prepare_source_trust_root(dir.path(), true, &backend.source_root_confirmed_for_process)
            .unwrap();

        // Repository staging/publication, lock publication, and three source
        // ancestors are confirmed before the newly linked object entry.
        mmap::fail_parent_sync_after(6);
        let first_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("an unconfirmed object link must not be acknowledged");
        assert!(first_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(path.exists(), "the failed sync happens after publication");

        // The object exists on retry, but that retry must still perform its
        // own directory confirmation rather than trusting path existence.
        mmap::fail_parent_sync_after(3);
        let retry_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("retry must propagate its own directory sync failure");
        assert!(retry_error
            .to_string()
            .contains("injected parent-directory fsync failure"));

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("a retry may acknowledge only after directory confirmation");
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_source_blob_retries_failed_ancestor_directory_sync() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let data = b"durable Windows source ancestors";
        let digest = source_digest(data);

        mmap::fail_parent_sync_after(0);
        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("new Windows source ancestors must be durable before publication");
        assert!(error
            .to_string()
            .contains("injected parent-directory fsync failure"));

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("retry must confirm every visible ancestor child-before-parent");
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_source_blob_retries_failed_digest_entry_sync() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let data = b"durable Windows digest entry";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();

        // Three ancestor-directory confirmations precede the final digest
        // entry confirmation.
        mmap::fail_parent_sync_after(3);
        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("a renamed digest without directory durability is unconfirmed");
        assert!(error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(
            path.exists(),
            "the no-clobber digest remains available for an exact retry"
        );

        // A visible digest does not launder the failed confirmation: the
        // existing-object retry must repeat the leaf-directory flush.
        mmap::fail_parent_sync_after(3);
        backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("exact retry must propagate its own digest-entry sync failure");

        backend
            .save_source_blob("repo-a", digest, data)
            .expect("exact retry may acknowledge only after the digest entry is durable");
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
    }

    #[test]
    fn local_authority_freeze_does_not_create_a_missing_namespace() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repository_path = dir.path().join("missing-repo");

        let error = backend
            .freeze_existing_authority("missing-repo")
            .expect_err("freeze must require an existing local repository authority");
        assert!(error
            .to_string()
            .contains("unavailable for existing-authority access"));
        assert!(
            !repository_path.exists(),
            "a read/freeze API must not create repository storage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_source_writer_blocked_by_freeze_cannot_recreate_detached_root() {
        let directory = TempDir::new().unwrap();
        let base = directory.path().join("kindb");
        std::fs::create_dir(&base).unwrap();
        let backend = LocalFileBackend::new(&base);
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        let freeze = backend.freeze_existing_authority("repo-a").unwrap();
        let competing = LocalFileBackend::new(&base);
        let data = b"must not survive detach";
        let digest = source_digest(data);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(competing.save_source_blob("repo-a", digest, data))
                .unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "source writer must wait on the same repository authority lock"
        );

        let detached = directory.path().join("detached-kindb");
        std::fs::rename(&base, &detached).unwrap();
        drop(freeze);
        let error = finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("blocked source writer must wake after freeze release")
            .expect_err("blocked source writer must be revoked by namespace detach");
        assert!(
            error.to_string().contains("namespace changed")
                || error
                    .to_string()
                    .contains("unavailable for existing-authority access")
                || error
                    .to_string()
                    .contains("was detached after this backend opened"),
            "unexpected post-detach source-writer error: {error}"
        );
        writer.join().unwrap();
        assert!(
            !base.exists(),
            "blocked source writer must not recreate the detached storage root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preopened_local_writers_cannot_recreate_a_detached_root() {
        let directory = TempDir::new().unwrap();
        let base = directory.path().join("kindb");
        std::fs::create_dir(&base).unwrap();
        let backend = LocalFileBackend::new(&base);
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        let preopened = LocalFileBackend::new(&base);

        std::fs::rename(&base, directory.path().join("detached-kindb")).unwrap();
        let data = b"revoked source body";
        let source_error = preopened
            .save_source_blob("repo-a", source_digest(data), data)
            .expect_err("preopened source writer must not recreate detached storage");
        assert!(
            source_error
                .to_string()
                .contains("refusing to recreate a detached repository namespace")
                || source_error
                    .to_string()
                    .contains("unavailable for existing-authority access")
                || source_error
                    .to_string()
                    .contains("was detached after this backend opened"),
            "unexpected preopened source-writer error: {source_error}"
        );
        let overlay_error = preopened
            .save_overlay("repo-a", "session-a", b"revoked overlay")
            .expect_err("preopened overlay writer must not recreate detached storage");
        assert!(
            overlay_error
                .to_string()
                .contains("unavailable for existing-authority access")
                || overlay_error
                    .to_string()
                    .contains("was detached after this backend opened"),
            "unexpected preopened overlay-writer error: {overlay_error}"
        );
        assert!(
            !base.exists(),
            "no preopened local writer may recreate the detached storage root"
        );

        std::fs::create_dir(&base).unwrap();
        let replacement = LocalFileBackend::new(&base);
        replacement
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let replacement_error = preopened
            .save_source_blob("repo-a", source_digest(data), data)
            .expect_err("stale backend must not bind a newly created storage-root epoch");
        assert!(
            replacement_error
                .to_string()
                .contains("changed since this backend opened"),
            "unexpected replacement-epoch error: {replacement_error}"
        );
        assert!(
            !replacement
                .source_blob_path("repo-a", source_digest(data))
                .unwrap()
                .exists(),
            "stale backend must not add source bytes to the replacement storage epoch"
        );
        assert!(
            !replacement.overlay_path("repo-a", "session-a").exists(),
            "stale backend must not add overlays to the replacement storage epoch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_backend_rejects_repository_replacement_across_every_local_surface() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &snapshot, GENERATION_INIT)
            .unwrap();
        let source = b"retained exact source";
        backend
            .save_source_blob("repo-a", source_digest(source), source)
            .unwrap();
        backend
            .save_overlay("repo-a", "session-a", b"retained overlay")
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(generation)
            .to_bytes()
            .unwrap();
        let head = backend.save_delta("repo-a", &delta, generation).unwrap();

        let visible = directory.path().join("repo-a");
        let detached = directory.path().join("repo-a-detached");
        let staged_replacement = directory.path().join("repo-a-replacement");
        copy_test_directory(&visible, &staged_replacement);
        std::fs::rename(&visible, &detached).unwrap();
        std::fs::rename(&staged_replacement, &visible).unwrap();
        let replacement_before = test_directory_bytes(&visible);
        let detached_before = test_directory_bytes(&detached);

        let error = backend
            .load_snapshot("repo-a")
            .expect_err("the retained reader must reject the replacement snapshot surface");
        assert!(
            error.to_string().contains("repository namespace")
                && error.to_string().contains("changed"),
            "unexpected replaced snapshot-reader error: {error}"
        );
        assert_repository_namespace_rejected(backend.load_recovery_state("repo-a"));
        assert_repository_namespace_rejected(backend.save_snapshot("repo-a", &snapshot, head));
        let next_delta = crate::storage::delta::GraphSnapshotDelta::empty(head)
            .to_bytes()
            .unwrap();
        assert_repository_namespace_rejected(backend.save_delta("repo-a", &next_delta, head));
        assert_repository_namespace_rejected(backend.load_deltas_since("repo-a", GENERATION_INIT));
        assert_repository_namespace_rejected(backend.clear_deltas("repo-a"));
        assert_repository_namespace_rejected(
            backend.load_source_blob("repo-a", source_digest(source)),
        );
        assert_repository_namespace_rejected(
            backend.source_blob_len("repo-a", source_digest(source)),
        );
        let new_source = b"must not enter replacement";
        assert_repository_namespace_rejected(backend.save_source_blob(
            "repo-a",
            source_digest(new_source),
            new_source,
        ));
        assert_repository_namespace_rejected(backend.load_overlay("repo-a", "session-a"));
        assert_repository_namespace_rejected(backend.save_overlay(
            "repo-a",
            "session-b",
            b"must not enter replacement",
        ));
        assert_repository_namespace_rejected(backend.delete_overlay("repo-a", "session-a"));
        assert_repository_namespace_rejected(backend.freeze_existing_authority("repo-a"));
        assert_repository_namespace_rejected(backend.list_repos());

        assert_eq!(
            test_directory_bytes(&visible),
            replacement_before,
            "stale backend operations must not touch the replacement namespace"
        );
        assert_eq!(
            test_directory_bytes(&detached),
            detached_before,
            "rejected operations must not continue mutating the detached namespace"
        );
        assert!(
            backend.load_snapshot("repo-b").unwrap().is_some(),
            "repository capabilities are pinned independently"
        );

        let replacement_backend = LocalFileBackend::new(directory.path());
        let recovered = replacement_backend
            .load_recovery_state("repo-a")
            .expect("a new process may bind the replacement epoch");
        assert!(recovered.0.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn writer_blocked_on_old_repository_lock_cannot_touch_visible_replacement() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        let freeze = backend.freeze_existing_authority("repo-a").unwrap();

        let competing = LocalFileBackend::new(directory.path());
        let namespace = competing
            .repository_capability("repo-a", false)
            .unwrap()
            .expect("competing backend pins the old repository before waiting");
        let marker = LocalFileBackend::open_repository_lock(&namespace, false).unwrap();
        LocalFileBackend::pin_repository_lock_identity(&namespace, &marker).unwrap();
        let lock_target = LocalFileBackend::repository_lock_target(&namespace, &marker).unwrap();
        use fs2::FileExt;
        assert!(
            lock_target.try_lock_exclusive().is_err(),
            "the competing writer must contend on the exact old repository lock"
        );

        let visible = directory.path().join("repo-a");
        let detached = directory.path().join("repo-a-detached");
        let staged_replacement = directory.path().join("repo-a-replacement");
        copy_test_directory(&visible, &staged_replacement);
        std::fs::rename(&visible, &detached).unwrap();
        std::fs::rename(&staged_replacement, &visible).unwrap();
        let replacement_before = test_directory_bytes(&visible);

        drop(freeze);
        lock_target
            .lock_exclusive()
            .expect("the competing writer acquires the old lock after release");
        let result = competing.confirm_existing_lock_visible(&namespace);
        FileExt::unlock(&lock_target).unwrap();
        assert_repository_namespace_rejected(result);
        assert_eq!(
            test_directory_bytes(&visible),
            replacement_before,
            "the post-wait visibility check must reject before replacement IO"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_snapshot_surface_rejects_swap_before_authority_publication() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let initial = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("repo-a", &initial, GENERATION_INIT)
            .unwrap();
        let mut next = GraphSnapshot::empty();
        next.admit_artifact_for_test("next.rs".to_string(), crate::types::regular_tree_entry(1));
        let next = next.to_bytes().unwrap();

        let repo = directory.path().join("repo-a");
        let visible = repo.join("snapshots");
        let detached = repo.join("snapshots-detached");
        let replacement = repo.join("snapshots-replacement");
        copy_test_directory(&visible, &replacement);
        backend.set_snapshot_before_authority_commit_hook(move || {
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });

        let error = backend
            .save_snapshot("repo-a", &next, generation)
            .expect_err("a swapped snapshot surface must stop before authority publication");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected snapshot-surface error: {error}"
        );
        assert_repository_namespace_rejected(backend.load_snapshot("repo-a"));

        let reopened = LocalFileBackend::new(directory.path());
        let (bytes, reopened_generation) = reopened
            .load_snapshot("repo-a")
            .unwrap()
            .expect("old visible authority remains complete");
        assert_eq!(reopened_generation, generation);
        assert_eq!(bytes, initial);
        assert!(
            directory
                .path()
                .join("repo-a/snapshots-detached/00000000000000000002.kndb")
                .exists(),
            "the rejected write targets only the detached retained surface"
        );
        assert!(
            !directory
                .path()
                .join("repo-a/snapshots/00000000000000000002.kndb")
                .exists(),
            "the replacement snapshot surface must remain untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_delta_surface_rejects_swap_before_authority_publication() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let initial = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("repo-a", &initial, GENERATION_INIT)
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(generation)
            .to_bytes()
            .unwrap();

        let repo = directory.path().join("repo-a");
        let visible = repo.join("deltas");
        let detached = repo.join("deltas-detached");
        let replacement = repo.join("deltas-replacement");
        std::fs::create_dir(&replacement).unwrap();
        backend.set_delta_before_authority_commit_hook(move || {
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });

        let error = backend
            .save_delta("repo-a", &delta, generation)
            .expect_err("a swapped delta surface must stop before authority publication");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected delta-surface error: {error}"
        );
        let error = backend
            .load_deltas_since("repo-a", GENERATION_INIT)
            .expect_err("the retained reader must reject the replacement delta surface");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected replaced delta-reader error: {error}"
        );

        let reopened = LocalFileBackend::new(directory.path());
        let (_, reopened_generation) = reopened
            .load_snapshot("repo-a")
            .unwrap()
            .expect("old visible authority remains complete");
        assert_eq!(reopened_generation, generation);
        assert!(
            directory
                .path()
                .join("repo-a/deltas-detached/00000000000000000002.kndd")
                .exists(),
            "the rejected delta targets only the detached retained surface"
        );
        assert!(
            !directory
                .path()
                .join("repo-a/deltas/00000000000000000002.kndd")
                .exists(),
            "the replacement delta surface must remain untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_commit_surface_swap_is_classified_indeterminate_not_uncommitted() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let generation = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let mut next = GraphSnapshot::empty();
        next.admit_artifact_for_test(
            "committed.rs".to_string(),
            crate::types::regular_tree_entry(2),
        );
        let next = next.to_bytes().unwrap();

        let repo = directory.path().join("repo-a");
        let visible = repo.join("snapshots");
        let detached = repo.join("snapshots-detached");
        let replacement = repo.join("snapshots-replacement");
        backend.set_snapshot_after_authority_commit_hook(move || {
            copy_test_directory(&visible, &replacement);
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });
        let error = backend
            .save_snapshot("repo-a", &next, generation)
            .expect_err("post-commit surface confirmation must report uncertainty");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "committed authority must never be reported as not committed: {error}"
        );

        let reopened = LocalFileBackend::new(directory.path());
        let (bytes, reopened_generation) = reopened
            .load_snapshot("repo-a")
            .unwrap()
            .expect("replacement carries the committed exact snapshot");
        assert_eq!(reopened_generation, generation + 1);
        assert_eq!(bytes, next);
    }

    #[cfg(unix)]
    #[test]
    fn exact_snapshot_retry_never_returns_a_freeze_for_a_swapped_surface() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        assert_eq!(generation, 1);

        let repo = directory.path().join("repo-a");
        let visible = repo.join("snapshots");
        let detached = repo.join("snapshots-detached");
        let replacement = repo.join("snapshots-replacement");
        copy_test_directory(&visible, &replacement);
        backend.set_snapshot_retry_before_confirmation_hook(move || {
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });

        let error = backend
            .save_snapshot_and_freeze(
                "repo-a",
                &snapshot,
                SnapshotCursor::from_backend_generation(GENERATION_INIT),
                None,
            )
            .expect_err("an exact retry must not return a freeze for a detached surface epoch");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "an already-committed exact retry must report uncertainty after a surface swap: {error}"
        );

        let reopened = LocalFileBackend::new(directory.path());
        let (bytes, reopened_generation) = reopened
            .load_snapshot("repo-a")
            .unwrap()
            .expect("a fresh backend may bind the still-complete visible epoch");
        assert_eq!(reopened_generation, generation);
        assert_eq!(bytes, snapshot);
    }

    #[cfg(unix)]
    #[test]
    fn authority_load_rejects_snapshot_surface_swapped_during_deferred_cleanup() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        let snapshots = directory.path().join("repo-a/snapshots");
        std::fs::copy(
            snapshots.join(format!("{generation:020}.kndb")),
            snapshots.join("00000000000000000000.kndb"),
        )
        .unwrap();

        let visible = snapshots;
        let detached = directory.path().join("repo-a/snapshots-detached");
        let replacement = directory.path().join("repo-a/snapshots-replacement");
        backend.set_snapshot_cleanup_before_confirmation_hook(move || {
            copy_test_directory(&visible, &replacement);
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });

        let error = backend
            .load_snapshot("repo-a")
            .expect_err("authority bytes from a detached cleanup epoch must not be returned");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected cleanup-swap error: {error}"
        );

        let reopened = LocalFileBackend::new(directory.path());
        let (bytes, reopened_generation) = reopened
            .load_snapshot("repo-a")
            .unwrap()
            .expect("a fresh backend may bind the replacement snapshot surface");
        assert_eq!(reopened_generation, generation);
        assert_eq!(bytes, snapshot);
    }

    #[cfg(unix)]
    #[test]
    fn authority_post_rename_verification_failure_is_classified_indeterminate() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let generation = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let mut next = GraphSnapshot::empty();
        next.admit_artifact_for_test(
            "committed.rs".to_string(),
            crate::types::regular_tree_entry(9),
        );
        let next = next.to_bytes().unwrap();
        let authority_path = directory.path().join("repo-a/authority.json");
        let installed_copy = directory.path().join("installed-authority.json");
        backend.set_snapshot_before_authority_commit_hook(move || {
            mmap::set_promotion_after_target_rename_hook(move || {
                std::fs::copy(&authority_path, &installed_copy).unwrap();
                std::fs::write(&authority_path, b"post-rename tamper").unwrap();
            });
        });

        let outcome = backend.save_snapshot_classified(
            "repo-a",
            &next,
            SnapshotCursor::from_backend_generation(generation),
        );
        assert!(
            matches!(outcome, SnapshotSaveOutcome::Indeterminate(_)),
            "no post-rename verification failure may be reported as not committed: {outcome:?}"
        );
        let installed: LocalAuthorityRecord = serde_json::from_slice(
            &std::fs::read(directory.path().join("installed-authority.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(installed.head_generation, generation + 1);
    }

    #[cfg(unix)]
    #[test]
    fn retained_overlay_surface_rejects_swap_and_session_traversal() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        backend
            .save_overlay("repo-a", "session-a", b"retained")
            .unwrap();
        for invalid in [
            "",
            "..",
            "../authority",
            "nested/session",
            "CON",
            "trailing.",
            "Upper",
        ] {
            let error = backend
                .save_overlay("repo-a", invalid, b"invalid")
                .expect_err("overlay identifiers must be one portable component");
            assert!(
                error.to_string().contains("overlay session id"),
                "unexpected overlay validation error for {invalid:?}: {error}"
            );
        }
        let oversized = "a".repeat(mmap::MAX_ATOMIC_DESTINATION_LEAF_BYTES - ".bin".len() + 1);
        let error = backend
            .save_overlay("repo-a", &oversized, b"invalid")
            .expect_err("overlay names must reserve room for every atomic recovery suffix");
        assert!(
            error
                .to_string()
                .contains("recovery-staging filename budget"),
            "unexpected oversized overlay error: {error}"
        );

        let repo = directory.path().join("repo-a");
        let visible = repo.join("overlays");
        let detached = repo.join("overlays-detached");
        let replacement = repo.join("overlays-replacement");
        copy_test_directory(&visible, &replacement);
        backend.set_overlay_after_write_hook(move || {
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });
        let error = backend
            .save_overlay("repo-a", "session-b", b"detached only")
            .expect_err("a swapped overlay surface must fail closed");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected overlay-surface error: {error}"
        );
        let error = backend
            .load_overlay("repo-a", "session-a")
            .expect_err("the retained reader must reject the replacement overlay surface");
        assert!(
            error.to_string().contains("repository surface")
                && error.to_string().contains("changed"),
            "unexpected replaced overlay-reader error: {error}"
        );

        let reopened = LocalFileBackend::new(directory.path());
        assert_eq!(
            reopened.load_overlay("repo-a", "session-a").unwrap(),
            Some(b"retained".to_vec())
        );
        assert_eq!(reopened.load_overlay("repo-a", "session-b").unwrap(), None);
        assert!(
            directory
                .path()
                .join("repo-a/overlays-detached/session-b.bin")
                .exists(),
            "the rejected overlay write targets only the detached retained surface"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_directory_lock_serializes_across_lock_marker_replacement() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let freeze = backend.freeze_existing_authority("repo-a").unwrap();

        let repo = directory.path().join("repo-a");
        std::fs::rename(repo.join(".lock"), repo.join(".lock-detached")).unwrap();
        std::fs::write(repo.join(".lock"), b"replacement marker").unwrap();
        let competing = LocalFileBackend::new(directory.path());
        let namespace = competing
            .repository_capability("repo-a", false)
            .unwrap()
            .unwrap();
        let marker = LocalFileBackend::open_repository_lock(&namespace, false).unwrap();
        LocalFileBackend::pin_repository_lock_identity(&namespace, &marker).unwrap();
        let lock_target = LocalFileBackend::repository_lock_target(&namespace, &marker).unwrap();
        use fs2::FileExt;
        assert!(
            lock_target.try_lock_exclusive().is_err(),
            "a replacement lock marker must not create a second lock epoch"
        );

        drop(freeze);
        lock_target
            .lock_exclusive()
            .expect("the replacement-marker backend acquires the repository lock after release");
        FileExt::unlock(&lock_target).unwrap();
        competing
            .save_overlay("repo-a", "serialized", b"after freeze")
            .unwrap();
        let error = backend
            .load_snapshot("repo-a")
            .expect_err("the original backend must reject its replaced marker identity");
        assert!(
            error.to_string().contains("lock") && error.to_string().contains("changed since"),
            "unexpected replaced-lock error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_lock_publication_sync_pins_the_first_marker_epoch() {
        let directory = TempDir::new().unwrap();
        let repository = directory.path().join("repo-a");
        std::fs::create_dir(&repository).unwrap();
        std::fs::write(repository.join("preexisting"), b"retain namespace").unwrap();
        let backend = LocalFileBackend::new(directory.path());

        mmap::fail_parent_sync_after(0);
        let first_error = backend
            .acquire_lock("repo-a")
            .expect_err("the first lock marker publication sync is deliberately failed");
        assert!(first_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(backend
            .repository_namespaces
            .lock()
            .get("repo-a")
            .unwrap()
            .lock_identity
            .lock()
            .is_some());

        std::fs::rename(repository.join(".lock"), repository.join(".lock-detached")).unwrap();
        std::fs::File::create(repository.join(".lock")).unwrap();
        let retry_error = backend
            .acquire_lock("repo-a")
            .expect_err("same backend must not pin a replacement lock marker after sync failure");
        assert!(
            retry_error.to_string().contains("lock")
                && retry_error.to_string().contains("changed since"),
            "unexpected lock-publication retry error: {retry_error}"
        );
    }

    #[test]
    fn listing_does_not_retain_every_discovered_repository_or_stray_directory() {
        let directory = TempDir::new().unwrap();
        let writer = LocalFileBackend::new(directory.path());
        writer
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        drop(writer);
        for index in 0..128 {
            std::fs::create_dir(directory.path().join(format!("stray-{index:03}"))).unwrap();
        }

        let lister = LocalFileBackend::new(directory.path());
        assert_eq!(lister.list_repos().unwrap(), vec!["repo-a".to_string()]);
        assert!(
            lister.repository_namespaces.lock().is_empty(),
            "read-only discovery must not pin every repository or stray child"
        );
    }

    #[test]
    fn listing_never_confirms_or_removes_an_authority_recovery_marker() {
        let directory = TempDir::new().unwrap();
        let writer = LocalFileBackend::new(directory.path());
        writer.fail_next_snapshot_parent_sync_after_install();
        let error = writer
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("authority installation is deliberately left unconfirmed");
        assert!(matches!(
            error,
            KinDbError::SnapshotPersistenceIndeterminate(_)
        ));
        let authority = directory.path().join("repo-a/authority.json");
        let marker = mmap::recovery_marker_path(&authority);
        assert!(marker.exists());

        let lister = LocalFileBackend::new(directory.path());
        assert_eq!(lister.list_repos().unwrap(), vec!["repo-a".to_string()]);
        assert!(
            marker.exists(),
            "read-only repository discovery must not mutate authority recovery state"
        );
        assert!(lister.repository_namespaces.lock().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn initial_repository_bind_rejects_preopen_namespace_replacement() {
        let directory = TempDir::new().unwrap();
        let visible = directory.path().join("repo-a");
        let detached = directory.path().join("repo-a-detached");
        let replacement = directory.path().join("repo-a-replacement");
        std::fs::create_dir(&visible).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let visible_for_swap = visible.clone();
        set_local_directory_after_preopen_hook(LocalDirectoryBindKind::Repository, move || {
            std::fs::rename(&visible_for_swap, &detached).unwrap();
            std::fs::rename(&replacement, &visible_for_swap).unwrap();
        });

        let error = backend
            .existing_repository_path("repo-a")
            .expect_err("initial repository admission must bind one pre/open/post identity");
        assert!(
            error.to_string().contains("local directory namespace")
                && error.to_string().contains("changed"),
            "unexpected initial repository-bind error: {error}"
        );
        assert!(
            backend.repository_namespaces.lock().is_empty(),
            "the replacement epoch must not become the backend's retained identity"
        );
        let fresh = LocalFileBackend::new(directory.path());
        assert_eq!(
            fresh.existing_repository_path("repo-a").unwrap(),
            Some(visible)
        );
    }

    #[cfg(unix)]
    #[test]
    fn initial_surface_bind_rejects_preopen_namespace_replacement() {
        let directory = TempDir::new().unwrap();
        let writer = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        writer
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        drop(writer);

        let backend = LocalFileBackend::new(directory.path());
        backend
            .existing_repository_path("repo-a")
            .unwrap()
            .expect("repository identity is pinned before the surface race");
        let visible = directory.path().join("repo-a/snapshots");
        let detached = directory.path().join("repo-a/snapshots-detached");
        let replacement = directory.path().join("repo-a/snapshots-replacement");
        copy_test_directory(&visible, &replacement);
        set_local_directory_after_preopen_hook(LocalDirectoryBindKind::Surface, move || {
            std::fs::rename(&visible, &detached).unwrap();
            std::fs::rename(&replacement, &visible).unwrap();
        });

        let error = backend
            .load_snapshot("repo-a")
            .expect_err("initial surface admission must bind one pre/open/post identity");
        assert!(
            error.to_string().contains("local directory namespace")
                && error.to_string().contains("changed"),
            "unexpected initial surface-bind error: {error}"
        );
        let namespace = backend.repository_namespaces.lock();
        let repo = namespace.get("repo-a").unwrap();
        assert!(
            repo.surface_directories.lock().is_empty(),
            "the replacement surface epoch must not become retained"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_creation_retains_the_randomized_epoch_it_publishes() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let visible = directory.path().join("repo-a");
        let detached = directory.path().join("repo-a-detached");
        let replacement = directory.path().join("repo-a-replacement");
        std::fs::create_dir(&replacement).unwrap();
        let visible_for_swap = visible.clone();
        set_local_directory_after_preopen_hook(LocalDirectoryBindKind::Repository, move || {
            std::fs::rename(&visible_for_swap, &detached).unwrap();
            std::fs::rename(&replacement, &visible_for_swap).unwrap();
        });

        let error = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("repository creation must not admit a post-publication replacement");
        assert!(
            error
                .to_string()
                .contains("newly published local directory namespace")
                && error.to_string().contains("replaced"),
            "unexpected repository-creation race error: {error}"
        );
        assert!(
            backend.repository_namespaces.lock().is_empty(),
            "the replacement repository epoch must not be retained"
        );
        assert!(
            backend
                .poisoned_repository_namespaces
                .lock()
                .contains_key("repo-a"),
            "the displaced published epoch must poison same-backend admission"
        );
        assert_eq!(
            std::fs::read_dir(&visible).unwrap().count(),
            0,
            "the rejected creator must not write a lock or authority into the replacement"
        );
        let retry_error = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("same backend must never bind the replacement repository epoch");
        assert!(
            retry_error
                .to_string()
                .contains("displaced during creation")
                && retry_error
                    .to_string()
                    .contains("will not bind a replacement epoch"),
            "unexpected repository-creation retry error: {retry_error}"
        );
        assert_eq!(
            std::fs::read_dir(&visible).unwrap().count(),
            0,
            "same-backend retry must not write into the replacement repository"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_publication_sync_is_retried_before_initialization() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        let repository = directory.path().join("repo-a");

        mmap::fail_parent_sync_after(1);
        let first_error = backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .expect_err("repository publication must not proceed after its parent sync fails");
        assert!(first_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(repository.is_dir());
        assert!(!repository.join(".lock").exists());
        assert!(backend
            .repository_namespaces
            .lock()
            .get("repo-a")
            .unwrap()
            .publication_sync_pending
            .load(std::sync::atomic::Ordering::SeqCst));

        mmap::fail_parent_sync_after(0);
        let retry_error = backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .expect_err("retry must repeat the failed repository publication sync");
        assert!(retry_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(
            !repository.join(".lock").exists(),
            "repository initialization must wait for publication durability"
        );

        assert_eq!(
            backend
                .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
                .unwrap(),
            GENERATION_INIT + 1
        );
        assert!(repository.join(".lock").is_file());
        assert!(!backend
            .repository_namespaces
            .lock()
            .get("repo-a")
            .unwrap()
            .publication_sync_pending
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn empty_repository_publication_is_reconfirmed_after_backend_reopen() {
        let directory = TempDir::new().unwrap();
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        let repository = directory.path().join("repo-a");
        {
            let backend = LocalFileBackend::new(directory.path());
            mmap::fail_parent_sync_after(1);
            backend
                .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
                .expect_err("repository publication is deliberately left unconfirmed");
        }
        assert!(repository.is_dir());
        assert!(!repository.join(".lock").exists());

        let reopened = LocalFileBackend::new(directory.path());
        mmap::fail_parent_sync_after(0);
        let reopen_error = reopened
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .expect_err("an empty visible repository must be conservatively reconfirmed");
        assert!(reopen_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(!repository.join(".lock").exists());

        assert_eq!(
            reopened
                .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
                .unwrap(),
            GENERATION_INIT + 1
        );
        assert!(repository.join(".lock").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn surface_creation_retains_the_randomized_epoch_it_publishes() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        initialize_local_repository_namespace(&backend, "repo-a");
        let visible = directory.path().join("repo-a/snapshots");
        let detached = directory.path().join("repo-a/snapshots-detached");
        let replacement = directory.path().join("repo-a/snapshots-replacement");
        std::fs::create_dir(&replacement).unwrap();
        let visible_for_swap = visible.clone();
        set_local_directory_after_preopen_hook(LocalDirectoryBindKind::Surface, move || {
            std::fs::rename(&visible_for_swap, &detached).unwrap();
            std::fs::rename(&replacement, &visible_for_swap).unwrap();
        });

        let error = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("surface creation must not admit a post-publication replacement");
        assert!(
            error
                .to_string()
                .contains("newly published local directory namespace")
                && error.to_string().contains("replaced"),
            "unexpected surface-creation race error: {error}"
        );
        assert_eq!(
            std::fs::read_dir(&visible).unwrap().count(),
            0,
            "the rejected creator must not write snapshot bytes into the replacement surface"
        );
        let namespace = backend.repository_namespaces.lock();
        assert!(
            namespace
                .get("repo-a")
                .unwrap()
                .surface_directories
                .lock()
                .is_empty(),
            "the replacement surface epoch must not be retained"
        );
        assert!(
            namespace
                .get("repo-a")
                .unwrap()
                .poisoned_surfaces
                .lock()
                .contains_key("snapshots"),
            "the displaced published surface epoch must poison same-backend admission"
        );
        drop(namespace);
        let retry_error = backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("same backend must never bind the replacement surface epoch");
        assert!(
            retry_error
                .to_string()
                .contains("displaced during creation")
                && retry_error
                    .to_string()
                    .contains("will not bind a replacement epoch"),
            "unexpected surface-creation retry error: {retry_error}"
        );
        assert_eq!(
            std::fs::read_dir(&visible).unwrap().count(),
            0,
            "same-backend retry must not write into the replacement surface"
        );
    }

    #[cfg(unix)]
    #[test]
    fn no_replace_publication_refuses_an_occupied_directory_name() {
        let directory = TempDir::new().unwrap();
        let parent =
            cap_std::fs::Dir::open_ambient_dir(directory.path(), cap_std::ambient_authority())
                .expect("the temporary parent namespace opens");
        parent.create_dir("stage").unwrap();
        parent.create_dir("published").unwrap();
        let occupant = LocalFileBackend::local_directory_entry_identity(
            &parent,
            "published".as_ref(),
            Path::new("published"),
        )
        .unwrap()
        .expect("the occupied target name holds a directory");
        let staged = LocalFileBackend::local_directory_entry_identity(
            &parent,
            "stage".as_ref(),
            Path::new("stage"),
        )
        .unwrap()
        .expect("the staged name holds a directory");

        assert!(
            !LocalFileBackend::rename_local_directory_no_replace(
                &parent,
                "stage".as_ref(),
                "published".as_ref(),
            )
            .expect("an occupied target name is a refusal, not a failure"),
            "publication must refuse a target name another directory already holds"
        );
        assert_eq!(
            LocalFileBackend::local_directory_entry_identity(
                &parent,
                "published".as_ref(),
                Path::new("published"),
            )
            .unwrap(),
            Some(occupant),
            "the refused publication must leave the occupant's exact epoch in place"
        );
        assert_eq!(
            LocalFileBackend::local_directory_entry_identity(
                &parent,
                "stage".as_ref(),
                Path::new("stage"),
            )
            .unwrap(),
            Some(staged),
            "the refused stage must survive for its caller to report a competing target"
        );

        assert!(
            LocalFileBackend::rename_local_directory_no_replace(
                &parent,
                "stage".as_ref(),
                "unoccupied".as_ref(),
            )
            .expect("an unoccupied target name publishes"),
            "publication must succeed onto a name no directory holds"
        );
        assert_eq!(
            LocalFileBackend::local_directory_entry_identity(
                &parent,
                "unoccupied".as_ref(),
                Path::new("unoccupied"),
            )
            .unwrap(),
            Some(staged),
            "the published name must carry the exact staged epoch"
        );
        assert_eq!(
            LocalFileBackend::local_directory_entry_identity(
                &parent,
                "stage".as_ref(),
                Path::new("stage"),
            )
            .unwrap(),
            None,
            "the staged name must be free once its epoch is published"
        );
    }

    #[cfg(unix)]
    #[test]
    fn surface_publication_sync_is_retried_before_use() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        initialize_local_repository_namespace(&backend, "repo-a");
        let namespace = backend
            .repository_capability("repo-a", false)
            .unwrap()
            .unwrap();
        let surface_path = directory.path().join("repo-a/snapshots");

        mmap::fail_parent_sync_after(1);
        let first_error = namespace
            .surface(LocalFileBackend::snapshots_surface_name(), true)
            .expect_err("surface publication must not proceed after its parent sync fails");
        assert!(first_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(surface_path.is_dir());
        assert_eq!(std::fs::read_dir(&surface_path).unwrap().count(), 0);
        assert!(namespace
            .surface_directories
            .lock()
            .get(LocalFileBackend::snapshots_surface_name())
            .unwrap()
            .publication_sync_pending
            .load(std::sync::atomic::Ordering::SeqCst));

        mmap::fail_parent_sync_after(0);
        let retry_error = namespace
            .surface(LocalFileBackend::snapshots_surface_name(), true)
            .expect_err("retry must repeat the failed surface publication sync");
        assert!(retry_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert_eq!(
            std::fs::read_dir(&surface_path).unwrap().count(),
            0,
            "surface payloads must wait for publication durability"
        );

        let surface = namespace
            .surface(LocalFileBackend::snapshots_surface_name(), true)
            .unwrap()
            .unwrap();
        assert!(!surface
            .publication_sync_pending
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn case_alias_cannot_bind_one_directory_as_two_repository_ids() {
        let directory = TempDir::new().unwrap();
        let writer = LocalFileBackend::new(directory.path());
        writer
            .save_snapshot(
                "Repo",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        drop(writer);
        if !directory.path().join("repo").is_dir() {
            return;
        }

        let backend = LocalFileBackend::new(directory.path());
        let error = backend
            .load_snapshot("repo")
            .expect_err("case aliases must not bind one directory as two repositories");
        assert!(
            error
                .to_string()
                .contains("aliases existing directory name"),
            "unexpected repository-alias error: {error}"
        );
        assert!(backend.load_snapshot("Repo").unwrap().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_repository_handle_prevents_namespace_replacement() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &snapshot, GENERATION_INIT)
            .unwrap();
        backend
            .existing_repository_path("repo-a")
            .unwrap()
            .expect("repository handle is retained");

        let error = std::fs::rename(
            directory.path().join("repo-a"),
            directory.path().join("detached"),
        )
        .expect_err("Windows capability omits DELETE sharing");
        assert_eq!(
            error.raw_os_error(),
            Some(32),
            "expected Windows ERROR_SHARING_VIOLATION, got: {error}"
        );
        assert!(directory.path().join("repo-a").is_dir());
        assert!(!directory.path().join("detached").exists());
        assert!(backend.load_snapshot("repo-a").unwrap().is_some());
    }

    #[test]
    fn local_backend_roundtrip_snapshot() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // No snapshot yet
        assert!(backend.load_snapshot("test-repo").unwrap().is_none());

        // Create and save a snapshot
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let new_gen = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert_eq!(new_gen, 1);

        // Load it back
        let (loaded_bytes, gen) = backend.load_snapshot("test-repo").unwrap().unwrap();
        assert_eq!(gen, 1);
        let loaded = GraphSnapshot::from_bytes(&loaded_bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn local_backend_cas_rejects_stale_generation() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();

        // First write succeeds
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert_eq!(gen1, 1);

        // Second write with correct generation succeeds with different bytes.
        let mut replacement = GraphSnapshot::empty();
        replacement.admit_artifact_for_test(
            "replacement.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let replacement_bytes = replacement.to_bytes().unwrap();
        let gen2 = backend
            .save_snapshot("test-repo", &replacement_bytes, gen1)
            .unwrap();
        assert_eq!(gen2, 2);

        // Write with stale generation fails
        let err = backend
            .save_snapshot("test-repo", &bytes, gen1)
            .unwrap_err();
        assert!(err.to_string().contains("generation mismatch"));
    }

    #[test]
    fn local_backend_overlay_roundtrip() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        initialize_local_repository_namespace(&backend, "test-repo");

        // No overlay yet
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_none());

        // Save overlay
        let overlay_data = b"overlay state bytes";
        backend
            .save_overlay("test-repo", "session-1", overlay_data)
            .unwrap();

        // Load it back
        let loaded = backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, overlay_data);
    }

    #[test]
    fn local_backend_delete_overlay() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        initialize_local_repository_namespace(&backend, "test-repo");

        // Save an overlay
        backend
            .save_overlay("test-repo", "session-1", b"overlay data")
            .unwrap();
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_some());

        // Delete it
        backend.delete_overlay("test-repo", "session-1").unwrap();
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_none());

        // Deleting a non-existent overlay is a no-op
        backend.delete_overlay("test-repo", "session-1").unwrap();
    }

    #[test]
    fn local_backend_save_snapshot_writes_raw_bytes() {
        // Verify that save_snapshot writes the exact input bytes (no re-serialization).
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Read the immutable authority target directly and confirm byte-for-byte match.
        let on_disk = std::fs::read(backend.versioned_snapshot_path("test-repo", 1)).unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn local_backend_save_and_load_delta() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create initial snapshot
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Save a delta
        let mut delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        delta.resolved_tree.added.push((
            crate::types::ArtifactId::new(),
            crate::types::LocatedEntry::new(
                crate::types::RepoPath::from_utf8("new.rs").unwrap(),
                crate::types::regular_tree_entry(42),
            ),
        ));
        let delta_bytes = delta.to_bytes().unwrap();
        let gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();
        assert_eq!(gen2, 2);

        // Load deltas since gen1
        let loaded = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, gen2);

        let loaded_delta =
            crate::storage::delta::GraphSnapshotDelta::from_bytes(&loaded[0].0).unwrap();
        assert_eq!(loaded_delta.resolved_tree.added.len(), 1);

        // No deltas since gen2
        let empty = backend.load_deltas_since("test-repo", gen2).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn local_snapshot_tuple_describes_base_while_authority_tracks_head() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "generation-bytes";
        let mut base = GraphSnapshot::empty();
        base.admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));
        let base_bytes = base.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo_id, &base_bytes, GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .admit_artifact_for_test("delta.rs".to_string(), crate::types::regular_tree_entry(2));
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        let (loaded, generation) = backend.load_snapshot(repo_id).unwrap().unwrap();
        assert_eq!(loaded, base_bytes);
        assert_eq!(generation, gen1);
        let authority = backend.load_snapshot_authority(repo_id).unwrap().unwrap();
        assert_eq!(authority.snapshot_generation, gen1);
        assert_eq!(authority.head_generation, gen2);
    }

    #[test]
    fn local_base_authority_reports_only_exact_selected_snapshot_bytes() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "base-payload-receipt";
        let mut snapshot = GraphSnapshot::empty();
        snapshot
            .admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));
        let snapshot_bytes = snapshot.to_bytes().unwrap();
        let generation = backend
            .save_snapshot(repo_id, &snapshot_bytes, GENERATION_INIT)
            .unwrap();

        let stats = recovered_payload_stats(&backend, repo_id).unwrap();
        assert_eq!(stats.snapshot_generation(), generation);
        assert_eq!(stats.head_generation(), generation);
        assert_eq!(stats.snapshot_bytes(), snapshot_bytes.len() as u64);
        assert_eq!(stats.acknowledged_delta_count(), 0);
        assert_eq!(stats.acknowledged_delta_bytes(), 0);
        assert_eq!(stats.total_payload_bytes(), snapshot_bytes.len() as u64);
    }

    #[test]
    fn local_backend_recovery_replays_sequential_deltas_after_reopen() {
        let dir = TempDir::new().unwrap();
        let repo_id = "restart-repo";
        let mut base = GraphSnapshot::empty();
        base.admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));
        let base_bytes = base.to_bytes().unwrap();

        let (first_delta_bytes, second_delta_bytes) = {
            let backend = LocalFileBackend::new(dir.path());
            let gen1 = backend
                .save_snapshot(repo_id, &base_bytes, GENERATION_INIT)
                .unwrap();

            let mut after_first = base.clone();
            after_first.admit_artifact_for_test(
                "first.rs".to_string(),
                crate::types::regular_tree_entry(2),
            );
            let first_delta = crate::storage::delta::compute_graph_delta(&base, &after_first, gen1);
            let first_delta_bytes = first_delta.to_bytes().unwrap();
            let gen2 = backend
                .save_delta(repo_id, &first_delta_bytes, gen1)
                .unwrap();

            let mut after_second = after_first.clone();
            after_second.admit_artifact_for_test(
                "second.rs".to_string(),
                crate::types::regular_tree_entry(3),
            );
            let second_delta =
                crate::storage::delta::compute_graph_delta(&after_first, &after_second, gen2);
            let second_delta_bytes = second_delta.to_bytes().unwrap();
            let gen3 = backend
                .save_delta(repo_id, &second_delta_bytes, gen2)
                .unwrap();
            assert_eq!(gen3, 3);
            (first_delta_bytes, second_delta_bytes)
        };

        let reopened = LocalFileBackend::new(dir.path());
        let recovered_authority = load_recovered_repository_authority(&reopened, repo_id, 0)
            .unwrap()
            .expect("base snapshot exists");
        let stats = recovered_authority.payload_stats;
        let recovered = recovered_authority.recovered;
        assert_eq!(recovered.generation, 3);
        assert_eq!(recovered.deltas_seen, 2);
        assert_eq!(recovered.deltas_applied, 2);
        assert_eq!(recovered.snapshot.resolved_tree.len(), 3);
        assert!(recovered.snapshot.has_artifact_path_for_test("base.rs"));
        assert!(recovered.snapshot.has_artifact_path_for_test("first.rs"));
        assert!(recovered.snapshot.has_artifact_path_for_test("second.rs"));
        let acknowledged_delta_bytes = (first_delta_bytes.len() + second_delta_bytes.len()) as u64;
        assert_eq!(stats.snapshot_generation(), 1);
        assert_eq!(stats.head_generation(), 3);
        assert_eq!(stats.snapshot_bytes(), base_bytes.len() as u64);
        assert_eq!(stats.acknowledged_delta_count(), 2);
        assert_eq!(stats.acknowledged_delta_bytes(), acknowledged_delta_bytes);
        assert_eq!(
            stats.total_payload_bytes(),
            base_bytes.len() as u64 + acknowledged_delta_bytes
        );
    }

    #[test]
    fn staged_delta_above_head_is_seen_but_not_counted() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "staged-payload-receipt";
        let snapshot_bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let head = backend
            .save_snapshot(repo_id, &snapshot_bytes, GENERATION_INIT)
            .unwrap();
        let staged = crate::storage::delta::GraphSnapshotDelta::empty(head)
            .to_bytes()
            .unwrap();
        LocalFileBackend::atomic_write(&backend.delta_path(repo_id, head + 1), &staged).unwrap();

        let recovered = load_recovered_repository_authority(&backend, repo_id, 0)
            .unwrap()
            .expect("the base authority remains recoverable");
        assert_eq!(recovered.recovered.deltas_seen, 1);
        assert_eq!(recovered.recovered.deltas_applied, 0);
        let stats = recovered.payload_stats;
        assert_eq!(stats.snapshot_generation(), head);
        assert_eq!(stats.head_generation(), head);
        assert_eq!(stats.snapshot_bytes(), snapshot_bytes.len() as u64);
        assert_eq!(stats.acknowledged_delta_count(), 0);
        assert_eq!(stats.acknowledged_delta_bytes(), 0);
        assert_eq!(stats.total_payload_bytes(), snapshot_bytes.len() as u64);
    }

    #[test]
    fn initial_full_save_must_reject_journal_without_current_authority() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "initial-save-unbound-journal";
        initialize_local_repository_namespace(&backend, repo_id);
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, 1),
            &crate::storage::delta::GraphSnapshotDelta::empty(GENERATION_INIT)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = backend
            .save_snapshot(
                repo_id,
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("initial full save must not create authority over an unbound journal");
        assert!(error
            .to_string()
            .contains("deltas but no current snapshot authority"));
        assert!(!backend.authority_path(repo_id).exists());
        assert!(backend.delta_path(repo_id, 1).exists());
    }

    #[test]
    fn local_backend_accepts_only_the_exact_current_authority_shape() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "exact-current-authority";
        backend
            .save_snapshot(
                repo_id,
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let authority_path = backend.authority_path(repo_id);
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();

        for rejected_version in [1, 2] {
            let mut candidate = current.clone();
            candidate["version"] = serde_json::json!(rejected_version);
            LocalFileBackend::atomic_write(
                &authority_path,
                &serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
            let error = backend
                .load_snapshot_authority(repo_id)
                .expect_err("old authority versions must not be migrated");
            assert!(
                error
                    .to_string()
                    .contains("unsupported local authority version"),
                "unexpected old-version error: {error}"
            );
        }

        for required_field in ["acknowledged_deltas", "retired_deltas"] {
            let mut candidate = current.clone();
            candidate.as_object_mut().unwrap().remove(required_field);
            LocalFileBackend::atomic_write(
                &authority_path,
                &serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
            let error = backend
                .load_snapshot_authority(repo_id)
                .expect_err("current authority identity arrays are required");
            assert!(
                error.to_string().contains(required_field),
                "unexpected missing-field error for {required_field}: {error}"
            );
        }
    }

    #[test]
    fn local_atomic_authority_rejects_reserved_generation_delta_artifact() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "reserved-delta-generation";
        backend
            .save_snapshot(
                repo_id,
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, GENERATION_INIT),
            &crate::storage::delta::GraphSnapshotDelta::empty(GENERATION_INIT)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("reserved generation-0 journal artifacts must fail closed");
        assert!(error.to_string().contains("reserved or noncanonical"));
    }

    #[test]
    fn local_atomic_authority_rejects_replaced_acknowledged_delta_at_same_head() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "replaced-acknowledged-delta";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.admit_artifact_for_test(
            "committed.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let committed = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &committed.to_bytes().unwrap(), gen1)
            .unwrap();

        // Replacing the deterministic generation filename without moving
        // current authority must fail exact-byte validation.
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen2),
            &replacement.to_bytes().unwrap(),
        )
        .unwrap();
        let error = recovered_payload_stats(&backend, repo_id)
            .expect_err("replaced acknowledged bytes must return no payload receipt");
        assert!(error
            .to_string()
            .contains("acknowledged delta digest mismatch"));
    }

    #[test]
    fn local_recovery_validates_the_exact_delta_bytes_it_returns() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "recovery-read-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.admit_artifact_for_test(
            "committed.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let committed = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &committed.to_bytes().unwrap(), gen1)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, gen2);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        backend.set_recovery_after_authority_hook(move || {
            LocalFileBackend::atomic_write(&delta_path, &replacement).unwrap();
        });

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("recovery must hash the same bytes it is about to return and replay");
        assert!(
            error.to_string().contains("while loading recovery bytes"),
            "unexpected recovery race error: {error}"
        );
    }

    #[test]
    fn local_recovery_revalidates_retired_delta_replaced_after_authority_read() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "retired-recovery-read-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.admit_artifact_for_test(
            "retired.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, gen2);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        backend.set_recovery_after_authority_hook(move || {
            LocalFileBackend::atomic_write(&delta_path, &replacement).unwrap();
        });

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("retired bytes replaced after manifest validation must fail closed");
        assert!(
            error.to_string().contains("retired delta digest mismatch"),
            "unexpected retired recovery race error: {error}"
        );
    }

    #[test]
    fn local_backend_recovery_does_not_reapply_stale_deltas_after_full_promotion() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "promoted-repo";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();

        let mut current = base.clone();
        current.admit_artifact_for_test(
            "current.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let delta_bytes = delta.to_bytes().unwrap();
        let gen2 = backend.save_delta(repo_id, &delta_bytes, gen1).unwrap();

        // Model a crash after full snapshot promotion but before clear_deltas.
        let current_bytes = current.to_bytes().unwrap();
        let gen3 = backend
            .save_snapshot(repo_id, &current_bytes, gen2)
            .unwrap();
        assert_eq!(gen3, 3);
        assert!(
            backend.delta_path(repo_id, gen2).exists(),
            "the retired acknowledged delta remains visible until cleanup"
        );
        let selected_snapshot = backend.versioned_snapshot_path(repo_id, gen3);
        std::fs::copy(
            &selected_snapshot,
            backend.versioned_snapshot_path(repo_id, gen1),
        )
        .unwrap();
        std::fs::copy(
            &selected_snapshot,
            backend.versioned_snapshot_path(repo_id, gen3 + 1),
        )
        .unwrap();

        let recovered_authority = load_recovered_repository_authority(&backend, repo_id, 0)
            .unwrap()
            .expect("promoted snapshot exists");
        let stats = recovered_authority.payload_stats;
        let recovered = recovered_authority.recovered;
        assert_eq!(recovered.generation, gen3);
        assert_eq!(recovered.deltas_seen, 0);
        assert_eq!(recovered.deltas_applied, 0);
        assert_eq!(recovered.snapshot.resolved_tree.len(), 1);
        assert!(recovered.snapshot.has_artifact_path_for_test("current.rs"));
        assert_eq!(stats.snapshot_generation(), gen3);
        assert_eq!(stats.head_generation(), gen3);
        assert_eq!(stats.snapshot_bytes(), current_bytes.len() as u64);
        assert_eq!(stats.acknowledged_delta_count(), 0);
        assert_eq!(stats.acknowledged_delta_bytes(), 0);
        assert_eq!(stats.total_payload_bytes(), current_bytes.len() as u64);
        assert!(
            backend.versioned_snapshot_path(repo_id, gen3 + 1).exists(),
            "a newer staged snapshot may remain visible but is not selected or counted"
        );
    }

    #[test]
    fn local_backend_clear_deltas() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Save two deltas
        let empty_delta = crate::storage::delta::compute_graph_delta(
            &GraphSnapshot::empty(),
            &GraphSnapshot::empty(),
            gen1,
        );
        let delta_bytes = empty_delta.to_bytes().unwrap();
        let gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();
        let second_delta = crate::storage::delta::GraphSnapshotDelta::empty(gen2);
        backend
            .save_delta("test-repo", &second_delta.to_bytes().unwrap(), gen2)
            .unwrap();

        // Should have 2 deltas
        let deltas = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert_eq!(deltas.len(), 2);

        let error = backend
            .clear_deltas("test-repo")
            .expect_err("authoritative deltas cannot be cleared before promotion");
        assert!(error
            .to_string()
            .contains("refusing to clear authoritative"));

        // Promote the recovered head, then journal cleanup is safe.
        let recovered = load_recovered_snapshot(&backend, "test-repo")
            .unwrap()
            .unwrap();
        backend
            .save_snapshot(
                "test-repo",
                &recovered.snapshot.to_bytes().unwrap(),
                recovered.generation,
            )
            .unwrap();
        backend.clear_deltas("test-repo").unwrap();
        let empty = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn local_snapshot_promotion_crash_before_authority_keeps_old_chain_recoverable() {
        let dir = TempDir::new().unwrap();
        let repo_id = "promotion-crash";
        let backend = LocalFileBackend::new(dir.path());
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .admit_artifact_for_test("delta.rs".to_string(), crate::types::regular_tree_entry(9));
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        backend.fail_next_snapshot_before_authority_commit();
        let error = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect_err("injected inner-window crash must abort before authority commit");
        assert!(error
            .to_string()
            .contains("before local snapshot authority"));
        assert!(backend.versioned_snapshot_path(repo_id, 3).exists());

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("old base plus acknowledged delta remains authoritative");
        assert_eq!(recovered.generation, gen2);
        assert_eq!(recovered.deltas_applied, 1);
        assert!(recovered.snapshot.has_artifact_path_for_test("delta.rs"));

        let gen3 = reopened
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect("retry promotes the staged generation atomically");
        assert_eq!(gen3, 3);
        let promoted = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("promoted snapshot exists");
        assert_eq!(promoted.generation, gen3);
        assert_eq!(promoted.deltas_applied, 0);
        assert!(promoted.snapshot.has_artifact_path_for_test("delta.rs"));
    }

    #[test]
    fn local_full_authority_post_rename_sync_failure_retries_exact_cursor_without_early_gc() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "authority-post-rename-sync";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .admit_artifact_for_test("delta.rs".to_string(), crate::types::regular_tree_entry(9));
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        let old_snapshot = backend.versioned_snapshot_path(repo_id, gen1);
        let delta_path = backend.delta_path(repo_id, gen2);
        backend.set_snapshot_before_authority_commit_hook(|| {
            // Authority candidate publication and exact candidate claim consume
            // two syncs; fail the destination rename sync.
            mmap::fail_parent_sync_after(2);
        });

        let error = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect_err("installed but unconfirmed authority must be reported");
        assert!(error
            .to_string()
            .contains("durability or exact post-install verification is unconfirmed"));
        assert!(mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
        assert!(
            old_snapshot.exists(),
            "old base must not be GC'd before confirmation"
        );
        assert!(
            delta_path.exists(),
            "retired journal must not be GC'd before confirmation"
        );

        let generation = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect("exact retry must confirm and return the installed cursor");
        assert_eq!(generation, gen2 + 1);
        assert!(!mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, generation);
        assert_eq!(recovered.snapshot.resolved_tree, current.resolved_tree);
    }

    #[test]
    fn local_delta_authority_post_rename_sync_failure_retries_exact_cursor() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "delta-authority-post-rename-sync";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        let delta_bytes = delta.to_bytes().unwrap();
        backend.set_delta_before_authority_commit_hook(|| {
            // Authority candidate publication and exact candidate claim
            // consume two syncs; fail the destination rename sync.
            mmap::fail_parent_sync_after(2);
        });

        let error = backend
            .save_delta(repo_id, &delta_bytes, gen1)
            .expect_err("installed but unconfirmed delta authority must be reported");
        assert!(error
            .to_string()
            .contains("durability or exact post-install verification is unconfirmed"));
        assert!(backend.delta_path(repo_id, gen1 + 1).exists());
        assert!(mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());

        let retried = backend
            .save_delta(repo_id, &delta_bytes, gen1)
            .expect("exact retry must confirm installed delta cursor");
        assert_eq!(retried, gen1 + 1);
        assert!(!mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
    }

    #[test]
    fn quarantine_cleanup_waits_for_authoritative_snapshot_payload_verification() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "quarantine-after-payload";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let gen2 = backend.save_delta(repo_id, &delta_bytes, gen1).unwrap();
        let gen3 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen2)
            .unwrap();
        let canonical = backend.delta_path(repo_id, gen2);
        let quarantine = quarantine_delta_path(
            &canonical,
            gen2,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::rename(&canonical, &quarantine).unwrap();
        std::fs::write(backend.versioned_snapshot_path(repo_id, gen3), b"corrupt").unwrap();

        let error = backend
            .load_snapshot(repo_id)
            .expect_err("invalid authority payload must fail before quarantine cleanup");
        assert!(error.to_string().contains("digest mismatch"));
        assert!(
            quarantine.exists(),
            "forensic quarantine must remain after payload failure"
        );
    }

    #[test]
    fn direct_delta_load_finalizes_only_authority_bound_quarantine() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "direct-delta-quarantine";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let gen2 = backend.save_delta(repo_id, &delta_bytes, gen1).unwrap();
        backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen2)
            .unwrap();
        let canonical = backend.delta_path(repo_id, gen2);
        let quarantine = quarantine_delta_path(
            &canonical,
            gen2,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::rename(&canonical, &quarantine).unwrap();

        let deltas = backend
            .load_deltas_since(repo_id, GENERATION_INIT)
            .expect("direct delta load must verify authority then finalize its quarantine");
        assert!(deltas.is_empty());
        assert!(!quarantine.exists());

        let unbound_repo = "unbound-direct-delta-quarantine";
        initialize_local_repository_namespace(&backend, unbound_repo);
        std::fs::create_dir_all(backend.deltas_dir(unbound_repo)).unwrap();
        let unbound_canonical = backend.delta_path(unbound_repo, 1);
        let unbound = quarantine_delta_path(
            &unbound_canonical,
            1,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::write(&unbound, &delta_bytes).unwrap();
        let error = backend
            .load_deltas_since(unbound_repo, GENERATION_INIT)
            .expect_err("quarantine without authority must fail closed");
        assert!(error.to_string().contains("no current snapshot authority"));
        assert!(unbound.exists());
    }

    #[test]
    fn local_full_save_rejects_a_staged_next_delta_before_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "staged-next-before-save";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen1 + 1),
            &crate::storage::delta::GraphSnapshotDelta::empty(gen1)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen1)
            .expect_err("full save must not commit over a staged next-generation delta");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        let lock = backend.acquire_existing_lock(repo_id).unwrap();
        let authority = backend
            .read_authority_record_raw_unlocked(&lock.namespace)
            .unwrap()
            .unwrap();
        assert_eq!(authority.head_generation, gen1);
        assert!(backend.delta_path(repo_id, gen1 + 1).exists());
    }

    #[test]
    fn local_full_save_rechecks_for_a_staged_delta_before_authority_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "staged-next-during-save";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let staged_path = backend.delta_path(repo_id, gen1 + 1);
        backend.set_snapshot_before_authority_commit_hook(move || {
            LocalFileBackend::atomic_write(
                &staged_path,
                &crate::storage::delta::GraphSnapshotDelta::empty(gen1)
                    .to_bytes()
                    .unwrap(),
            )
            .unwrap();
        });

        let error = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen1)
            .expect_err("the pre-commit rescan must catch a staged delta from a racing writer");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        let lock = backend.acquire_existing_lock(repo_id).unwrap();
        let authority = backend
            .read_authority_record_raw_unlocked(&lock.namespace)
            .unwrap()
            .unwrap();
        assert_eq!(authority.head_generation, gen1);
    }

    fn local_backend_with_two_deltas() -> (TempDir, LocalFileBackend, &'static str) {
        let dir = TempDir::new().unwrap();
        let repo_id = "incomplete-chain";
        let backend = LocalFileBackend::new(dir.path());
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let first = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        let gen2 = backend
            .save_delta(repo_id, &first.to_bytes().unwrap(), gen1)
            .unwrap();
        let second = crate::storage::delta::GraphSnapshotDelta::empty(gen2);
        backend
            .save_delta(repo_id, &second.to_bytes().unwrap(), gen2)
            .unwrap();
        (dir, backend, repo_id)
    }

    #[test]
    fn local_recovery_rejects_missing_delta_prefix() {
        let (_dir, backend, repo_id) = local_backend_with_two_deltas();
        std::fs::remove_file(backend.delta_path(repo_id, 2)).unwrap();
        let error = recovered_payload_stats(&backend, repo_id)
            .expect_err("a missing first delta must return no payload receipt");
        assert!(error.to_string().contains("expected generation 2, found 3"));
    }

    #[test]
    fn local_recovery_rejects_missing_delta_head() {
        let (_dir, backend, repo_id) = local_backend_with_two_deltas();
        std::fs::remove_file(backend.delta_path(repo_id, 3)).unwrap();
        let error = recovered_payload_stats(&backend, repo_id)
            .expect_err("a missing acknowledged head must return no payload receipt");
        assert!(error
            .to_string()
            .contains("delta chain ended at generation 2, acknowledged head is 3"));
    }

    #[test]
    fn local_backend_compact_deltas() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create an initial snapshot with one exact tree entry.
        let mut snapshot = GraphSnapshot::empty();
        snapshot.admit_artifact_for_test("old.rs".to_string(), crate::types::regular_tree_entry(1));
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Create a delta that adds a new exact tree entry.
        let mut new_snapshot = snapshot.clone();
        new_snapshot
            .admit_artifact_for_test("new.rs".to_string(), crate::types::regular_tree_entry(2));
        let delta = crate::storage::delta::compute_graph_delta(&snapshot, &new_snapshot, gen1);
        let delta_bytes = delta.to_bytes().unwrap();
        let _gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();

        // Compact: merges delta into snapshot
        let compacted_gen = backend.compact_deltas("test-repo").unwrap();
        assert!(compacted_gen > gen1);

        // No more deltas
        let deltas = backend
            .load_deltas_since("test-repo", GENERATION_INIT)
            .unwrap();
        assert!(deltas.is_empty());

        // Snapshot now contains both exact tree entries.
        let (snap_bytes, _) = backend.load_snapshot("test-repo").unwrap().unwrap();
        let compacted = GraphSnapshot::from_bytes(&snap_bytes).unwrap();
        assert_eq!(compacted.resolved_tree.len(), 2);
        assert!(compacted.has_artifact_path_for_test("old.rs"));
        assert!(compacted.has_artifact_path_for_test("new.rs"));
    }

    #[test]
    fn local_compaction_returns_committed_cursor_when_cleanup_fails() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "cleanup-cursor";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .admit_artifact_for_test("delta.rs".to_string(), crate::types::regular_tree_entry(7));
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let head = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        backend.fail_next_delta_cleanup();

        let committed = backend
            .compact_deltas(repo_id)
            .expect("post-commit cleanup failure must not discard the new cursor");
        assert!(committed > head);
        let authority = backend.load_snapshot_authority(repo_id).unwrap().unwrap();
        assert_eq!(authority.snapshot_generation, committed);
        assert_eq!(authority.head_generation, committed);
        assert!(backend.delta_path(repo_id, head).exists());
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, committed);
        assert_eq!(recovered.snapshot.resolved_tree, current.resolved_tree);
    }

    #[test]
    fn local_compaction_preserves_post_authority_replacement_and_fails_closed() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "compaction-cleanup-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.admit_artifact_for_test(
            "committed.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let committed_delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let delta_generation = backend
            .save_delta(repo_id, &committed_delta.to_bytes().unwrap(), gen1)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, delta_generation);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let expected_replacement = replacement.clone();
        let raced_path = delta_path.clone();
        backend.set_compaction_before_delta_cleanup_hook(move || {
            LocalFileBackend::atomic_write(&raced_path, &replacement).unwrap();
        });

        let promoted_generation = backend
            .compact_deltas(repo_id)
            .expect("post-commit cleanup race must return the promoted cursor");
        assert_eq!(promoted_generation, delta_generation + 1);
        assert_eq!(
            std::fs::read(&delta_path).unwrap(),
            expected_replacement,
            "cleanup must preserve journal bytes installed after authority commit"
        );
        let lock = backend.acquire_existing_lock(repo_id).unwrap();
        let authority = backend
            .read_authority_record_raw_unlocked(&lock.namespace)
            .unwrap()
            .unwrap();
        assert!(authority
            .retired_deltas
            .iter()
            .any(|identity| identity.generation == delta_generation));
        drop(lock);
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("replacement of retired journal bytes must fail closed");
        assert!(
            error.to_string().contains("retired delta digest mismatch"),
            "unexpected residual-journal error: {error}"
        );
    }

    #[test]
    fn local_reopen_finalizes_exact_quarantine_left_by_cleanup_crash() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "cleanup-quarantine-crash";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.admit_artifact_for_test(
            "retired.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        let gen3 = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();
        backend.set_cleanup_after_quarantine_hook(|| panic!("simulated cleanup crash"));

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend.clear_deltas(repo_id).unwrap();
        }));
        assert!(crashed.is_err());
        assert!(!backend.delta_path(repo_id, gen2).exists());
        let quarantined: Vec<_> = std::fs::read_dir(backend.deltas_dir(repo_id))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".kin-journal-cleanup-"))
            })
            .collect();
        assert_eq!(quarantined.len(), 1);

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("exact authority-bound quarantine must be finalized on reopen");
        assert_eq!(recovered.generation, gen3);
        assert_eq!(recovered.deltas_seen, 0);
        assert!(!quarantined[0].exists());
        reopened.clear_deltas(repo_id).unwrap();
    }

    #[test]
    fn local_backend_reclaims_superseded_immutable_bases_after_save_and_reopen() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "base-cleanup";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo_id, &bytes, GENERATION_INIT)
            .unwrap();
        let gen2 = backend.save_snapshot(repo_id, &bytes, gen1).unwrap();
        assert!(!backend.versioned_snapshot_path(repo_id, gen1).exists());
        assert!(backend.versioned_snapshot_path(repo_id, gen2).exists());

        // A crash can leave an older base behind after authority commit. The
        // next locked load retries cleanup, while preserving a future staged
        // generation that may belong to an in-flight writer.
        std::fs::copy(
            backend.versioned_snapshot_path(repo_id, gen2),
            backend.versioned_snapshot_path(repo_id, gen1),
        )
        .unwrap();
        let future = backend.versioned_snapshot_path(repo_id, gen2 + 1);
        std::fs::copy(backend.versioned_snapshot_path(repo_id, gen2), &future).unwrap();
        let reopened = LocalFileBackend::new(dir.path());
        reopened.load_snapshot(repo_id).unwrap().unwrap();
        assert!(!reopened.versioned_snapshot_path(repo_id, gen1).exists());
        assert!(reopened.versioned_snapshot_path(repo_id, gen2).exists());
        assert!(future.exists());
    }

    #[test]
    fn local_backend_delta_base_gen_mismatch() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Try saving a delta with wrong base generation
        let delta = crate::storage::delta::compute_graph_delta(
            &GraphSnapshot::empty(),
            &GraphSnapshot::empty(),
            0,
        );
        let delta_bytes = delta.to_bytes().unwrap();
        let err = backend
            .save_delta("test-repo", &delta_bytes, GENERATION_INIT)
            .unwrap_err();
        assert!(err.to_string().contains("base generation mismatch"));
    }

    #[test]
    fn local_backend_list_repos() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // No repos yet
        let repos = backend.list_repos().unwrap();
        assert!(repos.is_empty());

        // Save snapshots for two repos
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &bytes, GENERATION_INIT)
            .unwrap();

        // Create a directory without a graph.kndb — should NOT appear
        std::fs::create_dir_all(dir.path().join("not-a-repo")).unwrap();

        let mut repos = backend.list_repos().unwrap();
        repos.sort();
        assert_eq!(repos, vec!["repo-a", "repo-b"]);
    }

    /// A live storage root holds the engine's snapshot, vector, index, and
    /// generation files beside the repository namespaces. Binding each of those
    /// names as a namespace refuses on the first one, so listing a real root
    /// hard-failed instead of answering with the repositories it holds.
    #[test]
    fn local_backend_list_repos_skips_index_files_in_the_storage_root() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &bytes, GENERATION_INIT)
            .unwrap();

        for index_file in [
            "graph.kndb",
            "graph.kvec",
            "graph.kidx",
            "head-generation",
            "generation",
        ] {
            std::fs::write(dir.path().join(index_file), b"engine state").unwrap();
        }

        let mut repos = backend
            .list_repos()
            .expect("index files beside the namespaces are not repositories");
        repos.sort();
        assert_eq!(repos, vec!["repo-a", "repo-b"]);
    }

    /// Skipping the engine's own files must not soften the bind: an entry that
    /// is not a regular file still has to prove it is a real namespace.
    #[cfg(unix)]
    #[test]
    fn local_backend_list_repos_still_refuses_a_symlinked_namespace() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();

        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("repo-link")).unwrap();

        let error = backend
            .list_repos()
            .expect_err("a symlink claiming a namespace name must not be listed as a repository");
        assert!(
            error.to_string().contains("is not a real directory"),
            "unexpected listing refusal: {error}"
        );
    }

    #[test]
    fn probe_reports_a_retained_namespace_without_loading_authority() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();

        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-missing"),
            LocalNamespaceProbe::Absent
        ));
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_namespace_displaced_during_creation_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let visible = dir.path().join("repo-a");
        let detached = dir.path().join("repo-a-detached");
        let replacement = dir.path().join("repo-a-replacement");
        std::fs::create_dir(&replacement).unwrap();
        let visible_for_swap = visible.clone();
        set_local_directory_after_preopen_hook(LocalDirectoryBindKind::Repository, move || {
            std::fs::rename(&visible_for_swap, &detached).unwrap();
            std::fs::rename(&replacement, &visible_for_swap).unwrap();
        });

        backend
            .save_snapshot(
                "repo-a",
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("repository creation must reject a post-publication replacement");

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(error)) => {
                assert!(
                    error.to_string().contains("displaced during creation"),
                    "unexpected displaced-namespace probe error: {error}"
                );
            }
            other => panic!("a displaced namespace must be an identity loss, got {other:?}"),
        }
    }

    /// The identity question and the authority-readable question are different.
    /// A namespace this backend still reaches stays retained even when its
    /// snapshot no longer decodes, so a caller cannot report a corrupt payload
    /// as a replaced repository.
    #[test]
    fn probe_reports_a_corrupt_snapshot_on_an_intact_namespace_as_retained() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));

        std::fs::write(backend.authority_path("repo-a"), b"{ truncated").unwrap();
        for entry in std::fs::read_dir(backend.snapshots_dir("repo-a")).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::write(entry.path(), b"not a snapshot").unwrap();
            }
        }

        assert!(
            matches!(
                backend.probe_pinned_repository_namespace("repo-a"),
                LocalNamespaceProbe::Retained
            ),
            "a corrupt payload on an intact namespace is not an identity fault"
        );
        backend
            .load_snapshot_authority("repo-a")
            .expect_err("the full authority load still refuses the corrupt payload");
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_replaced_namespace_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));

        let namespace = dir.path().join("repo-a");
        let replacement = dir.path().join("repo-a-replacement");
        std::fs::create_dir_all(&replacement).unwrap();
        std::fs::rename(&namespace, dir.path().join("repo-a-original")).unwrap();
        std::fs::rename(&replacement, &namespace).unwrap();

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(error)) => {
                assert!(
                    error
                        .to_string()
                        .contains("changed since this backend opened"),
                    "unexpected replacement refusal: {error}"
                );
            }
            other => panic!("a replaced namespace must be an identity loss, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_detached_namespace_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));

        std::fs::rename(dir.path().join("repo-a"), dir.path().join("repo-moved")).unwrap();

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::Namespace(error)) => {
                assert!(
                    error
                        .to_string()
                        .contains("was detached after this backend opened"),
                    "unexpected detachment refusal: {error}"
                );
            }
            other => panic!("a detached namespace must be an identity loss, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_replaced_storage_root_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("kindb");
        std::fs::create_dir_all(&root).unwrap();
        let backend = LocalFileBackend::new(&root);
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));

        let replacement = dir.path().join("kindb-replacement");
        std::fs::create_dir_all(replacement.join("repo-a")).unwrap();
        std::fs::rename(&root, dir.path().join("kindb-original")).unwrap();
        std::fs::rename(&replacement, &root).unwrap();

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::StorageRoot(error)) => {
                assert!(
                    error
                        .to_string()
                        .contains("changed since this backend opened"),
                    "unexpected root replacement refusal: {error}"
                );
            }
            other => panic!("a replaced storage root must be an identity loss, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_symlinked_storage_root_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("kindb");
        std::fs::create_dir_all(&root).unwrap();
        let backend = LocalFileBackend::new(&root);
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();

        let replacement = dir.path().join("kindb-replacement");
        std::fs::create_dir_all(&replacement).unwrap();
        std::fs::rename(&root, dir.path().join("kindb-original")).unwrap();
        std::os::unix::fs::symlink(&replacement, &root).unwrap();

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::StorageRoot(error)) => {
                assert!(
                    error
                        .to_string()
                        .contains("changed to a non-directory or link"),
                    "unexpected symlinked-root probe error: {error}"
                );
            }
            other => panic!("a symlinked storage root must be an identity loss, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_non_directory_storage_root_as_identity_lost() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("kindb");
        std::fs::create_dir_all(&root).unwrap();
        let backend = LocalFileBackend::new(&root);
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();

        std::fs::rename(&root, dir.path().join("kindb-original")).unwrap();
        std::fs::write(&root, b"not a storage root").unwrap();

        match backend.probe_pinned_repository_namespace("repo-a") {
            LocalNamespaceProbe::IdentityLost(LocalNamespaceIdentityFault::StorageRoot(error)) => {
                assert!(
                    error
                        .to_string()
                        .contains("changed to a non-directory or link"),
                    "unexpected non-directory-root probe error: {error}"
                );
            }
            other => {
                panic!("a non-directory storage root must be an identity loss, got {other:?}")
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_an_uninspectable_storage_root_as_unavailable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("parent");
        let root = parent.join("kindb");
        std::fs::create_dir_all(&root).unwrap();
        let backend = LocalFileBackend::new(&root);
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(matches!(
            backend.probe_pinned_repository_namespace("repo-a"),
            LocalNamespaceProbe::Retained
        ));

        let original_permissions = std::fs::metadata(&parent).unwrap().permissions();
        let mut inaccessible_permissions = original_permissions.clone();
        inaccessible_permissions.set_mode(0o0);
        std::fs::set_permissions(&parent, inaccessible_permissions).unwrap();
        let probe = backend.probe_pinned_repository_namespace("repo-a");
        std::fs::set_permissions(&parent, original_permissions).unwrap();

        match probe {
            LocalNamespaceProbe::Unavailable(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("failed to inspect local storage root"),
                    "unexpected unavailable-root probe error: {error}"
                );
            }
            other => panic!("an uninspectable storage root must be unavailable, got {other:?}"),
        }
    }

    #[test]
    fn local_backend_multiple_repos_isolated() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &bytes, GENERATION_INIT)
            .unwrap();

        // Each repo has its own generation
        let (_, gen_a) = backend.load_snapshot("repo-a").unwrap().unwrap();
        let (_, gen_b) = backend.load_snapshot("repo-b").unwrap().unwrap();
        assert_eq!(gen_a, 1);
        assert_eq!(gen_b, 1);

        // Advancing one doesn't affect the other
        backend.save_snapshot("repo-a", &bytes, gen_a).unwrap();
        let (_, gen_a2) = backend.load_snapshot("repo-a").unwrap().unwrap();
        let (_, gen_b2) = backend.load_snapshot("repo-b").unwrap().unwrap();
        assert_eq!(gen_a2, 2);
        assert_eq!(gen_b2, 1);
    }

    #[test]
    fn acquire_lock_creates_lock_file() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let _lock = backend.acquire_lock("test-repo").unwrap();
        let lock_path = dir.path().join("test-repo").join(".lock");
        assert!(lock_path.exists(), "lock file should be created");
        // Lock is released when _lock is dropped
    }
}
