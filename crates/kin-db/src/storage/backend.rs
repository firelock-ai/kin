// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

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
    delete_quarantined_delta_exact, is_quarantine_delta_name, load_quarantined_deltas,
    quarantine_delta_path, quarantined_file_matches, sync_parent_directory,
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
    file.sync_all().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to fsync immutable source blob {}: {error}",
            display_path.display()
        ))
    })
}

#[cfg(windows)]
fn sync_source_file_for_ack(file: &std::fs::File, display_path: &Path) -> Result<(), KinDbError> {
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

#[cfg(unix)]
fn open_source_directory_at(
    parent: &std::fs::File,
    name: &str,
    display_path: &Path,
    create: bool,
    confirm_durability: bool,
) -> Result<std::fs::File, KinDbError> {
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
    Ok(directory)
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

#[cfg(unix)]
fn open_source_blob_capability(
    base_path: &Path,
    repo_id: &str,
    digest: [u8; 32],
    create: bool,
    confirm_durability: bool,
    root_confirmed_for_process: &parking_lot::Mutex<bool>,
) -> Result<SourceBlobCapability, KinDbError> {
    validate_source_blob_repo_id(repo_id)?;
    if create {
        prepare_source_trust_root(base_path, confirm_durability, root_confirmed_for_process)?;
    }
    let trusted_root = std::fs::canonicalize(base_path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to resolve immutable source blob trust root {}: {error}",
            base_path.display()
        ))
    })?;
    let mut parent = std::fs::File::open(&trusted_root).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to open immutable source blob trust root {}: {error}",
            trusted_root.display()
        ))
    })?;
    if !parent
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?
        .is_dir()
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root {} is not a real directory",
            trusted_root.display()
        )));
    }

    let digest_hex = hex::encode(digest);
    let mut display = trusted_root;
    let mut repo_dir = None;
    for component in [repo_id, "source-blobs", "sha256", &digest_hex[..2]] {
        display.push(component);
        let child =
            open_source_directory_at(&parent, component, &display, create, confirm_durability)?;
        if repo_dir.is_none() {
            repo_dir = Some(
                child
                    .try_clone()
                    .map_err(|error| KinDbError::StorageError(error.to_string()))?,
            );
        }
        parent = child;
    }
    Ok(SourceBlobCapability {
        repo_dir: repo_dir.expect("validated source path always contains repo component"),
        leaf_dir: parent,
        leaf_path: display,
    })
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
fn confirm_source_blob_namespace(
    base_path: &Path,
    repo_id: &str,
    digest: [u8; 32],
    capability: &SourceBlobCapability,
    root_confirmed_for_process: &parking_lot::Mutex<bool>,
) -> Result<(), KinDbError> {
    let current = open_source_blob_capability(
        base_path,
        repo_id,
        digest,
        false,
        false,
        root_confirmed_for_process,
    )?;
    if !same_directory(&capability.repo_dir, &current.repo_dir)?
        || !same_directory(&capability.leaf_dir, &current.leaf_dir)?
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root changed while accessing {}",
            capability.leaf_path.display()
        )));
    }
    Ok(())
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
fn publish_source_file_at(
    directory: &std::fs::File,
    digest_hex: &str,
    data: &[u8],
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
        .and_then(|()| staged.sync_all())
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
    mmap::sync_directory_handle(directory, Path::new("pinned immutable source directory"))?;
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
    repo_index: usize,
    leaf_path: PathBuf,
}

#[cfg(windows)]
impl WindowsSourceBlobCapability {
    fn repo_dir(&self) -> &cap_std::fs::Dir {
        &self.directories[self.repo_index]
    }

    fn leaf_dir(&self) -> &cap_std::fs::Dir {
        self.directories
            .last()
            .expect("source capability always contains its digest-prefix directory")
    }
}

#[cfg(windows)]
struct WindowsOpenedSourceBlob {
    file: std::fs::File,
    data: Vec<u8>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[cfg(windows)]
fn open_windows_source_directory_at(
    parent: &cap_std::fs::Dir,
    component: &std::ffi::OsStr,
    display_path: &Path,
    create: bool,
) -> Result<cap_std::fs::Dir, KinDbError> {
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
    let file = parent.open_with(component, &options).map_err(|error| {
        KinDbError::StorageError(format!(
            "refusing reparse-point or non-directory immutable source blob ancestor {} (or missing path): {error}",
            display_path.display()
        ))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(error.to_string()))?;
    if windows_source_metadata_is_reparse(&metadata) || !metadata.is_dir() {
        return Err(KinDbError::StorageError(format!(
            "refusing reparse-point or non-directory immutable source blob ancestor {}",
            display_path.display()
        )));
    }
    Ok(cap_std::fs::Dir::from_std_file(file.into_std()))
}

#[cfg(windows)]
fn windows_source_absolute_base(base_path: &Path) -> Result<PathBuf, KinDbError> {
    let absolute = if base_path.is_absolute() {
        base_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to resolve current directory for immutable source storage: {error}"
                ))
            })?
            .join(base_path)
    };
    if absolute
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root may not contain parent traversal: {}",
            base_path.display()
        )));
    }
    Ok(absolute)
}

#[cfg(windows)]
fn open_windows_source_blob_capability(
    base_path: &Path,
    repo_id: &str,
    digest: [u8; 32],
    create: bool,
) -> Result<WindowsSourceBlobCapability, KinDbError> {
    validate_source_blob_repo_id(repo_id)?;
    let absolute = windows_source_absolute_base(base_path)?;
    let ambient_root = absolute
        .ancestors()
        .last()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .ok_or_else(|| {
            KinDbError::StorageError(format!(
                "immutable source blob trust root has no filesystem root: {}",
                absolute.display()
            ))
        })?;
    let relative = absolute.strip_prefix(ambient_root).map_err(|_| {
        KinDbError::StorageError(format!(
            "immutable source blob trust root is not beneath its filesystem root: {}",
            absolute.display()
        ))
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root contains an unsupported component: {}",
            absolute.display()
        )));
    }

    let root = cap_std::fs::Dir::open_ambient_dir(ambient_root, cap_std::ambient_authority())
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open immutable source filesystem root {}: {error}",
                ambient_root.display()
            ))
        })?;
    let mut directories = vec![root];
    let mut display = ambient_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            unreachable!("immutable source root components were validated")
        };
        display.push(name);
        let next = open_windows_source_directory_at(
            directories
                .last()
                .expect("filesystem root capability was inserted"),
            name,
            &display,
            false,
        )?;
        directories.push(next);
    }

    let digest_hex = hex::encode(digest);
    let repo_index = directories.len();
    for component in [
        std::ffi::OsStr::new(repo_id),
        std::ffi::OsStr::new("source-blobs"),
        std::ffi::OsStr::new("sha256"),
        std::ffi::OsStr::new(&digest_hex[..2]),
    ] {
        display.push(component);
        let next = open_windows_source_directory_at(
            directories
                .last()
                .expect("filesystem root capability was inserted"),
            component,
            &display,
            create,
        )?;
        directories.push(next);
    }

    Ok(WindowsSourceBlobCapability {
        directories,
        repo_index,
        leaf_path: display,
    })
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
            "failed to inspect immutable source Windows file identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    let identity = WindowsSourceIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    };
    if identity.volume_serial == 0 || identity.file_id.iter().all(|byte| *byte == 0) {
        return Err(KinDbError::StorageError(
            "immutable source Windows object returned a zero FILE_ID_128 identity".to_string(),
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
fn confirm_windows_source_blob_namespace(
    base_path: &Path,
    repo_id: &str,
    digest: [u8; 32],
    capability: &WindowsSourceBlobCapability,
) -> Result<(), KinDbError> {
    let current = open_windows_source_blob_capability(base_path, repo_id, digest, false)?;
    if current.directories.len() != capability.directories.len() {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob trust root changed while accessing {}",
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
                "immutable source blob trust root changed while accessing {}",
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

    // Flush the exact renamed file handle after the namespace transition.
    // Windows has no supported directory-fsync equivalent; the write-through
    // staging handle plus this post-rename flush is its strongest supported
    // file/metadata durability boundary.
    sync_source_file_for_ack(
        staged.file(),
        Path::new("pinned immutable Windows source object"),
    )?;
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
}

impl SnapshotAuthority {
    /// Backend CAS cursor represented by this coherent authority view.
    pub const fn cursor(&self) -> SnapshotCursor {
        SnapshotCursor::from_backend_generation(self.head_generation)
    }
}

pub type PersistedDelta = (Vec<u8>, Generation);
pub type SnapshotRecoveryState = (Option<SnapshotAuthority>, Vec<PersistedDelta>);

/// A snapshot reconstructed from durable base bytes plus its acknowledged
/// incremental-delta chain.
#[derive(Debug)]
pub struct RecoveredSnapshot {
    pub snapshot: GraphSnapshot,
    pub generation: Generation,
    pub deltas_applied: usize,
    pub deltas_seen: usize,
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

    let mut snapshot = GraphSnapshot::from_bytes(&authority.snapshot_bytes)?;
    let deltas_seen = raw_deltas.len();
    if authority.snapshot_generation == authority.head_generation {
        return Ok(Some(RecoveredSnapshot {
            snapshot,
            generation: authority.head_generation,
            deltas_applied: 0,
            deltas_seen,
        }));
    }
    let mut expected_generation = checked_next_generation(
        authority.snapshot_generation,
        &format!("repo {repo_id} recovery"),
    )?;
    let mut recovered_generation = authority.snapshot_generation;
    let mut applied = 0usize;
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
        applied += 1;
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

    Ok(Some(RecoveredSnapshot {
        snapshot,
        generation: authority.head_generation,
        deltas_applied: applied,
        deltas_seen,
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
            }))
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
    #[cfg(any(unix, windows))]
    storage_root_identity: parking_lot::Mutex<Option<LocalStorageRootIdentity>>,
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
    source_blob_after_capability_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    source_blob_before_publish_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalStorageRootIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
}

/// Read the exact `BY_HANDLE_FILE_INFORMATION` identity of a storage root.
///
/// Windows binds file identity to an open handle rather than to `Metadata`, and
/// the `std` accessors for those fields are still unstable, so the root is
/// reopened and its handle information is read through a stable wrapper. The
/// reopen keeps exactly the reach `symlink_metadata` had: a zero access mask
/// asks for identity without demanding read rights,
/// `FILE_FLAG_BACKUP_SEMANTICS` admits a directory handle, and
/// `FILE_FLAG_OPEN_REPARSE_POINT` leaves a final symlink unfollowed, so a root
/// swapped for a link after the metadata call cannot redirect identity. A root
/// that disappeared in that window is absent, exactly as a missing root is at
/// the metadata call. A volume serial that does not fit the `DWORD` it is
/// documented to be, and a filesystem that reports no file ID at all, both fail
/// closed rather than pinning an identity that cannot tell two directories
/// apart.
#[cfg(windows)]
fn windows_storage_root_identity(
    path: &Path,
) -> Result<Option<LocalStorageRootIdentity>, KinDbError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let root = match options.open(path) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect local storage root {}: {error}",
                path.display()
            )))
        }
    };
    let information = winapi_util::file::information(&root).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to inspect local storage root {}: {error}",
            path.display()
        ))
    })?;
    let volume_serial = u32::try_from(information.volume_serial_number()).map_err(|_| {
        KinDbError::StorageError(format!(
            "local storage root {} has no stable volume identity",
            path.display()
        ))
    })?;
    let file_index = information.file_index();
    if file_index == 0 {
        return Err(KinDbError::StorageError(format!(
            "local storage root {} has no stable file identity",
            path.display()
        )));
    }
    Ok(Some(LocalStorageRootIdentity {
        volume_serial,
        file_index,
    }))
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
    _lock_file: std::fs::File,
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
}

const LOCAL_AUTHORITY_VERSION: u32 = 3;

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
}

impl LocalFileBackend {
    /// Create a new local backend rooted at `base_path`.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        let base_path = base_path.into();
        #[cfg(any(unix, windows))]
        let storage_root_identity = Self::inspect_storage_root_identity(&base_path)
            .ok()
            .flatten();
        Self {
            base_path,
            #[cfg(any(unix, windows))]
            storage_root_identity: parking_lot::Mutex::new(storage_root_identity),
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
            source_blob_after_capability_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            source_blob_before_publish_hook: parking_lot::Mutex::new(None),
        }
    }

    /// Return the base path.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    #[cfg(any(unix, windows))]
    fn inspect_storage_root_identity(
        path: &Path,
    ) -> Result<Option<LocalStorageRootIdentity>, KinDbError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local storage root {}: {error}",
                    path.display()
                )))
            }
        };
        #[cfg(unix)]
        {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KinDbError::StorageError(format!(
                    "local storage root {} is not a real directory",
                    path.display()
                )));
            }
            Ok(Some(LocalStorageRootIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()
            {
                return Err(KinDbError::StorageError(format!(
                    "local storage root {} is not a real directory",
                    path.display()
                )));
            }
            windows_storage_root_identity(path)
        }
    }

    /// Confirm that this backend still names the same storage-root directory it
    /// first observed. A missing root is acceptable only for a backend that has
    /// never observed one; writes still refuse to create it.
    fn confirm_storage_root_identity(&self) -> Result<bool, KinDbError> {
        #[cfg(any(unix, windows))]
        {
            let current = Self::inspect_storage_root_identity(&self.base_path)?;
            let mut expected = self.storage_root_identity.lock();
            match (*expected, current) {
                (Some(expected), Some(current)) if expected == current => Ok(true),
                (Some(_), Some(_)) => Err(KinDbError::StorageError(format!(
                    "local storage root {} changed since this backend opened; refusing to bind a replacement repository namespace",
                    self.base_path.display()
                ))),
                (Some(_), None) => Err(KinDbError::StorageError(format!(
                    "local storage root {} was detached after this backend opened",
                    self.base_path.display()
                ))),
                (None, Some(current)) => {
                    *expected = Some(current);
                    Ok(true)
                }
                (None, None) => Ok(false),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let metadata = match std::fs::symlink_metadata(&self.base_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(KinDbError::StorageError(format!(
                        "failed to inspect local storage root {}: {error}",
                        self.base_path.display()
                    )))
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KinDbError::StorageError(format!(
                    "local storage root {} is not a real directory",
                    self.base_path.display()
                )));
            }
            Ok(true)
        }
    }

    fn authority_path(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("authority.json")
    }

    fn snapshots_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("snapshots")
    }

    fn versioned_snapshot_path(&self, repo_id: &str, generation: Generation) -> PathBuf {
        self.snapshots_dir(repo_id)
            .join(format!("{generation:020}.kndb"))
    }

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

    fn deltas_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("deltas")
    }

    fn delta_path(&self, repo_id: &str, gen: Generation) -> PathBuf {
        self.deltas_dir(repo_id).join(format!("{gen:020}.kndd"))
    }

    fn existing_repository_path(&self, repo_id: &str) -> Result<Option<PathBuf>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if !self.confirm_storage_root_identity()? {
            return Ok(None);
        }
        let repository_path = self.base_path.join(repo_id);
        let metadata = match std::fs::symlink_metadata(&repository_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local repository authority directory {}: {error}",
                    repository_path.display()
                )))
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(KinDbError::StorageError(format!(
                "local repository authority directory {} is not a real directory",
                repository_path.display()
            )));
        }
        Ok(Some(repository_path))
    }

    fn acquire_lock(&self, repo_id: &str) -> Result<std::fs::File, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if !self.confirm_storage_root_identity()? {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} is unavailable; refusing to recreate a detached authority namespace",
                self.base_path.display()
            )));
        }
        let repository_path = self.base_path.join(repo_id);
        match std::fs::create_dir(&repository_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to create local repository authority directory {}: {error}",
                    repository_path.display()
                )))
            }
        }
        self.existing_repository_path(repo_id)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local repository authority directory {} disappeared during initialization",
                repository_path.display()
            ))
        })?;
        let lock_path = repository_path.join(".lock");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let lock_file = options.open(&lock_path).map_err(|error| {
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
        if !opened_metadata.is_file() {
            return Err(KinDbError::StorageError(format!(
                "opened local repository authority lock {} is not a regular file",
                lock_path.display()
            )));
        }
        use fs2::FileExt;
        lock_file.lock_exclusive().map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to acquire exclusive lock on {}: {e}",
                lock_path.display()
            ))
        })?;
        self.confirm_existing_lock_visible(&lock_path, &lock_file)?;
        if !self.confirm_storage_root_identity()? {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} disappeared while Kin acquired its initialization lock",
                self.base_path.display()
            )));
        }
        Ok(lock_file)
    }

    fn acquire_existing_lock(&self, repo_id: &str) -> Result<std::fs::File, KinDbError> {
        let repository_path = self.existing_repository_path(repo_id)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local repository authority directory {} is unavailable for existing-authority access",
                self.base_path.join(repo_id).display()
            ))
        })?;

        let lock_path = repository_path.join(".lock");
        let lock_metadata = std::fs::symlink_metadata(&lock_path).map_err(|error| {
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

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let lock_file = options.open(&lock_path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open existing local repository authority lock {}: {error}",
                lock_path.display()
            ))
        })?;
        let opened_metadata = lock_file.metadata().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect opened local repository authority lock {}: {error}",
                lock_path.display()
            ))
        })?;
        if !opened_metadata.is_file() {
            return Err(KinDbError::StorageError(format!(
                "opened local repository authority lock {} is not a regular file",
                lock_path.display()
            )));
        }

        use fs2::FileExt;
        lock_file.lock_exclusive().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to acquire existing local repository authority lock {}: {error}",
                lock_path.display()
            ))
        })?;
        self.confirm_existing_lock_visible(&lock_path, &lock_file)?;
        if !self.confirm_storage_root_identity()? {
            return Err(KinDbError::StorageError(format!(
                "local storage root {} disappeared while Kin acquired its existing-authority lock",
                self.base_path.display()
            )));
        }
        Ok(lock_file)
    }

    fn confirm_existing_lock_visible(
        &self,
        lock_path: &Path,
        lock_file: &std::fs::File,
    ) -> Result<(), KinDbError> {
        let visible = std::fs::symlink_metadata(lock_path).map_err(|error| {
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

        #[cfg(unix)]
        {
            let opened = lock_file.metadata().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect held local repository authority lock {}: {error}",
                    lock_path.display()
                ))
            })?;
            if opened.dev() != visible.dev() || opened.ino() != visible.ino() {
                return Err(KinDbError::StorageError(format!(
                    "local repository authority lock {} changed while Kin waited",
                    lock_path.display()
                )));
            }
        }
        #[cfg(windows)]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let visible_file = options.open(lock_path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to reopen visible local repository authority lock {}: {error}",
                    lock_path.display()
                ))
            })?;
            if windows_source_file_identity(lock_file)?
                != windows_source_file_identity(&visible_file)?
            {
                return Err(KinDbError::StorageError(format!(
                    "local repository authority lock {} changed while Kin waited",
                    lock_path.display()
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn freeze_existing_authority(
        &self,
        repo_id: &str,
    ) -> Result<LocalAuthorityFreezeLock, KinDbError> {
        let lock_file = self.acquire_existing_lock(repo_id)?;
        let authority = self.load_authority_unlocked(repo_id)?.ok_or_else(|| {
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
        self.confirm_existing_lock_visible(
            &self.base_path.join(repo_id).join(".lock"),
            &lock_file,
        )?;
        Ok(LocalAuthorityFreezeLock {
            repo_id: repo_id.to_string(),
            authority,
            _lock_file: lock_file,
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
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (digest, max_bytes);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(windows)]
        {
            let capability =
                open_windows_source_blob_capability(&self.base_path, repo_id, digest, false)?;
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                max_bytes,
                false,
            )?
            else {
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            return Ok(Some(data.data));
        }
        #[cfg(unix)]
        {
            let capability = open_source_blob_capability(
                &self.base_path,
                repo_id,
                digest,
                false,
                false,
                &self.source_root_confirmed_for_process,
            )?;
            confirm_source_blob_namespace(
                &self.base_path,
                repo_id,
                digest,
                &capability,
                &self.source_root_confirmed_for_process,
            )?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_source_file_at(&capability.leaf_dir, &digest_hex, max_bytes)?
            else {
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            confirm_source_blob_namespace(
                &self.base_path,
                repo_id,
                digest,
                &capability,
                &self.source_root_confirmed_for_process,
            )?;
            Ok(Some(data.data))
        }
    }

    fn sync_parent(path: &Path) -> Result<(), KinDbError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        #[cfg(not(unix))]
        {
            let _ = parent;
            return Ok(());
        }
        #[cfg(unix)]
        {
            let directory = std::fs::File::open(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to open directory {} for fsync: {error}",
                    parent.display()
                ))
            })?;
            directory.sync_all().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to fsync directory {}: {error}",
                    parent.display()
                ))
            })
        }
    }

    fn atomic_write(path: &Path, data: &[u8]) -> Result<(), KinDbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        mmap::atomic_write_bytes_no_magic(path, data)
    }

    fn snapshot_file_name(generation: Generation) -> String {
        format!("{generation:020}.kndb")
    }

    fn snapshot_digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn file_digest(path: &Path) -> Result<String, KinDbError> {
        let mut file = mmap::open_regular_nofollow(path, "digest source")?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read {} for digest verification: {error}",
                    path.display()
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
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        for (index, identity) in record.acknowledged_deltas.iter().enumerate() {
            let path = self.delta_path(repo_id, identity.generation);
            if !path.exists() {
                if let Some(next) = record.acknowledged_deltas[index + 1..]
                    .iter()
                    .find(|next| self.delta_path(repo_id, next.generation).exists())
                {
                    return Err(KinDbError::StorageError(format!(
                        "repo {repo_id} delta chain is incomplete: expected generation {}, found {}",
                        identity.generation, next.generation
                    )));
                }
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} delta chain ended at generation {}, acknowledged head is {}",
                    identity.generation - 1,
                    record.head_generation
                )));
            }
            let digest = Self::file_digest(&path).map_err(|error| {
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
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
        Self::validate_loaded_residual_deltas(repo_id, record, &deltas)
    }

    fn finalize_retired_quarantines_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let quarantined = load_quarantined_deltas(&self.deltas_dir(repo_id))?;
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
            delete_quarantined_delta_exact(artifact)?;
        }
        Ok(())
    }

    fn reject_unbound_staged_deltas_unlocked(
        &self,
        repo_id: &str,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<(), KinDbError> {
        let head_generation = record.map_or(GENERATION_INIT, |record| record.head_generation);
        let deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
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
        repo_id: &str,
        identities: &[LocalDeltaIdentity],
        required: bool,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let mut captured = Vec::new();
        for identity in identities {
            let path = self.delta_path(repo_id, identity.generation);
            let bytes = match std::fs::symlink_metadata(&path) {
                Ok(_) => mmap::read_regular_file(&path, "authority-bound delta")?,
                Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(KinDbError::StorageError(format!(
                        "failed to capture authority-bound delta {} for repo {repo_id}: {error}",
                        path.display()
                    )));
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
        Ok(captured)
    }

    fn capture_authority_bound_deltas_unlocked(
        &self,
        repo_id: &str,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let Some(record) = record else {
            return Ok(Vec::new());
        };
        let mut captured =
            self.capture_delta_identities_unlocked(repo_id, &record.acknowledged_deltas, true)?;
        captured.extend(self.capture_delta_identities_unlocked(
            repo_id,
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
        repo_id: &str,
        captured: &[PersistedDelta],
    ) -> bool {
        let mut complete = true;
        for (captured_bytes, generation) in captured {
            let path = self.delta_path(repo_id, *generation);
            let captured_sha256 = Self::snapshot_digest(captured_bytes);
            let quarantine_path = quarantine_delta_path(&path, *generation, &captured_sha256);
            match std::fs::rename(&path, &quarantine_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %path.display(), error = %error, "journal promotion committed; could not quarantine captured delta for cleanup");
                    continue;
                }
            }
            if let Err(error) = sync_parent_directory(&quarantine_path) {
                complete = false;
                tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; quarantined delta rename could not be made durable");
                continue;
            }
            #[cfg(test)]
            if let Some(hook) = self.cleanup_after_quarantine_hook.lock().take() {
                hook();
            }
            match quarantined_file_matches(
                &quarantine_path,
                &captured_sha256,
                captured_bytes.len() as u64,
            ) {
                Ok(true) => match std::fs::remove_file(&quarantine_path) {
                    Ok(()) => {
                        if let Err(error) = Self::sync_parent(&quarantine_path) {
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
        match self.load_deltas_since_unlocked(repo_id, GENERATION_INIT) {
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
        repo_id: &str,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let path = self.authority_path(repo_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local authority {}: {error}",
                    path.display()
                )))
            }
        }
        mmap::confirm_installed_write(&path)?;
        let bytes = mmap::read_regular_bounded(&path, "local authority", 1024 * 1024)?;
        let record: LocalAuthorityRecord = serde_json::from_slice(&bytes).map_err(|error| {
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
        Ok(Some(record))
    }

    fn read_authority_record_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let record = self.read_authority_record_raw_unlocked(repo_id)?;
        let Some(record) = record else {
            return Ok(None);
        };
        self.validate_acknowledged_deltas_unlocked(repo_id, &record)?;
        self.validate_residual_deltas_unlocked(repo_id, &record)?;
        Ok(Some(record))
    }

    fn read_authoritative_snapshot_bytes_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<Vec<u8>, KinDbError> {
        let path = self.snapshots_dir(repo_id).join(&record.snapshot_file);
        let snapshot_bytes = mmap::read_regular_file(&path, "authoritative snapshot")?;
        let digest = Self::snapshot_digest(&snapshot_bytes);
        if digest != record.snapshot_sha256 {
            return Err(KinDbError::StorageError(format!(
                "authoritative snapshot digest mismatch for repo {repo_id}: expected {}, found {digest}",
                record.snapshot_sha256
            )));
        }
        GraphSnapshot::from_bytes(&snapshot_bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "authoritative snapshot payload for repo {repo_id} is invalid: {error}"
            ))
        })?;
        Ok(snapshot_bytes)
    }

    fn clear_superseded_snapshots_unlocked(
        &self,
        repo_id: &str,
        keep_generation: Generation,
    ) -> Result<(), KinDbError> {
        let dir = self.snapshots_dir(repo_id);
        if !dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&dir).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local snapshot directory {}: {error}",
                dir.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read local snapshot entry in {}: {error}",
                    dir.display()
                ))
            })?;
            let path = entry.path();
            let Some(generation) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<Generation>().ok())
            else {
                continue;
            };
            if path.extension().and_then(|extension| extension.to_str()) != Some("kndb")
                || path.file_name().and_then(|name| name.to_str())
                    != Some(Self::snapshot_file_name(generation).as_str())
                || generation >= keep_generation
            {
                continue;
            }
            std::fs::remove_file(&path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to remove superseded local snapshot {}: {error}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    fn load_authority_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        let Some(record) = self.read_authority_record_unlocked(repo_id)? else {
            let quarantines = load_quarantined_deltas(&self.deltas_dir(repo_id))?;
            if !quarantines.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has {} quarantined deltas but no current snapshot authority; recovery is fail-closed",
                    quarantines.len()
                )));
            }
            let deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
            if !deltas.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has {} deltas but no current snapshot authority; recovery is fail-closed",
                    deltas.len()
                )));
            }
            return Ok(None);
        };

        let snapshot_bytes = self.read_authoritative_snapshot_bytes_unlocked(repo_id, &record)?;
        // Cleanup is downstream of both authority-directory durability and
        // exact authoritative payload verification.
        self.finalize_retired_quarantines_unlocked(repo_id, &record)?;
        if let Err(error) =
            self.clear_superseded_snapshots_unlocked(repo_id, record.snapshot_generation)
        {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        Ok(Some(SnapshotAuthority {
            snapshot_bytes,
            snapshot_generation: record.snapshot_generation,
            head_generation: record.head_generation,
        }))
    }

    fn write_authority_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            KinDbError::StorageError(format!("failed to encode local authority: {error}"))
        })?;
        let path = self.authority_path(repo_id);
        match mmap::atomic_write_bytes_no_magic_outcome(&path, &bytes)? {
            AtomicWriteOutcome::Durable => Ok(()),
            AtomicWriteOutcome::InstalledButNotSynced(error) => {
                Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                    "local authority {} was installed but its parent-directory durability is unconfirmed: {error}",
                    path.display()
                )))
            }
        }
    }

    fn load_deltas_since_unlocked(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let deltas_dir = self.deltas_dir(repo_id);
        if !deltas_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<(Generation, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&deltas_dir).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read deltas directory {}: {error}",
                deltas_dir.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!("failed to read delta entry: {error}"))
            })?;
            let path = entry.path();
            if is_quarantine_delta_name(&path) {
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("kndd") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "delta authority {} has a non-UTF8 generation",
                        path.display()
                    ))
                })?;
            let generation = stem.parse::<Generation>().map_err(|error| {
                KinDbError::StorageError(format!(
                    "delta authority {} has an invalid generation: {error}",
                    path.display()
                ))
            })?;
            let canonical_name = format!("{generation:020}.kndd");
            if generation == GENERATION_INIT
                || path.file_name().and_then(|name| name.to_str()) != Some(canonical_name.as_str())
            {
                return Err(KinDbError::StorageError(format!(
                    "delta authority {} has a reserved or noncanonical generation",
                    path.display()
                )));
            }
            if generation > since_gen {
                entries.push((generation, path));
            }
        }
        entries.sort_by_key(|(generation, _)| *generation);

        entries
            .into_iter()
            .map(|(generation, path)| {
                mmap::read_regular_file(&path, "local delta").map(|bytes| (bytes, generation))
            })
            .collect()
    }

    /// Persist one complete snapshot while the caller holds this repository's
    /// exclusive local authority lock.
    ///
    /// Keeping lock acquisition outside this helper lets the ordinary storage
    /// API drop the lock on return while the repository-authority API can
    /// return the exact same lock as a held successor freeze.
    fn save_snapshot_unlocked(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let current = self.load_authority_unlocked(repo_id)?;
        let current_record = self.read_authority_record_raw_unlocked(repo_id)?;
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
                // Re-sync the authority directory before accepting.
                mmap::sync_parent_dir(&self.authority_path(repo_id)).map_err(|error| {
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "local authority {} is installed but durability remains unconfirmed: {error}",
                        self.authority_path(repo_id).display()
                    ))
                })?;
                return Ok(record.head_generation);
            }
        }
        self.reject_unbound_staged_deltas_unlocked(repo_id, current_record.as_ref())?;
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
        let versioned_path = self.versioned_snapshot_path(repo_id, new_gen);
        Self::atomic_write(&versioned_path, data)?;

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
            self.capture_authority_bound_deltas_unlocked(repo_id, current_record.as_ref())?;
        self.reject_unbound_staged_deltas_unlocked(repo_id, current_record.as_ref())?;
        if self.capture_authority_bound_deltas_unlocked(repo_id, current_record.as_ref())?
            != captured_for_cleanup
            || self.read_authority_record_raw_unlocked(repo_id)? != current_record
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} authority or journal changed during full promotion; authority was not committed"
            )));
        }

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: requested_digest,
            acknowledged_deltas: Vec::new(),
            retired_deltas: Self::delta_identities(&captured_for_cleanup),
        };
        self.write_authority_unlocked(repo_id, &record)?;
        if let Err(error) = self.clear_superseded_snapshots_unlocked(repo_id, new_gen) {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        Ok(new_gen)
    }

    /// Persist a local full-snapshot CAS and return the same still-held
    /// repository lock that protected its commit point.
    pub(crate) fn save_snapshot_and_freeze(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> Result<(SnapshotCursor, LocalAuthorityFreezeLock), KinDbError> {
        let expected_gen = expected_cursor.backend_generation();
        let lock_file = if expected_gen == GENERATION_INIT
            && self.existing_repository_path(repo_id)?.is_none()
        {
            self.acquire_lock(repo_id)?
        } else {
            self.acquire_existing_lock(repo_id)?
        };
        let generation = self.save_snapshot_unlocked(repo_id, data, expected_gen)?;
        let cursor = SnapshotCursor::from_backend_generation(generation);
        let authority = SnapshotAuthority {
            snapshot_bytes: data.to_vec(),
            snapshot_generation: generation,
            head_generation: generation,
        };
        Ok((
            cursor,
            LocalAuthorityFreezeLock {
                repo_id: repo_id.to_string(),
                authority,
                _lock_file: lock_file,
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

    #[cfg(test)]
    fn set_source_blob_after_capability_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.source_blob_after_capability_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_source_blob_before_publish_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.source_blob_before_publish_hook.lock() = Some(Box::new(hook));
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
        validate_source_blob_repo_id(repo_id)?;
        let byte_len = u64::try_from(data.len()).map_err(|_| {
            KinDbError::StorageError(format!(
                "immutable source blob for repo {repo_id} does not fit the size boundary"
            ))
        })?;
        validate_source_blob_size(byte_len, &format!("repo {repo_id}"))?;
        verify_source_blob_digest(digest, data, &format!("repo {repo_id}"))?;
        #[cfg(any(unix, windows))]
        let _authority_lock = if self.existing_repository_path(repo_id)?.is_some() {
            self.acquire_existing_lock(repo_id)?
        } else {
            self.acquire_lock(repo_id)?
        };
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (repo_id, digest, data);
            return Err(KinDbError::StorageError(
                "secure local immutable source storage is unavailable on this platform; use the GCS backend"
                    .to_string(),
            ));
        }
        #[cfg(windows)]
        {
            let capability =
                open_windows_source_blob_capability(&self.base_path, repo_id, digest, true)?;
            #[cfg(test)]
            if let Some(hook) = self.source_blob_after_capability_hook.lock().take() {
                hook();
            }
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
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
                confirm_windows_source_blob_namespace(
                    &self.base_path,
                    repo_id,
                    digest,
                    &capability,
                )?;
                sync_source_file_for_ack(&existing.file, &capability.leaf_path.join(&digest_hex))?;
                return Ok(());
            }

            #[cfg(test)]
            if let Some(hook) = self.source_blob_before_publish_hook.lock().take() {
                hook();
            }
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            let published_identity =
                publish_windows_source_file_at(capability.leaf_dir(), &digest_hex, data)?;
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
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            sync_source_file_for_ack(&installed.file, &capability.leaf_path.join(&digest_hex))?;
            return Ok(());
        }
        #[cfg(unix)]
        {
            let capability = open_source_blob_capability(
                &self.base_path,
                repo_id,
                digest,
                true,
                true,
                &self.source_root_confirmed_for_process,
            )?;
            #[cfg(test)]
            if let Some(hook) = self.source_blob_after_capability_hook.lock().take() {
                hook();
            }
            let digest_hex = hex::encode(digest);

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
                confirm_source_blob_namespace(
                    &self.base_path,
                    repo_id,
                    digest,
                    &capability,
                    &self.source_root_confirmed_for_process,
                )?;
                sync_source_file_for_ack(&existing.file, &capability.leaf_path.join(&digest_hex))?;
                mmap::sync_directory_handle(&capability.leaf_dir, &capability.leaf_path)?;
                return Ok(());
            }

            #[cfg(test)]
            if let Some(hook) = self.source_blob_before_publish_hook.lock().take() {
                hook();
            }

            // Re-walk without creating anything and compare the directory
            // identity to the pinned handle. A substituted ancestor is rejected
            // before publication; all writes remain relative to the old handle.
            confirm_source_blob_namespace(
                &self.base_path,
                repo_id,
                digest,
                &capability,
                &self.source_root_confirmed_for_process,
            )?;

            let _published = publish_source_file_at(&capability.leaf_dir, &digest_hex, data)?;
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
            sync_source_file_for_ack(&installed.file, &capability.leaf_path.join(&digest_hex))?;
            mmap::sync_directory_handle(&capability.leaf_dir, &capability.leaf_path)?;
            Ok(())
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
        let _authority_lock = self.acquire_existing_lock(repo_id)?;
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
            let capability =
                open_windows_source_blob_capability(&self.base_path, repo_id, digest, true)?;
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                max_bytes,
                false,
            )?
            else {
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            return Ok(Some(data.data));
        }
        #[cfg(unix)]
        {
            // Preserve the historical read contract (a missing object returns
            // None) while still opening every component capability-relatively.
            let capability = open_source_blob_capability(
                &self.base_path,
                repo_id,
                digest,
                true,
                false,
                &self.source_root_confirmed_for_process,
            )?;
            let digest_hex = hex::encode(digest);
            let Some(data) = read_source_file_at(&capability.leaf_dir, &digest_hex, max_bytes)?
            else {
                return Ok(None);
            };
            verify_source_blob_digest(
                digest,
                &data.data,
                &capability.leaf_path.display().to_string(),
            )?;
            Ok(Some(data.data))
        }
    }

    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        #[cfg(any(unix, windows))]
        let _authority_lock = self.acquire_existing_lock(repo_id)?;
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
            let capability =
                open_windows_source_blob_capability(&self.base_path, repo_id, digest, true)?;
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            let digest_hex = hex::encode(digest);
            let opened = open_windows_source_file_at(
                capability.leaf_dir(),
                std::ffi::OsStr::new(&digest_hex),
                false,
            )?;
            let byte_len = opened.as_ref().map(|(_, byte_len)| *byte_len);
            confirm_windows_source_blob_namespace(&self.base_path, repo_id, digest, &capability)?;
            return Ok(byte_len);
        }
        #[cfg(unix)]
        {
            let capability = open_source_blob_capability(
                &self.base_path,
                repo_id,
                digest,
                true,
                false,
                &self.source_root_confirmed_for_process,
            )?;
            let digest_hex = hex::encode(digest);
            Ok(open_source_file_at(&capability.leaf_dir, &digest_hex)?
                .map(|(_, byte_len)| byte_len))
        }
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        let _lock = self.acquire_existing_lock(repo_id)?;
        self.load_authority_unlocked(repo_id)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok((None, Vec::new()));
        }
        let _lock = self.acquire_existing_lock(repo_id)?;
        let authority = self.load_authority_unlocked(repo_id)?;
        let authority_record = self.read_authority_record_raw_unlocked(repo_id)?;
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
            self.finalize_retired_quarantines_unlocked(repo_id, record)?;
        }
        let all_deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
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
        Ok((authority, deltas))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = if expected_gen == GENERATION_INIT
            && self.existing_repository_path(repo_id)?.is_none()
        {
            self.acquire_lock(repo_id)?
        } else {
            self.acquire_existing_lock(repo_id)?
        };
        self.save_snapshot_unlocked(repo_id, data, expected_gen)
    }

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
            Err(error @ KinDbError::SnapshotPersistenceIndeterminate(_)) => {
                SnapshotSaveOutcome::Indeterminate(error)
            }
            Err(error) => SnapshotSaveOutcome::NotCommitted(error),
        }
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_existing_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        let Some(mut record) = self.read_authority_record_unlocked(repo_id)? else {
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
            && mmap::read_regular_file(
                &self.delta_path(repo_id, current_gen),
                "idempotent local delta retry",
            )
            .is_ok_and(|bytes| bytes == delta_data)
        {
            mmap::sync_parent_dir(&self.authority_path(repo_id))?;
            return Ok(current_gen);
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
        let delta_path = self.delta_path(repo_id, new_gen);
        Self::atomic_write(&delta_path, delta_data)?;
        record.version = LOCAL_AUTHORITY_VERSION;
        record
            .retired_deltas
            .retain(|identity| identity.generation != new_gen);
        record.acknowledged_deltas.push(LocalDeltaIdentity {
            generation: new_gen,
            sha256: requested_digest,
        });
        record.head_generation = new_gen;
        self.write_authority_unlocked(repo_id, &record)?;
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
        let _lock = self.acquire_existing_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        self.load_deltas_since_unlocked(repo_id, since_gen)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(());
        }
        let _lock = self.acquire_existing_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        #[cfg(test)]
        if let Some(hook) = self.compaction_before_delta_cleanup_hook.lock().take() {
            hook();
        }
        let record = self.read_authority_record_unlocked(repo_id)?;
        let Some(record) = record else {
            if self
                .load_deltas_since_unlocked(repo_id, GENERATION_INIT)?
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
            self.capture_delta_identities_unlocked(repo_id, &record.retired_deltas, false)?;
        if !self.clear_exact_captured_deltas_unlocked(repo_id, &captured) {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta cleanup left residual journal artifacts; recovery remains fail-closed"
            )));
        }
        Ok(())
    }

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        let _lock = self.acquire_existing_lock(repo_id)?;
        let path = self.overlay_path(repo_id, session_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create overlay directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(&path, data).map_err(|e| {
            KinDbError::StorageError(format!("failed to write overlay {}: {e}", path.display()))
        })
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(None);
        }
        let _lock = self.acquire_existing_lock(repo_id)?;
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).map_err(|e| {
            KinDbError::StorageError(format!("failed to read overlay {}: {e}", path.display()))
        })?;
        Ok(Some(data))
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        if self.existing_repository_path(repo_id)?.is_none() {
            return Ok(());
        }
        let _lock = self.acquire_existing_lock(repo_id)?;
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&path).map_err(|e| {
            KinDbError::StorageError(format!("failed to delete overlay {}: {e}", path.display()))
        })
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        let mut repos = Vec::new();
        if !self.confirm_storage_root_identity()? {
            return Ok(repos);
        }
        let entries = std::fs::read_dir(&self.base_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read base directory {}: {e}",
                self.base_path.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                KinDbError::StorageError(format!("failed to read directory entry: {e}"))
            })?;
            if entry.path().is_dir() {
                let authority = entry.path().join("authority.json");
                if authority.exists() {
                    if let Some(name) = entry.file_name().to_str() {
                        repos.push(name.to_string());
                    }
                }
            }
        }
        Ok(repos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        assert!(error.to_string().contains("symlinked or non-directory"));
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
        assert!(error.to_string().contains("symlinked or non-directory"));
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

        // Four source-directory ancestors are confirmed before publication;
        // fail the following sync of the newly linked object entry.
        mmap::fail_parent_sync_after(4);
        let first_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("an unconfirmed object link must not be acknowledged");
        assert!(first_error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(path.exists(), "the failed sync happens after publication");

        // The object exists on retry, but that retry must still perform its
        // own directory confirmation rather than trusting path existence.
        mmap::fail_parent_sync_after(4);
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
                    .contains("unavailable for existing-authority access"),
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
                .contains("refusing to recreate a detached authority namespace")
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
    fn local_backend_recovery_replays_sequential_deltas_after_reopen() {
        let dir = TempDir::new().unwrap();
        let repo_id = "restart-repo";
        let mut base = GraphSnapshot::empty();
        base.admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));

        {
            let backend = LocalFileBackend::new(dir.path());
            let gen1 = backend
                .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
                .unwrap();

            let mut after_first = base.clone();
            after_first.admit_artifact_for_test(
                "first.rs".to_string(),
                crate::types::regular_tree_entry(2),
            );
            let first_delta = crate::storage::delta::compute_graph_delta(&base, &after_first, gen1);
            let gen2 = backend
                .save_delta(repo_id, &first_delta.to_bytes().unwrap(), gen1)
                .unwrap();

            let mut after_second = after_first.clone();
            after_second.admit_artifact_for_test(
                "second.rs".to_string(),
                crate::types::regular_tree_entry(3),
            );
            let second_delta =
                crate::storage::delta::compute_graph_delta(&after_first, &after_second, gen2);
            let gen3 = backend
                .save_delta(repo_id, &second_delta.to_bytes().unwrap(), gen2)
                .unwrap();
            assert_eq!(gen3, 3);
        }

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("base snapshot exists");
        assert_eq!(recovered.generation, 3);
        assert_eq!(recovered.deltas_seen, 2);
        assert_eq!(recovered.deltas_applied, 2);
        assert_eq!(recovered.snapshot.resolved_tree.len(), 3);
        assert!(recovered.snapshot.has_artifact_path_for_test("base.rs"));
        assert!(recovered.snapshot.has_artifact_path_for_test("first.rs"));
        assert!(recovered.snapshot.has_artifact_path_for_test("second.rs"));
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
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("authority must bind the exact acknowledged delta bytes");
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
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        // Model a crash after full snapshot promotion but before clear_deltas.
        let gen3 = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();
        assert_eq!(gen3, 3);

        let recovered = load_recovered_snapshot(&backend, repo_id)
            .unwrap()
            .expect("promoted snapshot exists");
        assert_eq!(recovered.generation, gen3);
        assert_eq!(recovered.deltas_seen, 0);
        assert_eq!(recovered.deltas_applied, 0);
        assert_eq!(recovered.snapshot.resolved_tree.len(), 1);
        assert!(recovered.snapshot.has_artifact_path_for_test("current.rs"));
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
        assert!(error.to_string().contains("durability is unconfirmed"));
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
        // The delta write consumes five syncs. Authority candidate install
        // plus the exact candidate claim consume two more; fail its
        // destination rename sync.
        mmap::fail_parent_sync_after(7);

        let error = backend
            .save_delta(repo_id, &delta_bytes, gen1)
            .expect_err("installed but unconfirmed delta authority must be reported");
        assert!(error.to_string().contains("durability is unconfirmed"));
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
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
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
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
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
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("missing first delta must fail closed");
        assert!(error.to_string().contains("expected generation 2, found 3"));
    }

    #[test]
    fn local_recovery_rejects_missing_delta_head() {
        let (_dir, backend, repo_id) = local_backend_with_two_deltas();
        std::fs::remove_file(backend.delta_path(repo_id, 3)).unwrap();
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("missing acknowledged head must fail closed");
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
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
            .unwrap()
            .unwrap();
        assert!(authority
            .retired_deltas
            .iter()
            .any(|identity| identity.generation == delta_generation));
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
