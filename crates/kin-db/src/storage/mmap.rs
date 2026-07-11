// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::KinDbError;
use crate::storage::format::{GraphSnapshot, LocateGraphSnapshot};

#[cfg(test)]
std::thread_local! {
    static PARENT_SYNC_FAILURE_COUNTDOWN: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static PROMOTION_AFTER_VALIDATION_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static CONFIRM_BEFORE_MARKER_CLAIM_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static PROMOTION_AFTER_TARGET_RENAME_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn fail_parent_sync_after(successful_syncs: usize) {
    PARENT_SYNC_FAILURE_COUNTDOWN.with(|countdown| countdown.set(Some(successful_syncs)));
}

#[cfg(test)]
fn set_promotion_after_validation_hook(hook: impl FnOnce() + 'static) {
    PROMOTION_AFTER_VALIDATION_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_promotion_after_validation_hook() {
    PROMOTION_AFTER_VALIDATION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_promotion_after_validation_hook() {}

#[cfg(test)]
fn set_confirm_before_marker_claim_hook(hook: impl FnOnce() + 'static) {
    CONFIRM_BEFORE_MARKER_CLAIM_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_confirm_before_marker_claim_hook() {
    CONFIRM_BEFORE_MARKER_CLAIM_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_confirm_before_marker_claim_hook() {}

#[cfg(test)]
fn set_promotion_after_target_rename_hook(hook: impl FnOnce() + 'static) {
    PROMOTION_AFTER_TARGET_RENAME_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_promotion_after_target_rename_hook() {
    PROMOTION_AFTER_TARGET_RENAME_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_promotion_after_target_rename_hook() {}

const RECOVERY_MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryMarker {
    version: u32,
    byte_len: u64,
    sha256: [u8; 32],
}

/// Result of the commit-point rename performed by an atomic write.
///
/// `InstalledButNotSynced` is deliberately distinct from an ordinary error:
/// the destination already contains the new bytes, but the parent directory
/// has not yet confirmed that rename as durable. Authority callers must either
/// confirm the directory sync or return without doing post-commit cleanup.
#[derive(Debug)]
pub(crate) enum AtomicWriteOutcome {
    Durable,
    InstalledButNotSynced(KinDbError),
}

const MAX_RECOVERY_MARKER_BYTES: u64 = 64 * 1024;
const MAX_AUTHORITY_CONFIRMATION_BYTES: u64 = 1024 * 1024;

/// Append a suffix to `path` without disturbing its existing extension.
///
/// `with_extension` *replaces* the extension, so `graph.kndb` and
/// `graph.kidx` would both collapse to `graph.tmp` and cross-contaminate
/// during concurrent saves. Appending keeps the discriminating extension,
/// so `graph.kndb` → `graph.kndb.tmp` and `graph.kidx` → `graph.kidx.tmp`
/// stay provably disjoint. The result is deterministic so crash recovery
/// can reconstruct the same name on reopen.
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn recovery_tmp_path(path: &Path) -> PathBuf {
    append_suffix(path, ".tmp")
}

pub(crate) fn recovery_marker_path(path: &Path) -> PathBuf {
    append_suffix(path, ".tmp.meta")
}

/// Path a corrupt snapshot is moved aside to when verify-on-read fails.
///
/// `tag` is a short hex fingerprint of the offending content so repeated
/// corruption of the same bytes lands on a stable name instead of piling up.
pub(crate) fn quarantine_path(path: &Path, tag: &str) -> PathBuf {
    append_suffix(path, &format!(".corrupt-{tag}"))
}

/// Atomically move a corrupt primary snapshot aside so it is never served and
/// the path is free for a healed snapshot to take its place.
///
/// Mirrors the corrupt-object quarantine kin-blobs performs on a failed
/// verify-on-read: the bad bytes are preserved for forensics under a distinct
/// name rather than deleted or silently overwritten.
pub(crate) fn quarantine_corrupt_snapshot(path: &Path, tag: &str) -> Result<PathBuf, KinDbError> {
    ensure_regular_path_entry(path, "snapshot selected for quarantine")?;
    let dest = quarantine_path(path, tag);
    std::fs::rename(path, &dest).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to quarantine corrupt snapshot {} → {}: {e}",
            path.display(),
            dest.display()
        ))
    })?;
    ensure_regular_path_entry(&dest, "quarantined snapshot")?;
    sync_parent_dir(path)?;
    Ok(dest)
}

fn unique_staging_path(path: &Path, kind: &str) -> PathBuf {
    append_suffix(
        path,
        &format!(".{kind}-{}", uuid::Uuid::new_v4().as_hyphenated()),
    )
}

fn write_new_bytes_and_fsync(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to create unique staged file {}: {e}",
                path.display()
            ))
        })?;
    file.write_all(bytes).map_err(|e| {
        KinDbError::StorageError(format!("failed to write {}: {e}", path.display()))
    })?;
    file.sync_all().map_err(|e| {
        KinDbError::StorageError(format!("failed to fsync {}: {e}", path.display()))
    })?;
    Ok(())
}

fn normalized_parent(path: &Path) -> Option<&Path> {
    path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }
    })
}

pub(crate) fn sync_parent_dir(path: &Path) -> Result<(), KinDbError> {
    #[cfg(test)]
    let inject_failure = PARENT_SYNC_FAILURE_COUNTDOWN.with(|countdown| match countdown.get() {
        Some(0) => {
            countdown.set(None);
            true
        }
        Some(remaining) => {
            countdown.set(Some(remaining - 1));
            false
        }
        None => false,
    });
    #[cfg(not(test))]
    let inject_failure = false;
    if inject_failure {
        return Err(KinDbError::StorageError(format!(
            "injected parent-directory fsync failure for {}",
            path.display()
        )));
    }
    let Some(parent) = normalized_parent(path) else {
        return Ok(());
    };
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
    #[cfg(unix)]
    {
        let dir = File::open(parent).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open parent directory {} for fsync: {error}",
                parent.display()
            ))
        })?;
        dir.sync_all().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to fsync parent directory {}: {error}",
                parent.display()
            ))
        })
    }
}

fn ensure_regular_path_entry(path: &Path, role: &str) -> Result<(), KinDbError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to inspect {role} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(KinDbError::StorageError(format!(
            "refusing non-regular {role} {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn open_regular_nofollow(path: &Path, role: &str) -> Result<File, KinDbError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to open {role} {} without following links: {error}",
            path.display()
        ))
    })?;
    if !file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect opened {role} {}: {error}",
                path.display()
            ))
        })?
        .is_file()
    {
        return Err(KinDbError::StorageError(format!(
            "refusing non-regular {role} {}",
            path.display()
        )));
    }
    Ok(file)
}

pub(crate) fn read_regular_bounded(
    path: &Path,
    role: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, KinDbError> {
    let file = open_regular_nofollow(path, role)?;
    let len = file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect {role} {}: {error}",
                path.display()
            ))
        })?
        .len();
    if len > max_bytes {
        return Err(KinDbError::StorageError(format!(
            "{role} {} is {len} bytes, above the {max_bytes}-byte safety limit",
            path.display()
        )));
    }
    let capacity = usize::try_from(len).map_err(|_| {
        KinDbError::StorageError(format!(
            "{role} {} length does not fit in memory",
            path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            KinDbError::StorageError(format!("failed to read {role} {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(KinDbError::StorageError(format!(
            "{role} {} grew above the {max_bytes}-byte safety limit while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

pub(crate) fn read_regular_file(path: &Path, role: &str) -> Result<Vec<u8>, KinDbError> {
    let mut file = open_regular_nofollow(path, role)?;
    let len = file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect {role} {}: {error}",
                path.display()
            ))
        })?
        .len();
    let capacity = usize::try_from(len).map_err(|_| {
        KinDbError::StorageError(format!(
            "{role} {} length does not fit in memory",
            path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(|error| {
        KinDbError::StorageError(format!("failed to read {role} {}: {error}", path.display()))
    })?;
    Ok(bytes)
}

#[derive(Debug)]
pub(crate) struct ExactPathClaim {
    original: PathBuf,
    held: Option<PathBuf>,
}

impl ExactPathClaim {
    fn held_path(&self) -> Option<&Path> {
        self.held.as_deref()
    }

    pub(crate) fn restore(self) -> Result<(), KinDbError> {
        let Some(held) = self.held else {
            return Ok(());
        };
        match std::fs::hard_link(&held, &self.original) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to restore claimed path {} from {}: {error}",
                    self.original.display(),
                    held.display()
                )))
            }
        }
        match std::fs::remove_file(&held) {
            Ok(()) => sync_parent_dir(&self.original),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                sync_parent_dir(&self.original)
            }
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to release claimed path {}: {error}",
                held.display()
            ))),
        }
    }

    pub(crate) fn release(self) -> Result<(), KinDbError> {
        let Some(held) = self.held else {
            return Ok(());
        };
        match std::fs::remove_file(&held) {
            Ok(()) => sync_parent_dir(&self.original),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                sync_parent_dir(&self.original)
            }
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to release claimed path {}: {error}",
                held.display()
            ))),
        }
    }
}

pub(crate) fn claim_exact_path(
    path: &Path,
    expected: Option<&[u8]>,
    role: &str,
) -> Result<ExactPathClaim, KinDbError> {
    let exists = match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect {role} {} before CAS claim: {error}",
                path.display()
            )))
        }
    };
    if !exists {
        if expected.is_some() {
            return Err(KinDbError::StorageError(format!(
                "{role} {} disappeared before CAS claim",
                path.display()
            )));
        }
        return Ok(ExactPathClaim {
            original: path.to_path_buf(),
            held: None,
        });
    }

    ensure_regular_path_entry(path, role)?;
    let held = unique_staging_path(path, "cas-claim");
    std::fs::rename(path, &held).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to claim {role} {}: {error}",
            path.display()
        ))
    })?;
    let claim = ExactPathClaim {
        original: path.to_path_buf(),
        held: Some(held.clone()),
    };
    if let Err(error) = sync_parent_dir(path) {
        let _ = claim.restore();
        return Err(error);
    }
    let actual = match read_regular_file(&held, role) {
        Ok(actual) => actual,
        Err(error) => {
            let _ = claim.restore();
            return Err(error);
        }
    };
    if expected != Some(actual.as_slice()) {
        claim.restore()?;
        return Err(KinDbError::StorageError(format!(
            "{role} {} changed before its CAS claim",
            path.display()
        )));
    }
    Ok(claim)
}

pub(crate) fn publish_new_file_no_clobber(
    path: &Path,
    bytes: &[u8],
    role: &str,
) -> Result<bool, KinDbError> {
    let staged = unique_staging_path(path, "no-clobber");
    write_new_bytes_and_fsync(&staged, bytes)?;
    match std::fs::hard_link(&staged, path) {
        Ok(()) => {
            sync_parent_dir(path)?;
            let _ = std::fs::remove_file(&staged);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&staged);
            Ok(false)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            Err(KinDbError::StorageError(format!(
                "failed to publish {role} {} without clobbering: {error}",
                path.display()
            )))
        }
    }
}

/// Remove the exact recovery candidate and marker entries observed at call
/// time without unlinking a racing replacement. This is used only after an
/// independent authoritative snapshot has been verified and projected.
pub(crate) fn discard_recovery_artifacts_if_unchanged(path: &Path) -> Result<(), KinDbError> {
    fn read_optional(path: &Path, role: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => read_regular_file(path, role).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to inspect {role} {}: {error}",
                path.display()
            ))),
        }
    }

    let marker_path = recovery_marker_path(path);
    let candidate_path = recovery_tmp_path(path);
    let marker_bytes = read_optional(&marker_path, "recovery marker cleanup source")?;
    let candidate_bytes = read_optional(&candidate_path, "recovery candidate cleanup source")?;
    let marker_claim = claim_exact_path(
        &marker_path,
        marker_bytes.as_deref(),
        "recovery marker cleanup source",
    )?;
    let candidate_claim = match claim_exact_path(
        &candidate_path,
        candidate_bytes.as_deref(),
        "recovery candidate cleanup source",
    ) {
        Ok(claim) => claim,
        Err(error) => {
            let _ = marker_claim.restore();
            return Err(error);
        }
    };
    candidate_claim.release()?;
    marker_claim.release()
}

fn load_recovery_marker_with_bytes(path: &Path) -> Result<(RecoveryMarker, Vec<u8>), KinDbError> {
    let marker_path = recovery_marker_path(path);
    let marker_bytes =
        read_regular_bounded(&marker_path, "recovery marker", MAX_RECOVERY_MARKER_BYTES)?;
    let marker = serde_json::from_slice(&marker_bytes).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to parse recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;
    Ok((marker, marker_bytes))
}

fn load_recovery_marker(path: &Path) -> Result<RecoveryMarker, KinDbError> {
    load_recovery_marker_with_bytes(path).map(|(marker, _)| marker)
}

/// Confirm a target whose rename completed but whose parent-directory fsync
/// did not. The recovery marker is retained across that phase while the
/// candidate path is absent, so a retry/reopen can distinguish an installed
/// cursor from an unpromoted candidate without trusting path visibility alone.
pub(crate) fn confirm_installed_write(path: &Path) -> Result<bool, KinDbError> {
    let marker_path = recovery_marker_path(path);
    match std::fs::symlink_metadata(&marker_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect recovery marker {}: {error}",
                marker_path.display()
            )))
        }
    }

    let tmp_path = recovery_tmp_path(path);
    match std::fs::symlink_metadata(&tmp_path) {
        Ok(_) => {
            return Err(KinDbError::StorageError(format!(
                "recovery candidate {} is still staged; refusing to confirm {} as installed",
                tmp_path.display(),
                path.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect recovery candidate {}: {error}",
                tmp_path.display()
            )))
        }
    }

    let (marker, marker_bytes) = load_recovery_marker_with_bytes(path)?;
    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(KinDbError::StorageError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }
    if marker.byte_len > MAX_AUTHORITY_CONFIRMATION_BYTES {
        return Err(KinDbError::StorageError(format!(
            "installed atomic authority {} claims {} bytes, above the {}-byte confirmation limit",
            path.display(),
            marker.byte_len,
            MAX_AUTHORITY_CONFIRMATION_BYTES
        )));
    }
    let mut installed = open_regular_nofollow(path, "installed atomic authority")?;
    let installed_len = installed
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect installed atomic authority {}: {error}",
                path.display()
            ))
        })?
        .len();
    if installed_len != marker.byte_len {
        return Err(KinDbError::StorageError(format!(
            "installed atomic authority {} length {installed_len} does not match retained marker {} length {}",
            path.display(),
            marker_path.display(),
            marker.byte_len
        )));
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = installed.read(&mut buffer).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to verify installed atomic authority {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > marker.byte_len {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if total != marker.byte_len || digest != marker.sha256 {
        return Err(KinDbError::StorageError(format!(
            "installed atomic destination {} does not match retained marker {}",
            path.display(),
            marker_path.display()
        )));
    }
    sync_parent_dir(path)?;
    run_confirm_before_marker_claim_hook();
    match claim_exact_path(
        &marker_path,
        Some(&marker_bytes),
        "installed-write recovery marker cleanup",
    ) {
        Ok(marker_claim) => {
            if let Err(error) = marker_claim.release() {
                tracing::warn!(path = %marker_path.display(), error = %error, "installed atomic destination is durable; deferred exact recovery-marker cleanup");
            }
        }
        Err(error) => {
            tracing::warn!(path = %marker_path.display(), error = %error, "installed atomic destination is durable; preserved a racing recovery marker");
        }
    }
    Ok(true)
}

pub(crate) fn write_recovery_candidate(
    path: &Path,
    snapshot: &GraphSnapshot,
) -> Result<(), KinDbError> {
    let bytes = snapshot.to_bytes()?;
    write_recovery_candidate_bytes(path, &bytes)
}

/// Like [`write_recovery_candidate`] but accepts pre-serialized snapshot bytes
/// (produced by [`BorrowedGraphSnapshot::to_bytes`]).
pub(crate) fn write_recovery_candidate_bytes(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let unique_tmp_path = unique_staging_path(path, "candidate");
    let unique_marker_path = unique_staging_path(path, "candidate-marker");
    let marker = RecoveryMarker {
        version: RECOVERY_MARKER_VERSION,
        byte_len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    let marker_bytes = serde_json::to_vec(&marker).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to serialize recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;

    let result = (|| {
        write_new_bytes_and_fsync(&unique_tmp_path, bytes)?;
        write_new_bytes_and_fsync(&unique_marker_path, &marker_bytes)?;
        // `rename` replaces a preplanted symlink/FIFO directory entry itself;
        // unlike `File::create`, it never follows that entry to a victim file.
        std::fs::rename(&unique_tmp_path, &tmp_path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to install recovery candidate {}: {error}",
                tmp_path.display()
            ))
        })?;
        ensure_regular_path_entry(&tmp_path, "recovery candidate")?;
        std::fs::rename(&unique_marker_path, &marker_path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to install recovery marker {}: {error}",
                marker_path.display()
            ))
        })?;
        ensure_regular_path_entry(&marker_path, "recovery marker")?;
        sync_parent_dir(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&unique_tmp_path);
        let _ = std::fs::remove_file(&unique_marker_path);
    }
    result
}

pub(crate) fn load_recovery_candidate(path: &Path) -> Result<GraphSnapshot, KinDbError> {
    load_recovery_candidate_with_persisted_root_hash(path).map(|(snapshot, _)| snapshot)
}

pub(crate) fn load_recovery_candidate_with_persisted_root_hash(
    path: &Path,
) -> Result<(GraphSnapshot, Option<[u8; 32]>), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let marker = load_recovery_marker(path).map_err(|err| {
        KinDbError::StorageError(format!(
            "recovery snapshot {} is unproven without a valid marker {}: {err}",
            tmp_path.display(),
            marker_path.display()
        ))
    })?;

    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(KinDbError::StorageError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }

    let mut candidate = open_regular_nofollow(&tmp_path, "recovery snapshot")?;
    let candidate_len = candidate
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect recovery snapshot {}: {error}",
                tmp_path.display()
            ))
        })?
        .len();
    if candidate_len != marker.byte_len {
        return Err(KinDbError::StorageError(format!(
            "recovery snapshot {} length {candidate_len} does not match marker {} length {}",
            tmp_path.display(),
            marker_path.display(),
            marker.byte_len
        )));
    }
    let capacity = usize::try_from(marker.byte_len).map_err(|_| {
        KinDbError::StorageError(format!(
            "recovery snapshot {} length does not fit in memory",
            tmp_path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    candidate.read_to_end(&mut bytes).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to read recovery snapshot {}: {e}",
            tmp_path.display()
        ))
    })?;

    if bytes.len() as u64 != marker.byte_len {
        return Err(KinDbError::StorageError(format!(
            "recovery snapshot {} length {} does not match marker {} length {}",
            tmp_path.display(),
            bytes.len(),
            marker_path.display(),
            marker.byte_len
        )));
    }

    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != marker.sha256 {
        return Err(KinDbError::StorageError(format!(
            "recovery snapshot {} checksum does not match marker {}",
            tmp_path.display(),
            marker_path.display()
        )));
    }

    GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes)
}

/// Read the leading 4 bytes of `path` and confirm they equal `expected`.
///
/// Run immediately after promoting a recovery candidate so a tmp file that
/// somehow carried the wrong content (e.g. cross-contamination between the
/// snapshot and read-index tmp files) fails loudly at write time instead of
/// surfacing as a confusing "expected KNDB magic, got KIDX" at the next reopen.
fn verify_destination_magic(path: &Path, expected: &[u8; 4]) -> Result<(), KinDbError> {
    let mut file = open_regular_nofollow(path, "promoted destination")?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| {
        KinDbError::StorageError(format!("failed to read magic from {}: {e}", path.display()))
    })?;
    if &magic != expected {
        return Err(KinDbError::StorageError(format!(
            "promoted {} but magic {:?} does not match expected {:?}",
            path.display(),
            magic,
            expected
        )));
    }
    Ok(())
}

/// Promote the recovery candidate onto the primary path.
///
/// `expected_magic` is the leading 4 bytes the promoted file must carry. The
/// KNDB snapshot path passes `Some(GraphSnapshot::MAGIC)` so cross-contaminated
/// content fails loudly here; callers writing other on-disk formats through
/// this primitive (e.g. the msgpack locate cache) pass `None`.
pub(crate) fn promote_recovery_candidate(path: &Path) -> Result<(), KinDbError> {
    promote_recovery_candidate_with_magic(path, Some(&GraphSnapshot::MAGIC))
}

pub(crate) fn promote_recovery_candidate_with_magic(
    path: &Path,
    expected_magic: Option<&[u8; 4]>,
) -> Result<(), KinDbError> {
    match promote_recovery_candidate_with_magic_outcome(path, expected_magic)? {
        AtomicWriteOutcome::Durable => Ok(()),
        AtomicWriteOutcome::InstalledButNotSynced(error) => Err(error),
    }
}

fn promote_recovery_candidate_with_magic_outcome(
    path: &Path,
    expected_magic: Option<&[u8; 4]>,
) -> Result<AtomicWriteOutcome, KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);

    // Capture candidate and marker bytes, then atomically claim the exact
    // candidate entry. Promotion operates on the unpredictable claimed name,
    // so a replacement at the deterministic `.tmp` path cannot win the old
    // validate-then-rename window. The deterministic marker deliberately
    // remains discoverable until the target rename is directory-durable.
    let (marker, marker_bytes) = load_recovery_marker_with_bytes(path)?;
    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(KinDbError::StorageError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }
    let candidate = read_regular_bounded(&tmp_path, "recovery candidate", marker.byte_len)?;
    if candidate.len() as u64 != marker.byte_len
        || <[u8; 32]>::from(Sha256::digest(&candidate)) != marker.sha256
    {
        return Err(KinDbError::StorageError(format!(
            "recovery candidate {} no longer matches marker {}",
            tmp_path.display(),
            marker_path.display()
        )));
    }
    if let Some(expected) = expected_magic {
        if candidate.get(..expected.len()) != Some(expected.as_slice()) {
            return Err(KinDbError::StorageError(format!(
                "recovery candidate {} does not carry expected magic {:?}",
                tmp_path.display(),
                expected
            )));
        }
    }
    run_promotion_after_validation_hook();

    let candidate_claim = claim_exact_path(
        &tmp_path,
        Some(&candidate),
        "recovery candidate selected for promotion",
    )?;
    let claimed_candidate_path = candidate_claim
        .held_path()
        .expect("an existing recovery candidate must have a claimed path")
        .to_path_buf();
    let current_marker_bytes = match read_regular_bounded(
        &marker_path,
        "recovery marker selected for promotion",
        MAX_RECOVERY_MARKER_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = candidate_claim.restore();
            return Err(error);
        }
    };
    if current_marker_bytes != marker_bytes {
        let _ = candidate_claim.restore();
        return Err(KinDbError::StorageError(format!(
            "recovery marker {} changed before candidate promotion",
            marker_path.display()
        )));
    }

    if let Err(error) = std::fs::rename(&claimed_candidate_path, path) {
        let _ = candidate_claim.restore();
        return Err(KinDbError::StorageError(format!(
            "failed to rename {} → {}: {error}",
            claimed_candidate_path.display(),
            path.display()
        )));
    }
    run_promotion_after_target_rename_hook();
    ensure_regular_path_entry(path, "promoted destination")?;
    if let Err(error) = sync_parent_dir(path) {
        return Ok(AtomicWriteOutcome::InstalledButNotSynced(error));
    }

    let installed = read_regular_bounded(path, "promoted destination", marker.byte_len)?;
    if installed.len() as u64 != marker.byte_len
        || <[u8; 32]>::from(Sha256::digest(&installed)) != marker.sha256
    {
        return Err(KinDbError::StorageError(format!(
            "promoted destination {} does not match the claimed recovery candidate",
            path.display()
        )));
    }
    if let Some(expected) = expected_magic {
        verify_destination_magic(path, expected)?;
    }

    match claim_exact_path(
        &marker_path,
        Some(&marker_bytes),
        "durable recovery marker cleanup",
    ) {
        Ok(marker_claim) => {
            if let Err(error) = marker_claim.release() {
                tracing::warn!(path = %marker_path.display(), error = %error, "atomic destination is durable; deferred exact recovery-marker cleanup");
            }
        }
        Err(error) => {
            tracing::warn!(path = %marker_path.display(), error = %error, "atomic destination is durable; preserved a racing recovery marker");
        }
    }

    Ok(AtomicWriteOutcome::Durable)
}

/// Memory-mapped file reader for graph snapshots.
///
/// Maps the file into virtual memory so the OS handles paging.
/// The data is read directly from the mmap without copying.
pub struct MmapReader {
    _mmap: Mmap,
}

impl MmapReader {
    /// Open and mmap a snapshot file, returning the deserialized snapshot.
    ///
    /// The mmap is held open for the lifetime of the returned data,
    /// but since we deserialize into owned types, the caller doesn't
    /// need to keep the reader alive.
    pub fn open(path: &Path) -> Result<GraphSnapshot, KinDbError> {
        Self::open_with_persisted_root_hash(path).map(|(snapshot, _)| snapshot)
    }

    pub fn open_with_persisted_root_hash(
        path: &Path,
    ) -> Result<(GraphSnapshot, Option<[u8; 32]>), KinDbError> {
        let file = {
            let _span = tracing::info_span!("kindb.snapshot.mmap.open_file").entered();
            open_regular_nofollow(path, "snapshot")?
        };

        let mmap = unsafe {
            let _span = tracing::info_span!("kindb.snapshot.mmap.map_file").entered();
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };

        let _span = tracing::info_span!("kindb.snapshot.mmap.decode_bytes").entered();
        if trust_primary_snapshot() {
            let _span = tracing::info_span!("kindb.snapshot.trust_primary_snapshot").entered();
            GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&mmap)
        } else {
            GraphSnapshot::from_bytes_with_persisted_root_hash(&mmap)
        }
    }

    pub fn open_for_locate_with_persisted_root_hash(
        path: &Path,
    ) -> Result<(LocateGraphSnapshot, Option<[u8; 32]>), KinDbError> {
        let file = {
            let _span = tracing::info_span!("kindb.snapshot.mmap.open_file").entered();
            open_regular_nofollow(path, "locate snapshot")?
        };

        let mmap = unsafe {
            let _span = tracing::info_span!("kindb.snapshot.mmap.map_file").entered();
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };

        let _span = tracing::info_span!("kindb.snapshot.mmap.decode_locate_bytes").entered();
        if trust_primary_snapshot() {
            let _span = tracing::info_span!("kindb.snapshot.trust_primary_snapshot").entered();
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&mmap)
        } else {
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash(&mmap)
        }
    }

    pub fn read_persisted_root_hash_unverified(
        path: &Path,
    ) -> Result<Option<[u8; 32]>, KinDbError> {
        let file = open_regular_nofollow(path, "snapshot root trailer")?;
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };
        GraphSnapshot::persisted_root_hash_from_bytes_unverified(&mmap)
    }
}

fn trust_primary_snapshot() -> bool {
    matches!(
        std::env::var("KINDB_TRUST_PRIMARY_SNAPSHOT"),
        Ok(value)
            if !value.is_empty()
                && value != "0"
                && !value.eq_ignore_ascii_case("false")
                && !value.eq_ignore_ascii_case("no")
    )
}

/// Write a snapshot to a file atomically.
///
/// Writes to a `.tmp` file first, then renames to the target path.
/// This ensures the target file is always in a consistent state.
pub fn atomic_write(path: &Path, snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
    write_recovery_candidate(path, snapshot)?;
    promote_recovery_candidate(path)
}

/// Like [`atomic_write`] but accepts pre-serialized bytes (from
/// [`BorrowedGraphSnapshot::to_bytes`]). Asserts the promoted file carries the
/// KNDB magic.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    write_recovery_candidate_bytes(path, bytes)?;
    promote_recovery_candidate(path)
}

/// Like [`atomic_write_bytes`] but for on-disk formats that do not carry the
/// KNDB magic (e.g. the msgpack locate cache). Skips the post-promote magic
/// assert while keeping the same crash-safe tmp/marker/rename sequence.
pub(crate) fn atomic_write_bytes_no_magic(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    match atomic_write_bytes_no_magic_outcome(path, bytes)? {
        AtomicWriteOutcome::Durable => Ok(()),
        AtomicWriteOutcome::InstalledButNotSynced(error) => Err(error),
    }
}

pub(crate) fn atomic_write_bytes_no_magic_outcome(
    path: &Path,
    bytes: &[u8],
) -> Result<AtomicWriteOutcome, KinDbError> {
    write_recovery_candidate_bytes(path, bytes)?;
    promote_recovery_candidate_with_magic_outcome(path, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
    }

    #[test]
    fn atomic_write_and_mmap_read() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        let snap = GraphSnapshot::empty();

        atomic_write(&path, &snap).unwrap();
        let loaded = MmapReader::open(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn atomic_write_overwrites_partial_tmp_without_corrupting_target() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        atomic_write(&path, &snap).unwrap();

        let tmp_path = recovery_tmp_path(&path);
        std::fs::write(&tmp_path, b"partial write").unwrap();

        atomic_write(&path, &snap).unwrap();

        let loaded = MmapReader::open(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn promotion_rejects_candidate_swapped_after_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.kndb");
        let original_primary = GraphSnapshot::empty().to_bytes().unwrap();
        std::fs::write(&path, &original_primary).unwrap();

        let mut candidate = GraphSnapshot::empty();
        candidate
            .file_hashes
            .insert("candidate.rs".to_string(), [1; 32]);
        write_recovery_candidate_bytes(&path, &candidate.to_bytes().unwrap()).unwrap();

        let mut replacement = GraphSnapshot::empty();
        replacement
            .file_hashes
            .insert("replacement.rs".to_string(), [2; 32]);
        let replacement_bytes = replacement.to_bytes().unwrap();
        let tmp_path = recovery_tmp_path(&path);
        let installed_replacement = replacement_bytes.clone();
        set_promotion_after_validation_hook(move || {
            std::fs::write(&tmp_path, &installed_replacement).unwrap();
        });

        let error = promote_recovery_candidate(&path)
            .expect_err("candidate replacement after validation must lose the exact CAS");
        assert!(error.to_string().contains("changed before its CAS claim"));
        assert_eq!(std::fs::read(&path).unwrap(), original_primary);
        assert_eq!(
            std::fs::read(recovery_tmp_path(&path)).unwrap(),
            replacement_bytes
        );
    }

    #[test]
    fn promotion_keeps_marker_discoverable_across_post_rename_crash_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, b"old authority").unwrap();
        let installed = b"new authority";
        write_recovery_candidate_bytes(&path, installed).unwrap();
        set_promotion_after_target_rename_hook(|| panic!("simulated hard crash after rename"));

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = promote_recovery_candidate_with_magic(&path, None);
        }));
        assert!(crashed.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), installed);
        assert!(
            recovery_marker_path(&path).exists(),
            "the deterministic marker must witness an unconfirmed target rename"
        );
        assert!(!recovery_tmp_path(&path).exists());

        assert!(confirm_installed_write(&path).unwrap());
        assert!(!recovery_marker_path(&path).exists());
    }

    #[test]
    fn confirmation_never_unlinks_a_racing_replacement_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        let installed = b"installed authority";
        std::fs::write(&path, installed).unwrap();
        let marker = RecoveryMarker {
            version: RECOVERY_MARKER_VERSION,
            byte_len: installed.len() as u64,
            sha256: Sha256::digest(installed).into(),
        };
        let marker_path = recovery_marker_path(&path);
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        let replacement = b"racing replacement marker".to_vec();
        let replacement_path = marker_path.clone();
        let installed_replacement = replacement.clone();
        set_confirm_before_marker_claim_hook(move || {
            std::fs::write(&replacement_path, &installed_replacement).unwrap();
        });

        assert!(confirm_installed_write(&path).unwrap());
        assert_eq!(std::fs::read(&marker_path).unwrap(), replacement);
    }

    #[test]
    fn confirmation_rejects_marker_controlled_oversized_authority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        let oversized = MAX_AUTHORITY_CONFIRMATION_BYTES + 1;
        let file = File::create(&path).unwrap();
        file.set_len(oversized).unwrap();
        let marker = RecoveryMarker {
            version: RECOVERY_MARKER_VERSION,
            byte_len: oversized,
            sha256: [0; 32],
        };
        std::fs::write(
            recovery_marker_path(&path),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        let error = confirm_installed_write(&path)
            .expect_err("forged marker must not drive an unbounded authority allocation");
        assert!(error.to_string().contains("confirmation limit"));
    }

    #[test]
    fn write_recovery_candidate_requires_marker_for_recovery() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        let tmp_path = recovery_tmp_path(&path);
        std::fs::write(&tmp_path, snap.to_bytes().unwrap()).unwrap();

        let err = load_recovery_candidate(&path).unwrap_err();
        assert!(err.to_string().contains("unproven without a valid marker"));
    }

    #[test]
    fn write_recovery_candidate_round_trips_with_matching_marker() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        write_recovery_candidate(&path, &snap).unwrap();
        let loaded = load_recovery_candidate(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);

        promote_recovery_candidate(&path).unwrap();
        assert!(path.exists());
        assert!(!recovery_tmp_path(&path).exists());
        assert!(!recovery_marker_path(&path).exists());
    }

    #[test]
    fn load_recovery_candidate_rejects_mismatched_marker() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        write_recovery_candidate(&path, &snap).unwrap();

        let marker_path = recovery_marker_path(&path);
        let mut marker: RecoveryMarker =
            serde_json::from_slice(&std::fs::read(&marker_path).unwrap()).unwrap();
        marker.byte_len += 1;
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let err = load_recovery_candidate(&path).unwrap_err();
        assert!(err.to_string().contains("does not match marker"));
    }

    #[test]
    fn recovery_tmp_paths_preserve_extension() {
        let snapshot = Path::new("/repo/kindb/graph.kndb");
        assert_eq!(
            recovery_tmp_path(snapshot),
            PathBuf::from("/repo/kindb/graph.kndb.tmp")
        );
        assert_eq!(
            recovery_marker_path(snapshot),
            PathBuf::from("/repo/kindb/graph.kndb.tmp.meta")
        );
    }

    #[test]
    fn snapshot_and_index_tmp_paths_are_disjoint() {
        // Sibling artifacts in the same dir: the snapshot (graph.kndb) and the
        // read-index (graph.kidx). Before the fix both derived `graph.tmp` via
        // `with_extension` and cross-contaminated. Appending the suffix keeps
        // the discriminating extension, so the tmp paths are provably disjoint.
        let dir = Path::new("/repo/kindb");
        let snapshot_tmp = recovery_tmp_path(&dir.join("graph.kndb"));
        let index_tmp = append_suffix(&dir.join("graph.kidx"), ".tmp");

        assert_ne!(snapshot_tmp, index_tmp);
        assert_eq!(snapshot_tmp, PathBuf::from("/repo/kindb/graph.kndb.tmp"));
        assert_eq!(index_tmp, PathBuf::from("/repo/kindb/graph.kidx.tmp"));
    }

    #[test]
    fn promote_rejects_wrong_magic() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        // Write a tmp + marker whose body has the wrong magic (KIDX, the
        // read-index magic) so the promoted file would not be a valid KNDB
        // snapshot. The post-rename magic check must fail loudly.
        let bytes = b"KIDX not actually a snapshot".to_vec();
        let tmp_path = recovery_tmp_path(&path);
        let marker_path = recovery_marker_path(&path);
        let marker = RecoveryMarker {
            version: RECOVERY_MARKER_VERSION,
            byte_len: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        };
        std::fs::write(&tmp_path, &bytes).unwrap();
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let err = promote_recovery_candidate(&path).unwrap_err();
        assert!(
            err.to_string().contains("expected magic"),
            "expected a magic-mismatch error, got: {err}"
        );
    }

    #[test]
    fn atomic_write_propagates_parent_sync_failure_after_rename() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        std::fs::write(&path, b"old").unwrap();
        // Candidate installation and the exact candidate claim each sync once;
        // fail the following destination-rename durability sync.
        fail_parent_sync_after(2);

        let error = atomic_write_bytes_no_magic(&path, b"new")
            .expect_err("post-rename parent fsync failure must be reported");
        assert!(error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"new",
            "the error is post-rename and must not be misreported as a pre-commit failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_replaces_preplanted_symlink_and_fifo_entries_without_following_them() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = recovery_tmp_path(&path);
        let marker_path = recovery_marker_path(&path);
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        symlink(&sentinel, &tmp_path).unwrap();
        symlink(&sentinel, &marker_path).unwrap();
        symlink(&sentinel, &path).unwrap();

        atomic_write_bytes_no_magic(&path, b"safe replacement").unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
        assert_eq!(std::fs::read(&path).unwrap(), b"safe replacement");
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());

        std::fs::remove_file(&path).unwrap();
        make_fifo(&path);
        make_fifo(&tmp_path);
        make_fifo(&marker_path);
        atomic_write_bytes_no_magic(&path, b"fifo replacement").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"fifo replacement");
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_and_mmap_reads_reject_symlinks_and_fifos_without_blocking() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.kndb");
        let snapshot = GraphSnapshot::empty();
        write_recovery_candidate(&path, &snapshot).unwrap();
        let marker_path = recovery_marker_path(&path);
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        std::fs::remove_file(&marker_path).unwrap();
        symlink(&sentinel, &marker_path).unwrap();
        let error = load_recovery_candidate(&path)
            .expect_err("recovery marker symlink must not be followed");
        assert!(error.to_string().contains("without following links"));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");

        std::fs::remove_file(&marker_path).unwrap();
        std::fs::remove_file(recovery_tmp_path(&path)).unwrap();
        make_fifo(&marker_path);
        let error = load_recovery_candidate(&path)
            .expect_err("recovery marker FIFO must fail without blocking");
        assert!(error.to_string().contains("non-regular"));

        let fifo_snapshot = dir.path().join("fifo.kndb");
        make_fifo(&fifo_snapshot);
        let error =
            MmapReader::open(&fifo_snapshot).expect_err("snapshot FIFO must fail without blocking");
        assert!(error.to_string().contains("non-regular"));
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_replaces_preplanted_symlink_destination_without_clobbering_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.kndb");
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&path, b"corrupt").unwrap();
        std::fs::write(&sentinel, b"sentinel").unwrap();
        let destination = quarantine_path(&path, "bad0");
        symlink(&sentinel, &destination).unwrap();

        let quarantined = quarantine_corrupt_snapshot(&path, "bad0").unwrap();
        assert_eq!(quarantined, destination);
        assert_eq!(std::fs::read(&quarantined).unwrap(), b"corrupt");
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }

    #[test]
    fn atomic_write_and_quarantine_support_bare_relative_paths() {
        const CHILD: &str = "KINDB_BARE_RELATIVE_MMAP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let path = Path::new("graph.kndb");
            atomic_write_bytes_no_magic(path, b"bare").unwrap();
            assert_eq!(std::fs::read(path).unwrap(), b"bare");
            let quarantined = quarantine_corrupt_snapshot(path, "bare").unwrap();
            assert_eq!(quarantined, PathBuf::from("graph.kndb.corrupt-bare"));
            assert_eq!(std::fs::read(quarantined).unwrap(), b"bare");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("storage::mmap::tests::atomic_write_and_quarantine_support_bare_relative_paths")
            .arg("--nocapture")
            .env(CHILD, "1")
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
