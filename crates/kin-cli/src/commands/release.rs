// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs2::FileExt;
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, ChangeStore, EntityDelta, EntityStore, FilePathId,
    GraphStore, Hash256, RelationDelta, ResolvedSourceEntry, SemanticChange, SemanticChangeId,
    SourceEntryKind, SourceTreeResolution, Timestamp, Visibility, WorkId, WorkStore,
};

const PENDING_RELEASE_SCHEMA: u32 = 1;
const MAX_PENDING_RELEASE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PendingRelease {
    schema: u32,
    tag: String,
    branch_name: String,
    change_id: String,
    /// The complete `/graph/commit` body. Keeping it as one string preserves
    /// exact request bytes across retries and later CLI process invocations.
    request_json: String,
}

impl PendingRelease {
    fn new(
        tag: String,
        branch_name: String,
        change_id: SemanticChangeId,
        request_bytes: Vec<u8>,
    ) -> Result<Self> {
        let request_json = String::from_utf8(request_bytes)
            .context("serialized daemon release request was not UTF-8 JSON")?;
        let pending = Self {
            schema: PENDING_RELEASE_SCHEMA,
            tag,
            branch_name,
            change_id: change_id.to_string(),
            request_json,
        };
        pending.validate()?;
        Ok(pending)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != PENDING_RELEASE_SCHEMA {
            anyhow::bail!(
                "unsupported pending release schema {} (expected {})",
                self.schema,
                PENDING_RELEASE_SCHEMA
            );
        }
        if u64::try_from(self.request_json.len()).unwrap_or(u64::MAX) > MAX_PENDING_RELEASE_BYTES {
            anyhow::bail!("pending release request exceeds the 4 MiB safety limit");
        }
        let request: serde_json::Value = serde_json::from_str(&self.request_json)
            .context("pending release request is not valid JSON")?;
        let request_branch = request
            .get("branch_name")
            .and_then(serde_json::Value::as_str)
            .context("pending release request has no branch_name")?;
        let request_change: SemanticChange = serde_json::from_value(
            request
                .get("change")
                .cloned()
                .context("pending release request has no change")?,
        )
        .context("pending release request has an invalid semantic change")?;
        if request_branch != self.branch_name || request_change.id.to_string() != self.change_id {
            anyhow::bail!("pending release envelope does not match its serialized daemon request");
        }
        let expected_message_prefix = format!("release: {} (", self.tag);
        if request_change.author.to_string() != "kin-release"
            || !request_change.message.starts_with(&expected_message_prefix)
            || request_change.parents.len() != 1
            || request_change.authored_on.as_ref().map(ToString::to_string)
                != Some(self.branch_name.clone())
        {
            anyhow::bail!("pending release payload is not a one-parent Kin release marker");
        }
        let policy = request
            .get("release_policy")
            .and_then(serde_json::Value::as_object)
            .context("pending release payload has no daemon release policy")?;
        if ["force", "require_proof", "require_approval"]
            .iter()
            .any(|field| {
                policy
                    .get(*field)
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
            })
        {
            anyhow::bail!("pending release payload has an invalid daemon release policy");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
}

#[derive(Debug)]
struct LoadedPendingRelease {
    pending: PendingRelease,
    file: File,
    identity: ReleaseFileIdentity,
}

impl std::ops::Deref for LoadedPendingRelease {
    type Target = PendingRelease;

    fn deref(&self) -> &Self::Target {
        &self.pending
    }
}

#[cfg(unix)]
fn release_file_identity(file: &File) -> std::io::Result<ReleaseFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "release control object is not a regular file",
        ));
    }
    Ok(ReleaseFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn release_file_identity(file: &File) -> std::io::Result<ReleaseFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO,
    };

    let handle = file.as_raw_handle().cast();
    let mut attributes: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(std::io::Error::other(
            "release control object is a directory or reparse point",
        ));
    }
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let identity = ReleaseFileIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    };
    if identity.volume_serial == 0 || identity.file_id.iter().all(|byte| *byte == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "release control object has a zero Windows FILE_ID_128 identity",
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
fn open_windows_release_file(
    path: &Path,
    desired_access: u32,
    creation_disposition: u32,
) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            creation_disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    release_file_identity(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_windows_release_directory(path: &Path) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_handle(handle.cast()) };
    let mut attributes: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(std::io::Error::other(
            "release state parent is not an exact non-reparse directory",
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn rename_windows_release_handle(
    source: &File,
    destination_parent: &File,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, FILE_RENAME_INFO,
    };

    let wide = destination_name.encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pending release tombstone has an invalid Windows name",
        ));
    }
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| std::io::Error::other("pending release tombstone length overflow"))?;
    let buffer_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u16>()))
        .ok_or_else(|| std::io::Error::other("pending release rename buffer overflow"))?;
    let mut storage = vec![0_usize; buffer_bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.Flags = 0;
        (*info).RootDirectory = destination_parent.as_raw_handle().cast();
        (*info).FileNameLength = u32::try_from(name_bytes)
            .map_err(|_| std::io::Error::other("pending release tombstone name is too long"))?;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            wide.len(),
        );
        *std::ptr::addr_of_mut!((*info).FileName)
            .cast::<u16>()
            .add(wide.len()) = 0;
    }
    if unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle().cast(),
            FileRenameInfoEx,
            info.cast(),
            u32::try_from(buffer_bytes)
                .map_err(|_| std::io::Error::other("pending release rename buffer is too large"))?,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn delete_windows_release_handle(source: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle().cast(),
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

#[derive(Debug)]
struct ReleaseTransactionLock {
    file: File,
    path: PathBuf,
    identity: ReleaseFileIdentity,
}

impl ReleaseTransactionLock {
    fn acquire(layout: &kin_core::KinLayout) -> Result<Self> {
        let path = layout.pending_release_lock_path();
        #[cfg(unix)]
        let file = {
            if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
                anyhow::bail!(
                    "pending release lock must not be a symlink: {}",
                    path.display()
                );
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
                .open(&path)
                .with_context(|| format!("open pending release lock {}", path.display()))?
        };
        #[cfg(windows)]
        let file = {
            use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows_sys::Win32::Storage::FileSystem::OPEN_ALWAYS;
            open_windows_release_file(&path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS)
                .with_context(|| format!("open pending release lock {}", path.display()))?
        };
        #[cfg(not(any(unix, windows)))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("open pending release lock {}", path.display()))?;
        let identity = release_file_identity(&file)
            .with_context(|| format!("validate pending release lock {}", path.display()))?;
        file.try_lock_exclusive().with_context(|| {
            format!(
                "another Kin release or recovery is active for {}",
                layout.working_dir().display()
            )
        })?;

        #[cfg(unix)]
        let named = {
            let mut options = OpenOptions::new();
            options.read(true);
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options.open(&path)
        };
        #[cfg(windows)]
        let named = {
            use windows_sys::Win32::Foundation::GENERIC_READ;
            use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
            open_windows_release_file(&path, GENERIC_READ, OPEN_EXISTING)
        };
        #[cfg(not(any(unix, windows)))]
        let named = File::open(&path);
        let named = named.with_context(|| {
            format!(
                "revalidate pending release lock attachment {}",
                path.display()
            )
        })?;
        if release_file_identity(&named)? != identity {
            anyhow::bail!(
                "pending release lock {} changed identity while acquiring",
                path.display()
            );
        }
        recover_pending_release_tombstones(layout)?;
        Ok(Self {
            file,
            path,
            identity,
        })
    }

    /// Prove that the name every cooperating release process opens still
    /// refers to the kernel-locked object. A pathname lock can otherwise be
    /// renamed and replaced after acquisition, allowing another process to
    /// lock the substitute and enter the same release transaction.
    fn revalidate(&self) -> Result<()> {
        #[cfg(unix)]
        let named = {
            let mut options = OpenOptions::new();
            options.read(true);
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options.open(&self.path)
        };
        #[cfg(windows)]
        let named = {
            use windows_sys::Win32::Foundation::GENERIC_READ;
            use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
            open_windows_release_file(&self.path, GENERIC_READ, OPEN_EXISTING)
        };
        #[cfg(not(any(unix, windows)))]
        let named = File::open(&self.path);
        let named = named.with_context(|| {
            format!(
                "revalidate pending release lock attachment {}",
                self.path.display()
            )
        })?;
        if release_file_identity(&named)? != self.identity {
            anyhow::bail!(
                "pending release lock {} was replaced while held; refusing release state mutation",
                self.path.display()
            );
        }
        Ok(())
    }
}

impl Drop for ReleaseTransactionLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync release state directory {}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
fn persist_pending_release(layout: &kin_core::KinLayout, pending: &PendingRelease) -> Result<()> {
    persist_pending_release_with_before_publish(layout, pending, || Ok(()))
}

fn persist_pending_release_with_before_publish<F>(
    layout: &kin_core::KinLayout,
    pending: &PendingRelease,
    before_publish: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    pending.validate()?;
    let path = layout.pending_release_path();
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            anyhow::bail!(
                "pending release state already exists and must be recovered first: {}",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect pending release state {}", path.display()));
        }
    }
    let bytes = serde_json::to_vec_pretty(pending)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PENDING_RELEASE_BYTES {
        anyhow::bail!("pending release state exceeds the 4 MiB safety limit");
    }
    let temporary = layout
        .root()
        .join(format!(".pending-release-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create pending release state {}", temporary.display()))?;
    let write_result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("write pending release state {}", temporary.display()));
    }

    let result = (|| -> Result<()> {
        before_publish()?;
        // The journal is published by creating a second link to the fully
        // synced temporary inode. Unlike rename on Unix, hard_link never
        // replaces a destination created by a racing process.
        fs::hard_link(&temporary, &path).with_context(|| {
            format!(
                "publish pending release state without overwriting {} -> {}",
                temporary.display(),
                path.display()
            )
        })?;
        file.sync_all()
            .with_context(|| format!("sync published pending release state {}", path.display()))?;
        sync_directory(layout.root())?;
        fs::remove_file(&temporary).with_context(|| {
            format!(
                "remove published pending release temporary file {}",
                temporary.display()
            )
        })?;
        sync_directory(layout.root())?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn load_pending_release(layout: &kin_core::KinLayout) -> Result<Option<LoadedPendingRelease>> {
    let path = layout.pending_release_path();
    load_pending_release_path(&path)
}

fn load_pending_release_path(path: &Path) -> Result<Option<LoadedPendingRelease>> {
    #[cfg(unix)]
    let mut file = {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            anyhow::bail!(
                "pending release state must not be a symlink: {}",
                path.display()
            );
        }
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        }
    };
    #[cfg(windows)]
    let mut file = {
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{DELETE, OPEN_EXISTING};
        match open_windows_release_file(path, GENERIC_READ | DELETE, OPEN_EXISTING) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        }
    };
    #[cfg(not(any(unix, windows)))]
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let identity = release_file_identity(&file)
        .with_context(|| format!("validate pending release state {}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_PENDING_RELEASE_BYTES {
        anyhow::bail!("pending release state exceeds the 4 MiB safety limit");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_PENDING_RELEASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PENDING_RELEASE_BYTES {
        anyhow::bail!("pending release state exceeds the 4 MiB safety limit");
    }
    let pending: PendingRelease =
        serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))?;
    pending.validate()?;
    Ok(Some(LoadedPendingRelease {
        pending,
        file,
        identity,
    }))
}

#[cfg(test)]
fn clear_pending_release(layout: &kin_core::KinLayout, expected_change_id: &str) -> Result<()> {
    clear_pending_release_with_before_move(layout, expected_change_id, || Ok(()))
}

fn clear_pending_release_with_before_move<F>(
    layout: &kin_core::KinLayout,
    expected_change_id: &str,
    before_move: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let Some(loaded) = load_pending_release(layout)? else {
        return Ok(());
    };
    if loaded.change_id != expected_change_id {
        anyhow::bail!(
            "refusing to clear pending release {} while finalizing {}",
            loaded.change_id,
            expected_change_id
        );
    }
    if release_file_identity(&loaded.file)? != loaded.identity {
        anyhow::bail!("pending release handle changed identity before cleanup");
    }
    before_move()?;

    #[cfg(not(windows))]
    let pending_path = layout.pending_release_path();
    let tombstone_name = format!(".pending-release-delete-{}.tmp", uuid::Uuid::new_v4());
    let tombstone_path = layout.root().join(&tombstone_name);

    #[cfg(unix)]
    {
        let parent = rustix::fs::open(
            layout.root(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(std::fs::File::from)
        .with_context(|| format!("open release state directory {}", layout.root().display()))?;
        let pending_name = pending_path
            .file_name()
            .context("pending release path has no file name")?;
        rustix::fs::renameat_with(
            &parent,
            pending_name,
            &parent,
            std::ffi::OsStr::new(&tombstone_name),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .with_context(|| {
            format!(
                "move pending release into private tombstone {}",
                tombstone_path.display()
            )
        })?;
        rustix::fs::fsync(&parent)
            .with_context(|| format!("sync release state directory {}", layout.root().display()))?;
    }
    #[cfg(windows)]
    let windows_parent = {
        let parent = open_windows_release_directory(layout.root())
            .with_context(|| format!("open release state directory {}", layout.root().display()))?;
        rename_windows_release_handle(&loaded.file, &parent, std::ffi::OsStr::new(&tombstone_name))
            .with_context(|| {
                format!(
                    "move exact pending release handle into private tombstone {}",
                    tombstone_path.display()
                )
            })?;
        parent
    };
    #[cfg(not(any(unix, windows)))]
    fs::rename(&pending_path, &tombstone_path)?;

    #[cfg(unix)]
    let moved = {
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.open(&tombstone_path)
    };
    #[cfg(windows)]
    let moved = {
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{DELETE, OPEN_EXISTING};
        open_windows_release_file(&tombstone_path, GENERIC_READ | DELETE, OPEN_EXISTING)
    };
    #[cfg(not(any(unix, windows)))]
    let moved = File::open(&tombstone_path);
    let moved = moved.with_context(|| {
        format!(
            "reopen pending release tombstone {}",
            tombstone_path.display()
        )
    })?;
    let moved_identity = release_file_identity(&moved)?;
    if moved_identity != loaded.identity {
        #[cfg(unix)]
        {
            let parent = rustix::fs::open(
                layout.root(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(std::fs::File::from)?;
            let pending_name = pending_path
                .file_name()
                .context("pending release path has no file name")?;
            let _ = rustix::fs::renameat_with(
                &parent,
                std::ffi::OsStr::new(&tombstone_name),
                &parent,
                pending_name,
                rustix::fs::RenameFlags::NOREPLACE,
            );
            let _ = rustix::fs::fsync(&parent);
        }
        anyhow::bail!(
            "pending release changed identity before tombstoning; no unverified object was deleted"
        );
    }

    #[cfg(unix)]
    fs::remove_file(&tombstone_path).with_context(|| {
        format!(
            "unlink identity-verified pending release tombstone {}",
            tombstone_path.display()
        )
    })?;
    #[cfg(windows)]
    {
        delete_windows_release_handle(&loaded.file).with_context(|| {
            format!(
                "delete identity-bound pending release tombstone {}",
                tombstone_path.display()
            )
        })?;
        drop(windows_parent);
    }
    #[cfg(not(any(unix, windows)))]
    fs::remove_file(&tombstone_path)?;
    sync_directory(layout.root())
}

fn recover_pending_release_tombstones(layout: &kin_core::KinLayout) -> Result<()> {
    let mut tombstones = fs::read_dir(layout.root())?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            name.to_str()
                .is_some_and(|name| {
                    name.starts_with(".pending-release-delete-") && name.ends_with(".tmp")
                })
                .then(|| entry.path())
        })
        .collect::<Vec<_>>();
    tombstones.sort();
    for path in tombstones {
        let loaded = load_pending_release_path(&path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "pending release tombstone disappeared during recovery: {}",
                path.display()
            )
        })?;
        if release_file_identity(&loaded.file)? != loaded.identity {
            anyhow::bail!(
                "pending release tombstone changed identity during recovery: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        fs::remove_file(&path).with_context(|| {
            format!(
                "remove identity-verified pending release tombstone {}",
                path.display()
            )
        })?;
        #[cfg(windows)]
        delete_windows_release_handle(&loaded.file).with_context(|| {
            format!(
                "remove identity-bound pending release tombstone {}",
                path.display()
            )
        })?;
        #[cfg(not(any(unix, windows)))]
        fs::remove_file(&path)?;
    }
    sync_directory(layout.root())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReleaseAttempt {
    First,
    Recovery,
}

fn clear_pending_after_failure(
    attempt: PendingReleaseAttempt,
    kind: crate::backend::DaemonReleaseFailureKind,
    safe_to_abandon: bool,
) -> bool {
    // A first-attempt definitive rejection never became authority. A recovered
    // journal is cleared only when the daemon's serialized stale-head response
    // proved this exact change absent; ordinary policy/auth failures cannot
    // reconcile an earlier uncertain attempt and retain the journal.
    kind == crate::backend::DaemonReleaseFailureKind::Definitive
        && (attempt == PendingReleaseAttempt::First || safe_to_abandon)
}

async fn send_pending_release(
    layout: &kin_core::KinLayout,
    pending: &PendingRelease,
    attempt: PendingReleaseAttempt,
    transaction: &ReleaseTransactionLock,
) -> Result<()> {
    transaction.revalidate()?;
    match crate::backend::require_daemon_release_commit(
        layout,
        pending.request_json.as_bytes(),
        &pending.branch_name,
    )
    .await
    {
        Ok(()) => clear_pending_release_with_before_move(layout, &pending.change_id, || {
            transaction.revalidate()
        }),
        Err(error) => {
            if clear_pending_after_failure(attempt, error.kind, error.safe_to_abandon) {
                clear_pending_release_with_before_move(layout, &pending.change_id, || {
                    transaction.revalidate()
                })
                .with_context(|| {
                    format!(
                        "daemon definitively rejected release, but pending state cleanup failed: {error}"
                    )
                })?;
                return Err(anyhow::Error::new(error).context(format!(
                    "release request {} was definitively not applied; its pending journal was cleared safely and a later invocation may build a new marker",
                    pending.change_id
                )));
            }
            Err(anyhow::Error::new(error).context(format!(
                "release request {} remains recoverable at {}",
                pending.change_id,
                layout.pending_release_path().display()
            )))
        }
    }
}

fn added_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::AddedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::AddedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::AddedSymlink,
    }
}

fn modified_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::ModifiedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::ModifiedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::ModifiedSymlink,
    }
}

fn require_exact_source_tree<G: GraphStore>(
    graph: &G,
    head: &SemanticChangeId,
) -> Result<HashMap<FilePathId, ResolvedSourceEntry>> {
    match graph.resolve_source_tree_at(head)? {
        SourceTreeResolution::Exact { entries } => Ok(entries),
        SourceTreeResolution::Incomplete { gaps } => {
            let gaps = gaps
                .iter()
                .map(|gap| format!("{}@{}:{:?}", gap.file_id, gap.change_id, gap.reason))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "rollback requires exact source history at {head}, but found unresolved gaps: {gaps}"
            )
        }
    }
}

fn exact_source_tree_correction(
    current: &HashMap<FilePathId, ResolvedSourceEntry>,
    desired: &HashMap<FilePathId, ResolvedSourceEntry>,
) -> Vec<ArtifactDelta> {
    let mut deltas = Vec::new();
    for (path, old) in current {
        if !desired.contains_key(path) {
            deltas.push(ArtifactDelta {
                file_id: path.clone(),
                kind: ArtifactDeltaKind::Removed,
                old_hash: Some(old.hash),
                new_hash: None,
            });
        }
    }
    for (path, new) in desired {
        match current.get(path) {
            Some(old) if old == new => {}
            Some(old) => deltas.push(ArtifactDelta {
                file_id: path.clone(),
                kind: modified_artifact_kind(new.kind),
                old_hash: Some(old.hash),
                new_hash: Some(new.hash),
            }),
            None => deltas.push(ArtifactDelta {
                file_id: path.clone(),
                kind: added_artifact_kind(new.kind),
                old_hash: None,
                new_hash: Some(new.hash),
            }),
        }
    }
    deltas.sort_by(|left, right| left.file_id.0.cmp(&right.file_id.0));
    deltas
}

fn prior_exact_source_entry<G: GraphStore>(
    graph: &G,
    change: &SemanticChange,
    delta: &ArtifactDelta,
) -> Result<ResolvedSourceEntry> {
    let old_hash = delta.old_hash.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot exactly reverse source delta for {} in {}: old content hash is missing",
            delta.file_id,
            change.id
        )
    })?;
    let mut candidates = Vec::new();
    for parent in &change.parents {
        if let Some(entry) = require_exact_source_tree(graph, parent)?.get(&delta.file_id) {
            if entry.hash == old_hash && !candidates.contains(entry) {
                candidates.push(*entry);
            }
        }
    }
    match candidates.as_slice() {
        [entry] => Ok(*entry),
        [] => anyhow::bail!(
            "cannot exactly reverse source delta for {} in {}: no parent carries old hash {}",
            delta.file_id,
            change.id,
            old_hash
        ),
        _ => anyhow::bail!(
            "cannot exactly reverse source delta for {} in {}: parent history gives ambiguous entry kinds for old hash {}",
            delta.file_id,
            change.id,
            old_hash
        ),
    }
}

/// Semver bump level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SemverBump {
    Patch,
    Minor,
    Major,
}

impl std::fmt::Display for SemverBump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SemverBump::Patch => write!(f, "patch"),
            SemverBump::Minor => write!(f, "minor"),
            SemverBump::Major => write!(f, "major"),
        }
    }
}

/// Analyze entity changes since the last tag and suggest a semver bump.
///
/// `kin semver` walks the change history from HEAD back to the genesis
/// (or a future tag mechanism), classifying each entity delta:
///   - Removed public entity -> major (breaking)
///   - Modified public entity signature -> major (breaking)
///   - Added public entity -> minor (additive)
///   - Modified private/internal -> patch
///   - Any other modification -> patch
pub async fn semver() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin semver").await?;
    let graph = &*_snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    // Walk change history from HEAD
    let changes = collect_changes_from_head(&graph, &branch.head, 100)?;

    if changes.is_empty() {
        println!("No changes found on branch '{}'.", branch_name);
        return Ok(());
    }

    let mut max_bump = SemverBump::Patch;
    let mut breaking_reasons: Vec<String> = Vec::new();
    let mut additive_count = 0u32;
    let mut patch_count = 0u32;

    for change in &changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Removed(id) => {
                    // Removing any entity is potentially breaking.
                    // We'd need the entity to check visibility, but since it's removed
                    // we treat removal as breaking.
                    breaking_reasons.push(format!("removed entity {}", id));
                    max_bump = SemverBump::Major;
                }
                EntityDelta::Modified { old, new } => {
                    if old.visibility == Visibility::Public
                        && old.fingerprint.signature_hash != new.fingerprint.signature_hash
                    {
                        breaking_reasons.push(format!("changed public signature: {}", old.name));
                        max_bump = max_bump.max(SemverBump::Major);
                    } else if old.visibility == Visibility::Public
                        && new.visibility != Visibility::Public
                    {
                        breaking_reasons.push(format!(
                            "reduced visibility: {} (public -> {:?})",
                            old.name, new.visibility
                        ));
                        max_bump = max_bump.max(SemverBump::Major);
                    } else {
                        patch_count += 1;
                    }
                }
                EntityDelta::Added(entity) => {
                    if entity.visibility == Visibility::Public {
                        additive_count += 1;
                        max_bump = max_bump.max(SemverBump::Minor);
                    } else {
                        patch_count += 1;
                    }
                }
            }
        }
    }

    println!("Semver analysis for branch '{}':", branch_name);
    println!("  Changes analyzed: {}", changes.len());
    println!("  Suggested bump:   {}", max_bump);
    println!();

    if !breaking_reasons.is_empty() {
        println!("  Breaking changes ({}):", breaking_reasons.len());
        for reason in &breaking_reasons {
            println!("    - {}", reason);
        }
    }
    if additive_count > 0 {
        println!("  Additive (new public entities): {}", additive_count);
    }
    if patch_count > 0 {
        println!("  Patch-level modifications:      {}", patch_count);
    }

    Ok(())
}

/// Release gating options.
#[derive(Default)]
pub struct ReleaseOptions {
    pub force: bool,
    pub require_proof: bool,
    pub require_approval: bool,
}

/// Create a release change that snapshots the current entity graph state.
///
/// `kin release <tag>` creates a special SemanticChange with a release message
/// that marks the current graph state as a versioned release point.
///
/// Gating checks:
///   - Coverage ratio < 0.5 warns and requires `--force` to proceed
///   - `--require-proof`: blocks if any entity in the change lacks linked passing tests
///   - `--require-approval`: blocks if any non-root change lacks human approval
pub async fn release_with_options(tag: String, opts: ReleaseOptions) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    // Hold one repo-scoped lock across recovery, advisory preflight, marker
    // construction, and publication. A concurrent CLI must not observe an
    // uncertain request and manufacture a second marker from a newer head.
    let release_transaction = ReleaseTransactionLock::acquire(&layout)?;
    release_transaction.revalidate()?;
    if let Some(pending) = load_pending_release(&layout)? {
        let requested_tag_is_pending = pending.tag == tag;
        eprintln!(
            "Recovering pending release '{}' with exact change {} before creating any new marker.",
            pending.tag, pending.change_id
        );
        send_pending_release(
            &layout,
            &pending,
            PendingReleaseAttempt::Recovery,
            &release_transaction,
        )
        .await?;
        println!(
            "Recovered durable release '{}' on branch '{}'.",
            pending.tag, pending.branch_name
        );
        println!("  Change: {}", pending.change_id);
        if requested_tag_is_pending {
            return Ok(());
        }
    }
    if tag.trim().is_empty() || tag != tag.trim() || tag.chars().any(char::is_control) {
        anyhow::bail!("release tag must be non-empty, trimmed, and contain no control characters");
    }

    let snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin release").await?;
    let graph = &*snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    // Release policy and marker metadata must describe the immutable branch
    // parent, never ambient graph overlays that are not reachable from it.
    let source_state = graph.resolve_graph_at(&branch.head)?;
    let source_entities = source_state.entities;

    // Gating: coverage ratio check
    let summary =
        kin_review::source_bound_release_proof_coverage_for_entities(source_entities.values());
    if summary.coverage_ratio < 0.5 {
        if opts.force {
            eprintln!(
                "Warning: immutable source-bound proof coverage {:.1}% is below 50%; proceeding with --force.",
                summary.coverage_ratio * 100.0
            );
        } else {
            anyhow::bail!(
                "Release blocked: immutable source-bound proof coverage {:.1}% is below 50%. Verification runs are not yet bound to a source change; use --force to override the coverage gate.",
                summary.coverage_ratio * 100.0
            );
        }
    }

    // Gating: --require-proof
    if opts.require_proof && !summary.missing_proof.is_empty() {
        let missing_names: Vec<String> = summary
            .missing_proof
            .iter()
            .map(|eid| {
                source_entities
                    .get(eid)
                    .cloned()
                    .map(|entity| entity.name)
                    .unwrap_or_else(|| eid.to_string())
            })
            .collect();
        anyhow::bail!(
            "Release blocked: {} entity(ies) lack immutable source-bound passing proof: {}",
            summary.missing_proof.len(),
            missing_names.join(", ")
        );
    }

    // Gating: --require-approval (every reachable non-root change needs a human approval)
    if opts.require_approval {
        let unapproved = kin_review::unapproved_changes(graph, &branch.head, usize::MAX)?;
        if !unapproved.is_empty() {
            let detail = unapproved
                .iter()
                .map(|c| format!("{} ({})", c.change_id, c.author))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "Release blocked: {} non-root change(s) lack human approval: {}",
                unapproved.len(),
                detail
            );
        }
    }

    // Build a release change — empty deltas, just a marker with entity count snapshot
    let mut release_change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        parents: vec![branch.head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-release"),
        message: format!(
            "release: {} ({} entities snapshot)",
            tag,
            source_entities.len()
        ),
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        artifact_deltas: Vec::new(),
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        authored_on: Some(branch_name.clone()),
    };
    release_change.id = kin_core::compute_semantic_change_id(&release_change)?;
    let change_id = release_change.id;

    let request_bytes = crate::backend::serialize_daemon_release_request(
        &release_change,
        &branch_name.to_string(),
        opts.force,
        opts.require_proof,
        opts.require_approval,
    )?;
    let pending = PendingRelease::new(
        tag.clone(),
        branch_name.to_string(),
        change_id,
        request_bytes,
    )?;
    // Persist before the first byte can reach the daemon. Any timeout, 5xx, or
    // client death after this point is resumed with this exact payload.
    persist_pending_release_with_before_publish(&layout, &pending, || {
        release_transaction.revalidate()
    })?;
    send_pending_release(
        &layout,
        &pending,
        PendingReleaseAttempt::First,
        &release_transaction,
    )
    .await?;
    println!("Daemon accepted release change.");

    println!("Release '{}' created on branch '{}'.", tag, branch_name);
    println!("  Change: {}", change_id);
    println!("  Entities: {}", source_entities.len());
    println!("  Parent: {}", branch.head);

    Ok(())
}

/// Revert to a previous semantic change, restoring entity graph state.
///
/// `kin rollback <change_id>` creates a new change that reverses entity deltas
/// from HEAD back to the specified change.
///
/// `kin rollback --feature <work_id>` finds all changes linked to a work item
/// via graph traversal and reverses them in topological order.
pub async fn rollback_with_options(change_id_str: String, feature: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin rollback").await?;
    let graph = &*snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    // Feature-based rollback: find all changes linked to a work item
    if let Some(work_id_str) = feature {
        let work_uuid = uuid::Uuid::parse_str(&work_id_str)
            .map_err(|e| anyhow::anyhow!("invalid work ID '{}': {}", work_id_str, e))?;
        let work_id = WorkId(work_uuid);

        let work_item = graph
            .get_work_item(&work_id)?
            .ok_or_else(|| anyhow::anyhow!("work item '{}' not found", work_id_str))?;

        // Walk HEAD history and find changes that reference the work item
        let all_changes = collect_changes_from_head(&graph, &branch.head, 200)?;

        // Collect changes whose message references the work item ID
        let mut feature_changes: Vec<&SemanticChange> = Vec::new();
        for change in &all_changes {
            // Check if this change's message references the work item
            if change.message.contains(&work_id_str) {
                feature_changes.push(change);
            }
        }

        if feature_changes.is_empty() {
            println!(
                "No changes found linked to work item '{}' ({}).",
                work_item.title, work_id_str
            );
            return Ok(());
        }

        println!(
            "Rolling back {} change(s) linked to work item '{}' ({}):",
            feature_changes.len(),
            work_item.title,
            work_id_str
        );

        // Reverse in topological order (newest first — already in HEAD-first order)
        let mut reversed_entity_deltas = Vec::new();
        let mut reversed_relation_deltas = Vec::new();
        let current_source_tree = require_exact_source_tree(graph, &branch.head)?;
        let mut desired_source_tree = current_source_tree.clone();

        for change in &feature_changes {
            println!("  reverting: {} - {}", change.id, change.message);
            for delta in &change.entity_deltas {
                let reversed = match delta {
                    EntityDelta::Added(entity) => EntityDelta::Removed(entity.id),
                    EntityDelta::Removed(id) => {
                        if let Some(entity) = graph.get_entity(id)? {
                            EntityDelta::Added(entity)
                        } else {
                            continue;
                        }
                    }
                    EntityDelta::Modified { old, new } => EntityDelta::Modified {
                        old: new.clone(),
                        new: old.clone(),
                    },
                };
                reversed_entity_deltas.push(reversed);
            }
            for delta in &change.relation_deltas {
                let reversed = match delta {
                    RelationDelta::Added(rel) => RelationDelta::Removed(rel.id),
                    RelationDelta::Removed(_id) => continue,
                };
                reversed_relation_deltas.push(reversed);
            }
            for delta in &change.artifact_deltas {
                if delta.kind.is_added() {
                    desired_source_tree.remove(&delta.file_id);
                } else if delta.kind.is_removed() || delta.kind.is_modified() {
                    desired_source_tree.insert(
                        delta.file_id.clone(),
                        prior_exact_source_entry(graph, change, delta)?,
                    );
                } else {
                    anyhow::bail!(
                        "cannot reverse unsupported source delta {:?} for {} in {}",
                        delta.kind,
                        delta.file_id,
                        change.id
                    );
                }
            }
        }
        let reversed_artifact_deltas =
            exact_source_tree_correction(&current_source_tree, &desired_source_tree);

        let rollback_message = format!(
            "rollback: revert feature '{}' ({} change(s))",
            work_item.title,
            feature_changes.len()
        );
        let mut rollback_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![branch.head],
            timestamp: Timestamp::now(),
            author: AuthorId::new("kin-rollback"),
            message: rollback_message,
            entity_deltas: reversed_entity_deltas,
            relation_deltas: reversed_relation_deltas,
            artifact_deltas: reversed_artifact_deltas,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        rollback_change.id = kin_core::compute_semantic_change_id(&rollback_change)?;
        let rollback_change_id = rollback_change.id;

        for delta in &rollback_change.entity_deltas {
            match delta {
                EntityDelta::Added(entity) => {
                    graph.upsert_entity(entity)?;
                }
                EntityDelta::Removed(id) => {
                    graph.remove_entity(id)?;
                }
                EntityDelta::Modified { new, .. } => {
                    graph.upsert_entity(new)?;
                }
            }
        }
        for delta in &rollback_change.relation_deltas {
            match delta {
                RelationDelta::Added(rel) => {
                    graph.upsert_relation(rel)?;
                }
                RelationDelta::Removed(id) => {
                    graph.remove_relation(id)?;
                }
            }
        }

        crate::backend::require_daemon_commit(&layout, &rollback_change, &branch_name.to_string())
            .await?;
        println!("Snapshot saved.");

        println!("  Rollback change: {}", rollback_change_id);
        println!(
            "  Entity deltas reversed: {}",
            rollback_change.entity_deltas.len()
        );

        return Ok(());
    }

    let target_id = SemanticChangeId::from_hash(
        Hash256::from_hex(&change_id_str)
            .map_err(|e| anyhow::anyhow!("invalid change ID '{}': {}", change_id_str, e))?,
    );

    // Verify target change exists
    let target_change = graph
        .get_change(&target_id)?
        .ok_or_else(|| anyhow::anyhow!("change '{}' not found", change_id_str))?;

    // Get changes between target and HEAD (these are the ones we want to reverse)
    let changes_to_reverse = graph.get_changes_since(&target_id, &branch.head)?;

    if changes_to_reverse.is_empty() {
        println!(
            "Already at change '{}', nothing to rollback.",
            change_id_str
        );
        return Ok(());
    }

    // Build reversed deltas: walk changes in reverse, invert each delta
    let mut reversed_entity_deltas = Vec::new();
    let mut reversed_relation_deltas = Vec::new();
    let current_source_tree = require_exact_source_tree(graph, &branch.head)?;
    let target_source_tree = require_exact_source_tree(graph, &target_id)?;
    let reversed_artifact_deltas =
        exact_source_tree_correction(&current_source_tree, &target_source_tree);

    for change in changes_to_reverse.iter().rev() {
        for delta in &change.entity_deltas {
            let reversed = match delta {
                EntityDelta::Added(entity) => EntityDelta::Removed(entity.id),
                EntityDelta::Removed(id) => {
                    // We need the entity to restore it — try to get from graph
                    if let Some(entity) = graph.get_entity(id)? {
                        EntityDelta::Added(entity)
                    } else {
                        // Entity already gone, skip
                        continue;
                    }
                }
                EntityDelta::Modified { old, new } => EntityDelta::Modified {
                    old: new.clone(),
                    new: old.clone(),
                },
            };
            reversed_entity_deltas.push(reversed);
        }

        for delta in &change.relation_deltas {
            let reversed = match delta {
                RelationDelta::Added(rel) => RelationDelta::Removed(rel.id),
                RelationDelta::Removed(id) => {
                    // Cannot restore removed relations without the full relation data.
                    // Log and skip.
                    eprintln!("  warning: cannot restore removed relation {}", id);
                    continue;
                }
            };
            reversed_relation_deltas.push(reversed);
        }
    }

    // Create the rollback change
    let rollback_message = format!(
        "rollback: revert {} change(s) to {}",
        changes_to_reverse.len(),
        &change_id_str[..change_id_str.len().min(12)]
    );
    let mut rollback_change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        parents: vec![branch.head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-rollback"),
        message: rollback_message,
        entity_deltas: reversed_entity_deltas,
        relation_deltas: reversed_relation_deltas,
        artifact_deltas: reversed_artifact_deltas,
        projected_files: target_change.projected_files.clone(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        authored_on: Some(branch_name.clone()),
    };
    rollback_change.id = kin_core::compute_semantic_change_id(&rollback_change)?;
    let rollback_change_id = rollback_change.id;

    // Apply reversed entity deltas to the graph
    for delta in &rollback_change.entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                graph.upsert_entity(entity)?;
            }
            EntityDelta::Removed(id) => {
                graph.remove_entity(id)?;
            }
            EntityDelta::Modified { new, .. } => {
                graph.upsert_entity(new)?;
            }
        }
    }

    for delta in &rollback_change.relation_deltas {
        match delta {
            RelationDelta::Added(rel) => {
                graph.upsert_relation(rel)?;
            }
            RelationDelta::Removed(id) => {
                graph.remove_relation(id)?;
            }
        }
    }

    crate::backend::require_daemon_commit(&layout, &rollback_change, &branch_name.to_string())
        .await?;
    println!("Snapshot saved.");

    println!(
        "Rolled back {} change(s) on branch '{}'.",
        changes_to_reverse.len(),
        branch_name
    );
    println!(
        "  Target:   {} - {}",
        target_change.id, target_change.message
    );
    println!("  Rollback: {}", rollback_change_id);
    println!(
        "  Entity deltas reversed: {}",
        rollback_change.entity_deltas.len()
    );

    Ok(())
}

/// Walk change history from HEAD, collecting up to `limit` changes.
fn collect_changes_from_head<G: GraphStore>(
    graph: &G,
    head: &SemanticChangeId,
    limit: usize,
) -> Result<Vec<SemanticChange>> {
    let mut changes = Vec::new();
    let mut current = *head;

    for _ in 0..limit {
        match graph.get_change(&current)? {
            Some(change) => {
                let parents = change.parents.clone();
                changes.push(change);
                // Follow first parent (linear history)
                if let Some(parent) = parents.first() {
                    current = *parent;
                } else {
                    break; // Genesis
                }
            }
            None => break,
        }
    }

    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_release_fixture() -> (SemanticChange, Vec<u8>) {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32])),
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("kin-release"),
            message: "release: v0.3.0 (1 entities snapshot)".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(kin_model::BranchName::new("main")),
        };
        let request =
            crate::backend::serialize_daemon_release_request(&change, "main", true, true, true)
                .unwrap();
        (change, request)
    }

    #[test]
    fn pending_release_roundtrip_preserves_exact_request_bytes() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let (change, request) = pending_release_fixture();
        let pending = PendingRelease::new(
            "v0.3.0".to_string(),
            "main".to_string(),
            change.id,
            request.clone(),
        )
        .unwrap();

        persist_pending_release(&layout, &pending).unwrap();
        let recovered = load_pending_release(&layout).unwrap().unwrap();
        assert_eq!(recovered.pending, pending);
        assert_eq!(recovered.request_json.as_bytes(), request);
        clear_pending_release(&layout, &change.id.to_string()).unwrap();
        assert!(load_pending_release(&layout).unwrap().is_none());
    }

    #[test]
    fn pending_release_rejects_envelope_payload_mismatch() {
        let (change, request) = pending_release_fixture();
        let mut pending =
            PendingRelease::new("v0.3.0".to_string(), "main".to_string(), change.id, request)
                .unwrap();
        pending.change_id =
            SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32])).to_string();
        assert!(pending.validate().is_err());
    }

    #[test]
    fn pending_release_publish_never_overwrites_raced_state() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let (change, request) = pending_release_fixture();
        let pending =
            PendingRelease::new("v0.3.0".to_string(), "main".to_string(), change.id, request)
                .unwrap();
        let raced_bytes = b"raced pending state";

        let error = persist_pending_release_with_before_publish(&layout, &pending, || {
            fs::write(layout.pending_release_path(), raced_bytes)?;
            Ok(())
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("without overwriting"));
        assert_eq!(
            fs::read(layout.pending_release_path()).unwrap(),
            raced_bytes
        );
        assert_eq!(
            fs::read_dir(layout.root())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".pending-release-")
                })
                .count(),
            0,
            "failed no-clobber publication left a temporary journal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pending_release_cleanup_never_unlinks_an_aba_substitute() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let (change, request) = pending_release_fixture();
        let pending =
            PendingRelease::new("v0.3.0".to_string(), "main".to_string(), change.id, request)
                .unwrap();
        persist_pending_release(&layout, &pending).unwrap();
        let displaced = layout.root().join("displaced-pending-release.json");
        let substitute = b"unrelated substitute bytes";

        let error = clear_pending_release_with_before_move(&layout, &change.id.to_string(), || {
            fs::rename(layout.pending_release_path(), &displaced)?;
            fs::write(layout.pending_release_path(), substitute)?;
            Ok(())
        })
        .unwrap_err();

        assert!(error.to_string().contains("changed identity"));
        assert_eq!(fs::read(layout.pending_release_path()).unwrap(), substitute);
        assert_eq!(
            serde_json::from_slice::<PendingRelease>(&fs::read(displaced).unwrap()).unwrap(),
            pending
        );
        assert_eq!(
            fs::read_dir(layout.root())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pending-release-delete-"))
                .count(),
            0
        );
    }

    #[test]
    fn release_lock_recovers_identity_bound_cleanup_tombstone() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let (change, request) = pending_release_fixture();
        let pending =
            PendingRelease::new("v0.3.0".to_string(), "main".to_string(), change.id, request)
                .unwrap();
        persist_pending_release(&layout, &pending).unwrap();
        let tombstone = layout
            .root()
            .join(".pending-release-delete-crash-recovery.tmp");
        fs::rename(layout.pending_release_path(), &tombstone).unwrap();

        let lock = ReleaseTransactionLock::acquire(&layout).unwrap();

        assert!(!tombstone.exists());
        assert!(!layout.pending_release_path().exists());
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn release_lock_refuses_mutation_after_path_replacement() {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let lock = ReleaseTransactionLock::acquire(&layout).unwrap();
        let displaced = layout.root().join("displaced-release.lock");
        fs::rename(layout.pending_release_lock_path(), &displaced).unwrap();
        fs::write(layout.pending_release_lock_path(), b"substitute lock").unwrap();

        let error = lock.revalidate().unwrap_err();

        assert!(format!("{error:#}").contains("replaced while held"));
        assert!(
            displaced.exists(),
            "the actually locked inode must be retained"
        );
        assert_eq!(
            fs::read(layout.pending_release_lock_path()).unwrap(),
            b"substitute lock"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_pending_release_open_rejects_reparse_point() {
        use std::os::windows::fs::symlink_file;

        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let target = layout.root().join("pending-target.json");
        fs::write(&target, b"not authority").unwrap();
        symlink_file(&target, layout.pending_release_path()).unwrap();

        let error = load_pending_release(&layout).unwrap_err();

        assert!(format!("{error:#}").contains("reparse"));
        assert_eq!(fs::read(&target).unwrap(), b"not authority");
    }

    #[cfg(windows)]
    #[test]
    fn windows_release_lock_rejects_reparse_point() {
        use std::os::windows::fs::symlink_file;

        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let target = layout.root().join("lock-target");
        fs::write(&target, b"not a lock").unwrap();
        let lock_path = layout.pending_release_lock_path();
        let _ = fs::remove_file(&lock_path);
        symlink_file(&target, &lock_path).unwrap();

        let error = ReleaseTransactionLock::acquire(&layout).unwrap_err();

        assert!(format!("{error:#}").contains("reparse"));
        assert_eq!(fs::read(&target).unwrap(), b"not a lock");
    }

    #[test]
    fn recovered_pending_release_clears_only_after_exact_absence_proof() {
        assert!(!clear_pending_after_failure(
            PendingReleaseAttempt::Recovery,
            crate::backend::DaemonReleaseFailureKind::Definitive,
            false,
        ));
        assert!(clear_pending_after_failure(
            PendingReleaseAttempt::Recovery,
            crate::backend::DaemonReleaseFailureKind::Definitive,
            true,
        ));
        assert!(!clear_pending_after_failure(
            PendingReleaseAttempt::Recovery,
            crate::backend::DaemonReleaseFailureKind::Uncertain,
            true,
        ));
        assert!(clear_pending_after_failure(
            PendingReleaseAttempt::First,
            crate::backend::DaemonReleaseFailureKind::Definitive,
            false,
        ));
    }

    #[test]
    fn semver_bump_ordering() {
        assert!(SemverBump::Patch < SemverBump::Minor);
        assert!(SemverBump::Minor < SemverBump::Major);
        assert_eq!(SemverBump::Patch.max(SemverBump::Minor), SemverBump::Minor);
        assert_eq!(SemverBump::Minor.max(SemverBump::Major), SemverBump::Major);
    }

    #[test]
    fn semver_bump_display() {
        assert_eq!(format!("{}", SemverBump::Patch), "patch");
        assert_eq!(format!("{}", SemverBump::Minor), "minor");
        assert_eq!(format!("{}", SemverBump::Major), "major");
    }

    #[test]
    fn exact_source_tree_correction_preserves_modes_additions_and_removals() {
        let first_hash = Hash256::from_bytes([1; 32]);
        let removed_hash = Hash256::from_bytes([2; 32]);
        let added_hash = Hash256::from_bytes([3; 32]);
        let current = HashMap::from([
            (
                FilePathId::new("bin/kin"),
                ResolvedSourceEntry {
                    hash: first_hash,
                    kind: SourceEntryKind::File { executable: false },
                },
            ),
            (
                FilePathId::new("old-link"),
                ResolvedSourceEntry {
                    hash: removed_hash,
                    kind: SourceEntryKind::Symlink,
                },
            ),
        ]);
        let desired = HashMap::from([
            (
                FilePathId::new("bin/kin"),
                ResolvedSourceEntry {
                    hash: first_hash,
                    kind: SourceEntryKind::File { executable: true },
                },
            ),
            (
                FilePathId::new("current"),
                ResolvedSourceEntry {
                    hash: added_hash,
                    kind: SourceEntryKind::Symlink,
                },
            ),
        ]);

        let deltas = exact_source_tree_correction(&current, &desired);
        assert_eq!(deltas.len(), 3);
        assert_eq!(deltas[0].file_id, FilePathId::new("bin/kin"));
        assert_eq!(deltas[0].kind, ArtifactDeltaKind::ModifiedExecutableFile);
        assert_eq!(deltas[0].old_hash, Some(first_hash));
        assert_eq!(deltas[0].new_hash, Some(first_hash));
        assert_eq!(deltas[1].file_id, FilePathId::new("current"));
        assert_eq!(deltas[1].kind, ArtifactDeltaKind::AddedSymlink);
        assert_eq!(deltas[2].file_id, FilePathId::new("old-link"));
        assert_eq!(deltas[2].kind, ArtifactDeltaKind::Removed);
        assert_eq!(deltas[2].old_hash, Some(removed_hash));
    }
}
