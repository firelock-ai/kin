// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Crash-safe publication of registry artifacts.
//!
//! Registry readers must never observe a destination while it is being
//! rewritten. Stage bytes in the destination directory, durably flush them,
//! and only then replace the destination with one atomic rename.

use std::ffi::OsString;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Stable in-process identity for one named authority inside a pinned parent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum AuthorityKey {
    #[cfg(unix)]
    Unix {
        parent_device: u64,
        parent_inode: u64,
        name: OsString,
    },
    #[cfg(not(unix))]
    Path(PathBuf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactIdentity {
    #[cfg(unix)]
    pub(crate) device: u64,
    #[cfg(unix)]
    pub(crate) inode: u64,
    pub(crate) len: u64,
}

/// A registry storage root whose identity remains authoritative for the
/// lifetime of the adapter.
///
/// Unix operations walk only relative, normal components from the retained
/// directory descriptor with `openat(2)` and `O_NOFOLLOW`. Renaming or
/// replacing the configured pathname therefore cannot redirect a live
/// registry. Platforms without descriptor-relative filesystem APIs keep the
/// canonical path and reject reparse points before each operation.
#[derive(Clone)]
pub(crate) struct AuthorityRoot {
    path: PathBuf,
    inner: Arc<AuthorityRootInner>,
}

enum AuthorityRootInner {
    #[cfg(unix)]
    Unix(File),
    #[cfg(not(unix))]
    Path,
    Failed {
        kind: io::ErrorKind,
        message: String,
    },
}

impl std::fmt::Debug for AuthorityRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityRoot")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AuthorityRoot {
    /// Pin and create a configured root. Construction stays infallible for the
    /// existing public state constructors, but any initialization failure is
    /// retained and makes every later storage operation fail closed.
    pub(crate) fn new(path: &Path) -> Self {
        match Self::try_new(path) {
            Ok(root) => root,
            Err(error) => Self {
                path: path.to_path_buf(),
                inner: Arc::new(AuthorityRootInner::Failed {
                    kind: error.kind(),
                    message: error.to_string(),
                }),
            },
        }
    }

    fn try_new(path: &Path) -> io::Result<Self> {
        let path = pin_authority_root(path)?;
        ensure_directory_durable(&path)?;
        #[cfg(unix)]
        let inner = AuthorityRootInner::Unix(open_or_create_directory(&path)?.file);
        #[cfg(not(unix))]
        let inner = {
            reject_reparse_components(&path)?;
            AuthorityRootInner::Path
        };
        Ok(Self {
            path,
            inner: Arc::new(inner),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn initialization_error(&self) -> Option<io::Error> {
        match self.inner.as_ref() {
            AuthorityRootInner::Failed { kind, message } => {
                Some(io::Error::new(*kind, message.clone()))
            }
            #[cfg(unix)]
            AuthorityRootInner::Unix(_) => None,
            #[cfg(not(unix))]
            AuthorityRootInner::Path => None,
        }
    }

    fn validate_relative(relative: &Path, allow_empty: bool) -> io::Result<()> {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || (!allow_empty && relative.as_os_str().is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry authority paths must contain only relative normal components",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn unix_root(&self) -> io::Result<&File> {
        match self.inner.as_ref() {
            AuthorityRootInner::Unix(file) => Ok(file),
            AuthorityRootInner::Failed { kind, message } => {
                Err(io::Error::new(*kind, message.clone()))
            }
        }
    }

    #[cfg(unix)]
    fn directory(&self, relative: &Path, create: bool) -> io::Result<File> {
        Self::validate_relative(relative, true)?;
        let mut current = self.unix_root()?.try_clone()?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                unreachable!("relative path was validated")
            };
            let next = match open_directory_at(&current, name) {
                Ok(next) => next,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    mkdir_at(&current, name)?;
                    current.sync_all()?;
                    open_directory_at(&current, name)?
                }
                Err(error) => return Err(error),
            };
            current = next;
        }
        Ok(current)
    }

    #[cfg(unix)]
    fn parent_and_name(&self, relative: &Path, create: bool) -> io::Result<(File, OsString)> {
        Self::validate_relative(relative, false)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let name = relative
            .file_name()
            .expect("validated non-empty relative path")
            .to_os_string();
        Ok((self.directory(parent, create)?, name))
    }

    pub(crate) fn ensure_directory(&self, relative: &Path) -> io::Result<()> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, true)?;
        #[cfg(unix)]
        {
            let _ = self.directory(relative, true)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(relative);
            ensure_directory_durable(&path)?;
            reject_reparse_components(&self.path)?;
            reject_reparse_components(&path)
        }
    }

    pub(crate) fn read(&self, relative: &Path) -> io::Result<Vec<u8>> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, name) = self.parent_and_name(relative, false)?;
            let mut file = open_file_at(&parent, &name, libc::O_RDONLY, 0)?;
            validate_regular_file(&file, "registry artifact")?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let path = self.path.join(relative);
            reject_reparse_or_non_file(&path, "registry artifact")?;
            std::fs::read(path)
        }
    }

    pub(crate) fn open_read(&self, relative: &Path) -> io::Result<File> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, name) = self.parent_and_name(relative, false)?;
            let file = open_file_at(&parent, &name, libc::O_RDONLY, 0)?;
            validate_regular_file(&file, "registry artifact")?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let path = self.path.join(relative);
            reject_reparse_or_non_file(&path, "registry artifact")?;
            File::open(path)
        }
    }

    pub(crate) fn open_append(&self, relative: &Path) -> io::Result<File> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, name) = self.parent_and_name(relative, false)?;
            let file = open_file_at(&parent, &name, libc::O_WRONLY | libc::O_APPEND, 0)?;
            validate_regular_file(&file, "registry upload data")?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let path = self.path.join(relative);
            reject_reparse_or_non_file(&path, "registry upload data")?;
            OpenOptions::new().append(true).open(path)
        }
    }

    pub(crate) fn open_write(&self, relative: &Path) -> io::Result<File> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, name) = self.parent_and_name(relative, false)?;
            let file = open_file_at(&parent, &name, libc::O_WRONLY, 0)?;
            validate_regular_file(&file, "registry artifact")?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let path = self.path.join(relative);
            reject_reparse_or_non_file(&path, "registry artifact")?;
            OpenOptions::new().write(true).open(path)
        }
    }

    pub(crate) fn metadata(&self, relative: &Path) -> io::Result<std::fs::Metadata> {
        self.open_read(relative)?.metadata()
    }

    pub(crate) fn identity(&self, relative: &Path) -> io::Result<ArtifactIdentity> {
        let file = self.open_read(relative)?;
        #[cfg(unix)]
        {
            let stat = stat_file(&file)?;
            Ok(ArtifactIdentity {
                device: stat.st_dev as u64,
                inode: stat.st_ino as u64,
                len: stat.st_size as u64,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(ArtifactIdentity {
                len: file.metadata()?.len(),
            })
        }
    }

    pub(crate) fn read_dir_names(&self, relative: &Path) -> io::Result<Vec<OsString>> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, true)?;
        #[cfg(unix)]
        {
            use std::os::fd::{FromRawFd, IntoRawFd};
            use std::os::unix::ffi::OsStrExt;

            let directory = self.directory(relative, false)?;
            let descriptor = directory.into_raw_fd();
            let stream = unsafe { libc::fdopendir(descriptor) };
            if stream.is_null() {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed without taking ownership of the descriptor.
                drop(unsafe { File::from_raw_fd(descriptor) });
                return Err(error);
            }
            struct DirectoryStream(*mut libc::DIR);
            impl Drop for DirectoryStream {
                fn drop(&mut self) {
                    // SAFETY: fdopendir returned this live stream exactly once.
                    unsafe { libc::closedir(self.0) };
                }
            }
            let stream = DirectoryStream(stream);
            let mut names = Vec::new();
            loop {
                // SAFETY: the stream remains live and is accessed by one thread.
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    break;
                }
                // SAFETY: d_name is NUL-terminated for the lifetime of this entry.
                let bytes = unsafe {
                    std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                        .to_bytes()
                        .to_vec()
                };
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                names.push(std::ffi::OsStr::from_bytes(&bytes).to_os_string());
            }
            Ok(names)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            std::fs::read_dir(self.path.join(relative))?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect()
        }
    }

    pub(crate) fn write(&self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, destination_name) = self.parent_and_name(relative, true)?;
            write_at(&parent, &destination_name, bytes)
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            write(&self.path.join(relative), bytes)?;
            reject_reparse_components(&self.path)
        }
    }

    pub(crate) fn remove_file(&self, relative: &Path) -> io::Result<()> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let (parent, name) = self.parent_and_name(relative, false)?;
            match stat_at(&parent, &name) {
                Ok(stat) => {
                    validate_regular_stat(&stat, "registry artifact")?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            }
            let name = name_cstring(&name)?;
            // SAFETY: the retained parent descriptor and relative name are valid.
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            parent.sync_all()
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let path = self.path.join(relative);
            match reject_reparse_or_non_file(&path, "registry artifact") {
                Ok(()) => std::fs::remove_file(path),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(from, false)?;
        Self::validate_relative(to, false)?;
        #[cfg(unix)]
        {
            let (from_parent, from_name) = self.parent_and_name(from, false)?;
            let (to_parent, to_name) = self.parent_and_name(to, true)?;
            validate_regular_stat(&stat_at(&from_parent, &from_name)?, "registry artifact")?;
            match stat_at(&to_parent, &to_name) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "registry destination already exists",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            rename_at(&from_parent, &from_name, &to_parent, &to_name)?;
            to_parent.sync_all()?;
            let from_identity = stat_file(&from_parent)?;
            let to_identity = stat_file(&to_parent)?;
            if from_identity.st_dev != to_identity.st_dev
                || from_identity.st_ino != to_identity.st_ino
            {
                from_parent.sync_all()?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            reject_reparse_components(&self.path)?;
            let from = self.path.join(from);
            let to = self.path.join(to);
            reject_reparse_or_non_file(&from, "registry artifact")?;
            std::fs::rename(from, to)
        }
    }

    pub(crate) fn open_lock_file(&self, relative: &Path) -> io::Result<AnchoredLockFile> {
        if let Some(error) = self.initialization_error() {
            return Err(error);
        }
        Self::validate_relative(relative, false)?;
        #[cfg(unix)]
        {
            let (parent, name) = self.parent_and_name(relative, true)?;
            open_lock_file_in(parent, name)
        }
        #[cfg(not(unix))]
        {
            open_lock_file(&self.path.join(relative))
        }
    }
}

/// Resolve the configured authority root once, then retain the resulting
/// absolute path for every later descriptor-anchored operation.
///
/// This deliberately permits an operator-selected root such as macOS `/var`
/// (a system alias for `/private/var`) without permitting storage operations
/// to follow symlinks in package-controlled descendants. Missing descendants
/// are appended only after the nearest existing ancestor is canonicalized.
pub(crate) fn pin_authority_root(path: &Path) -> io::Result<PathBuf> {
    let mut cursor = path;
    let mut missing = Vec::<OsString>::new();

    loop {
        match cursor.canonicalize() {
            Ok(mut pinned) => {
                for component in missing.into_iter().rev() {
                    pinned.push(component);
                }
                return Ok(pinned);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "registry authority root has no existing ancestor",
                    )
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "registry authority root has no existing ancestor",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// A lock file opened without following the final path component.
pub(crate) struct AnchoredLockFile {
    pub(crate) file: File,
    key: AuthorityKey,
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
    name: OsString,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl AnchoredLockFile {
    pub(crate) fn authority_key(&self) -> AuthorityKey {
        self.key.clone()
    }

    pub(crate) fn verify_named(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let opened = validate_regular_file(&self.file, "registry transaction lock")?;
            let named = validate_regular_stat(
                &stat_at(&self.parent, &self.name)?,
                "registry transaction lock",
            )?;
            if opened != named {
                return Err(io::Error::other(
                    "registry transaction lock changed identity during acquisition",
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            reject_reparse_or_non_file(&self.path, "registry transaction lock")
        }
    }
}

#[cfg(any(test, not(unix)))]
pub(crate) fn open_lock_file(path: &Path) -> io::Result<AnchoredLockFile> {
    #[cfg(unix)]
    {
        let (parent, name) = anchor_named_path(path)?;
        open_lock_file_in(parent.file, name)
    }
    #[cfg(not(unix))]
    {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry transaction lock has no parent directory",
            )
        })?;
        ensure_directory_durable(parent)?;
        reject_reparse_components(parent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        reject_reparse_or_non_file(path, "registry transaction lock")?;
        let key = AuthorityKey::Path(path.canonicalize()?);
        Ok(AnchoredLockFile {
            file,
            key,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
fn open_lock_file_in(parent: File, name: OsString) -> io::Result<AnchoredLockFile> {
    let file = match open_file_at(
        &parent,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_file_at(&parent, &name, libc::O_RDWR, 0o600)?
        }
        Err(error) => return Err(error),
    };
    let opened = validate_regular_file(&file, "registry transaction lock")?;
    let named = validate_regular_stat(&stat_at(&parent, &name)?, "registry transaction lock")?;
    if opened != named {
        return Err(io::Error::other(
            "registry transaction lock changed identity while opening",
        ));
    }
    let parent_stat = stat_file(&parent)?;
    let key = AuthorityKey::Unix {
        parent_device: parent_stat.st_dev as u64,
        parent_inode: parent_stat.st_ino as u64,
        name: name.clone(),
    };
    Ok(AnchoredLockFile {
        file,
        key,
        parent,
        name,
    })
}

#[cfg(any(test, not(unix)))]
pub(crate) fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with_pre_commit(path, bytes, |_| Ok(()))
}

#[cfg(all(test, unix))]
fn write_with_pre_commit_impl<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic registry destination has no parent directory",
        )
    })?;
    let (anchor, destination_name) = anchor_named_path(path)?;
    let (mut staged, staged_name) = create_staged_file(&anchor.file)?;
    let staged_identity = validate_regular_file(&staged, "registry staged artifact")?;
    let staged_path = parent.join(&staged_name);

    let result = (|| {
        staged.write_all(bytes)?;
        staged.flush()?;
        staged.sync_all()?;
        pre_commit(&staged_path)?;
        verify_named_identity(
            &anchor.file,
            &staged_name,
            staged_identity,
            "registry staged artifact",
        )?;
        match stat_at(&anchor.file, &destination_name) {
            Ok(stat) => {
                validate_regular_stat(&stat, "existing registry destination")?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        rename_at(&anchor.file, &staged_name, &anchor.file, &destination_name)?;
        verify_named_identity(
            &anchor.file,
            &destination_name,
            staged_identity,
            "published registry artifact",
        )?;
        anchor.file.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = unlink_if_same(&anchor.file, &staged_name, staged_identity);
    }
    result
}

#[cfg(unix)]
fn write_at(parent: &File, destination_name: &std::ffi::OsStr, bytes: &[u8]) -> io::Result<()> {
    let (mut staged, staged_name) = create_staged_file(parent)?;
    let staged_identity = validate_regular_file(&staged, "registry staged artifact")?;
    let result = (|| {
        staged.write_all(bytes)?;
        staged.flush()?;
        staged.sync_all()?;
        verify_named_identity(
            parent,
            &staged_name,
            staged_identity,
            "registry staged artifact",
        )?;
        match stat_at(parent, destination_name) {
            Ok(stat) => {
                validate_regular_stat(&stat, "existing registry destination")?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        rename_at(parent, &staged_name, parent, destination_name)?;
        verify_named_identity(
            parent,
            destination_name,
            staged_identity,
            "published registry artifact",
        )?;
        parent.sync_all()
    })();
    if result.is_err() {
        let _ = unlink_if_same(parent, &staged_name, staged_identity);
    }
    result
}

#[cfg(not(unix))]
fn write_with_pre_commit_impl<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic registry destination has no parent directory",
        )
    })?;
    ensure_directory_durable(parent)?;
    reject_reparse_components(parent)?;

    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    pre_commit(staged.path())?;
    reject_reparse_components(parent)?;

    let published = staged.persist(path).map_err(|error| error.error)?;
    published.sync_all()?;
    sync_parent(parent)?;
    Ok(())
}

/// Create a directory chain and durably publish each newly-created component.
///
/// Syncing only the final file and its immediate parent is insufficient on a
/// first write: after a power loss, the new parent directory itself can vanish
/// from its parent even though the response was already acknowledged. Build
/// missing components from the first existing ancestor downward and fsync the
/// parent after every directory entry becomes visible.
pub(crate) fn ensure_directory_durable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let _ = open_or_create_directory(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut cursor = path.to_path_buf();
        let mut missing: Vec<PathBuf> = Vec::new();

        loop {
            match std::fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.is_dir() && !metadata_is_reparse(&metadata) => break,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "registry directory path is not a directory: {}",
                            cursor.display()
                        ),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.push(cursor.clone());
                    cursor = cursor
                        .parent()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "registry directory has no existing ancestor",
                            )
                        })?
                        .to_path_buf();
                }
                Err(error) => return Err(error),
            }
        }

        for directory in missing.into_iter().rev() {
            match std::fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = std::fs::symlink_metadata(&directory)?;
                    if !metadata.is_dir() || metadata_is_reparse(&metadata) {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "registry directory path raced with a non-directory: {}",
                                directory.display()
                            ),
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
            if let Some(parent) = directory.parent() {
                sync_parent(parent)?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
struct DirectoryAnchor {
    file: File,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(all(test, unix))]
fn anchor_named_path(path: &Path) -> io::Result<(DirectoryAnchor, OsString)> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry authority path has no parent directory",
        )
    })?;
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry authority path has no filename",
            )
        })?
        .to_os_string();
    Ok((open_or_create_directory(parent)?, name))
}

#[cfg(unix)]
fn open_or_create_directory(path: &Path) -> io::Result<DirectoryAnchor> {
    use std::os::fd::FromRawFd;

    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let start_c = name_cstring(start.as_os_str())?;
    // SAFETY: the path is NUL-terminated and flags request a directory descriptor.
    let fd = unsafe {
        libc::open(
            start_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of the successful descriptor transfers to File.
    let mut current = unsafe { File::from_raw_fd(fd) };

    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "registry directory paths may not contain parent traversal",
                ));
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported registry directory prefix",
                ));
            }
        };
        let next = match open_directory_at(&current, name) {
            Ok(next) => next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mkdir_at(&current, name)?;
                current.sync_all()?;
                open_directory_at(&current, name)?
            }
            Err(error) => return Err(error),
        };
        current = next;
    }
    Ok(DirectoryAnchor { file: current })
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = name_cstring(name)?;
    // SAFETY: parent is a live directory descriptor and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of the successful descriptor transfers to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn mkdir_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let name = name_cstring(name)?;
    // SAFETY: parent is a live directory descriptor and name is NUL-terminated.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(error)
}

#[cfg(unix)]
fn open_file_at(parent: &File, name: &std::ffi::OsStr, flags: i32, mode: u32) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = name_cstring(name)?;
    // SAFETY: parent is live, name is NUL-terminated, and ownership of a successful fd
    // transfers immediately to File.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_staged_file(parent: &File) -> io::Result<(File, OsString)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        let name = OsString::from(format!(
            ".kin-registry-stage-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        match open_file_at(
            parent,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => return Ok((file, name)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique registry staging file",
    ))
}

#[cfg(unix)]
fn rename_at(
    old_parent: &File,
    old_name: &std::ffi::OsStr,
    new_parent: &File,
    new_name: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let old_name = name_cstring(old_name)?;
    let new_name = name_cstring(new_name)?;
    // SAFETY: both descriptors and relative NUL-terminated names remain valid.
    if unsafe {
        libc::renameat(
            old_parent.as_raw_fd(),
            old_name.as_ptr(),
            new_parent.as_raw_fd(),
            new_name.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn unlink_if_same(parent: &File, name: &std::ffi::OsStr, expected: FileIdentity) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let actual = match stat_at(parent, name) {
        Ok(stat) => validate_regular_stat(&stat, "registry staged artifact")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if actual != expected {
        return Ok(());
    }
    let name = name_cstring(name)?;
    // SAFETY: parent is live and name is a relative NUL-terminated component.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn verify_named_identity(
    parent: &File,
    name: &std::ffi::OsStr,
    expected: FileIdentity,
    label: &str,
) -> io::Result<()> {
    let actual = validate_regular_stat(&stat_at(parent, name)?, label)?;
    if actual != expected {
        return Err(io::Error::other(format!(
            "{label} changed identity during publication"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn stat_file(file: &File) -> io::Result<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and the descriptor is live.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn stat_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<libc::stat> {
    use std::os::fd::AsRawFd;

    let name = name_cstring(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage and the descriptor/name are valid.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn validate_regular_file(file: &File, label: &str) -> io::Result<FileIdentity> {
    validate_regular_stat(&stat_file(file)?, label)
}

#[cfg(unix)]
fn validate_regular_stat(stat: &libc::stat, label: &str) -> io::Result<FileIdentity> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
        return Err(io::Error::other(format!(
            "{label} is not a single-link regular file"
        )));
    }
    Ok(FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
    })
}

#[cfg(unix)]
fn name_cstring(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry authority path contains a NUL byte",
        )
    })
}

#[cfg(not(unix))]
fn metadata_is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x400 != 0;
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(not(unix))]
fn reject_reparse_or_non_file(path: &Path, label: &str) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata_is_reparse(&metadata) || !metadata.is_file() {
        return Err(io::Error::other(format!(
            "{label} is a reparse point or non-file authority"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_reparse_components(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata_is_reparse(&metadata) || !metadata.is_dir() {
            return Err(io::Error::other(format!(
                "registry directory component is a reparse point or non-directory: {}",
                current.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_with_pre_commit<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    write_with_pre_commit_impl(path, bytes, pre_commit)
}

#[cfg(all(not(test), not(unix)))]
fn write_with_pre_commit<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    write_with_pre_commit_impl(path, bytes, pre_commit)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    // The published file itself is flushed above. Opening directories for a
    // portable metadata fsync is not supported by std on non-Unix platforms.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_pre_commit_preserves_destination_and_cleans_stage() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let destination = root_path.join("artifact");
        std::fs::write(&destination, b"old-complete-bytes").unwrap();

        let error = write_with_pre_commit(&destination, b"replacement", |_| {
            Err(io::Error::other("injected pre-rename failure"))
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read(&destination).unwrap(), b"old-complete-bytes");
        assert_eq!(std::fs::read_dir(root_path).unwrap().count(), 1);
    }

    #[test]
    fn successful_write_atomically_replaces_destination() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let destination = root_path.join("artifact");
        std::fs::write(&destination, b"old").unwrap();

        write(&destination, b"new-complete-bytes").unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-complete-bytes");
        assert_eq!(std::fs::read_dir(root_path).unwrap().count(), 1);
    }

    #[test]
    fn fully_staged_bytes_are_not_visible_at_the_destination_before_commit() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().canonicalize().unwrap().join("artifact");
        std::fs::write(&destination, b"old-complete-bytes").unwrap();

        write_with_pre_commit(&destination, b"new-complete-bytes", |stage| {
            assert_eq!(std::fs::read(&destination)?, b"old-complete-bytes");
            assert_eq!(std::fs::read(stage)?, b"new-complete-bytes");
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-complete-bytes");
    }

    #[test]
    fn first_write_durably_creates_nested_parent_chain() {
        let root = tempfile::tempdir().unwrap();
        let destination = root
            .path()
            .canonicalize()
            .unwrap()
            .join("packages")
            .join("manifests")
            .join("cargo")
            .join("demo");

        write(&destination, b"complete-manifest\n").unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), b"complete-manifest\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_symlinked_directory_components_and_destinations() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let real = root_path.join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = root_path.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(write(&alias.join("artifact"), b"blocked").is_err());
        assert!(!real.join("artifact").exists());

        let outside = root_path.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        let destination = real.join("artifact");
        symlink(&outside, &destination).unwrap();
        assert!(write(&destination, b"replacement").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        assert!(std::fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
