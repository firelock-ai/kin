// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Capability-owned atomic repository config replacement on Windows.
//!
//! The Unix writer holds a directory descriptor and publishes with
//! `renameat2`, so the whole transaction is bound to one directory object and
//! a raced name is either excluded (`NOREPLACE`) or recoverable (`EXCHANGE`).
//! Windows has neither call. What it does have is enough to satisfy the same
//! contract, by different means:
//!
//! * **The retained capability is a directory handle opened without
//!   `FILE_SHARE_DELETE`.** Renaming or deleting a directory requires opening
//!   it with `DELETE` access, and that open fails while this handle is held.
//!   The directory therefore cannot be swapped for another one mid-write. The
//!   handle is opened for `FILE_READ_ATTRIBUTES` only, which Windows exempts
//!   from sharing checks, so holding it never blocks ordinary work inside the
//!   directory and never conflicts with Kin's own second open.
//! * **Names are still resolved through the visible path**, because Windows
//!   has no handle-relative open in `std`. That is why every step revalidates
//!   the directory: the visible path is reopened and its
//!   `BY_HANDLE_FILE_INFORMATION` identity compared to the retained handle's.
//!   An ancestor rename that leaves a different directory at the same path is
//!   caught there, which is the same hole `revalidate_visible_directory`
//!   closes on Unix.
//! * **Publication over an existing config is `ReplaceFileW`**, which renames
//!   the current config to a backup name and the new file into its place. That
//!   is the pairing `RENAME_EXCHANGE` provides on Unix: the predecessor
//!   survives under a name this writer owns, so a failed post-publication
//!   check can put it back. `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`
//!   would publish atomically too, but it destroys the predecessor and with it
//!   any possibility of rollback.
//! * **Publication with no existing config is `MoveFileExW` without
//!   `MOVEFILE_REPLACE_EXISTING`**, which fails when the destination exists.
//!   That is `RENAME_NOREPLACE`, so a config raced in during the write is
//!   detected rather than overwritten.
//! * **Durability of the namespace move is `MOVEFILE_WRITE_THROUGH` /
//!   `REPLACEFILE_WRITE_THROUGH`**, which do not return until the move is
//!   flushed. Windows exposes no directory `fsync`, so there is deliberately
//!   no no-op `sync()` here pretending to be one; the flag is the flush, and
//!   it is requested at each of the four namespace moves this module makes.
//!
//! What is checked after publication differs from Unix on purpose. Unix
//! compares the published name's inode to the temp file's, because an inode is
//! the cheapest exact statement that the very file it wrote is the one now
//! published. Windows keeps that comparison where a rename makes it exact, and
//! adds a read-back of the published bytes, which is a stronger statement of
//! the same property and does not depend on whether `ReplaceFileW` preserves a
//! file record number.
//!
//! Owner-private staging has no `0o600` equivalent here. The temp file is
//! created with an empty share mode, so no other handle can open it at all
//! while Kin writes, and it inherits the ACL of the `.kin` directory it is
//! created in. That is inheritance, not an explicit owner-only DACL, and it is
//! the same protection the surrounding repository directory already carries.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, ReplaceFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
};

use super::{validated_config_authority_path, ConfigAuthorityKind};
use crate::error::{KinError, Result};

/// Identity of one file or directory, read from an open handle.
///
/// The pair is what NTFS guarantees unique for a live file, and it is the
/// Windows counterpart of the Unix device and inode pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

struct ConfigAuthority {
    directory: File,
    directory_identity: ConfigFileIdentity,
    display_directory: PathBuf,
    display_config: PathBuf,
    config_name: OsString,
    expected_config: Option<ConfigFileIdentity>,
}

struct ConfigTemp {
    name: OsString,
    identity: ConfigFileIdentity,
    display_path: PathBuf,
}

pub(super) fn save_config_atomically_scoped(
    path: &Path,
    contents: &[u8],
    kind: ConfigAuthorityKind,
) -> Result<()> {
    let authority = ConfigAuthority::open(path, kind)?;
    let (handle, temp) = authority.create_temp()?;
    let mut handle = Some(handle);
    let result = (|| {
        let mut file = handle.take().expect("temp handle is taken exactly once");
        file.write_all(contents)
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        file.sync_all()
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        // The Unix arm re-reads the temp by name here, to catch a name swapped
        // out from under the handle it wrote through. That cannot happen while
        // this handle is open: renaming or deleting a file requires opening it
        // with `DELETE`, and the empty share mode denies it. Repeating the
        // check here would be a check that cannot fail, so it is left to the
        // one below, which runs once the handle is closed and the window is
        // real.
        //
        // The handle is closed here rather than at the end of the transaction
        // because the publication below is itself a namespace move, and it
        // needs every handle on the file to permit deletion. Every check after
        // this point reads the name, exactly as the Unix arm's checks do.
        drop(file);
        authority.revalidate_visible_directory()?;
        authority.revalidate_expected_config()?;
        authority.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "config temp file",
        )?;

        match authority.expected_config {
            Some(expected) => authority.replace_published_config(&temp, expected, contents),
            None => authority.publish_first_config(&temp, contents),
        }
    })();

    drop(handle.take());
    if result.is_err() {
        if let Err(cleanup) = authority.cleanup_exact_temp(&temp) {
            return Err(KinError::Other(format!(
                "{}; exact config temp cleanup also failed: {cleanup}",
                result.expect_err("checked error")
            )));
        }
    }
    result
}

impl ConfigAuthority {
    fn open(path: &Path, kind: ConfigAuthorityKind) -> Result<Self> {
        let (config_name, directory_path) = validated_config_authority_path(path, kind)?;

        let directory = open_config_directory_nofollow(directory_path)?;
        let directory_identity = handle_identity(&directory, directory_path)?;
        let expected_config =
            inspect_config_file(directory_path, config_name, path, "repository config")?;
        let authority = Self {
            directory,
            directory_identity,
            display_directory: directory_path.to_path_buf(),
            display_config: path.to_path_buf(),
            config_name: config_name.to_os_string(),
            expected_config,
        };
        authority.revalidate_visible_directory()?;
        authority.revalidate_expected_config()?;
        Ok(authority)
    }

    fn create_temp(&self) -> Result<(File, ConfigTemp)> {
        loop {
            let name = OsString::from(format!(
                ".config.toml.kin-tmp-{}",
                uuid::Uuid::new_v4().simple()
            ));
            let display_path = self.display_directory.join(&name);
            let file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&display_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(KinError::io(&display_path, error)),
            };
            let identity = handle_identity(&file, &display_path)?;
            return Ok((
                file,
                ConfigTemp {
                    name,
                    identity,
                    display_path,
                },
            ));
        }
    }

    fn revalidate_visible_directory(&self) -> Result<()> {
        let visible = open_config_directory_nofollow(&self.display_directory)?;
        let visible_identity = handle_identity(&visible, &self.display_directory)?;
        let retained_identity = handle_identity(&self.directory, &self.display_directory)?;
        if visible_identity != self.directory_identity
            || retained_identity != self.directory_identity
        {
            return Err(KinError::Config(format!(
                "retained .kin authority changed or was replaced while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn revalidate_expected_config(&self) -> Result<()> {
        let actual = inspect_config_file(
            &self.display_directory,
            &self.config_name,
            &self.display_config,
            "repository config",
        )?;
        if actual != self.expected_config {
            return Err(KinError::Config(format!(
                "repository config changed identity while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn require_named_identity(
        &self,
        name: &OsStr,
        expected: ConfigFileIdentity,
        display: &Path,
        label: &str,
    ) -> Result<()> {
        let actual = inspect_config_file(&self.display_directory, name, display, label)?;
        if actual != Some(expected) {
            return Err(KinError::Config(format!(
                "{label} changed identity while saving {}",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    fn require_named_absent(&self, name: &OsStr, display: &Path, label: &str) -> Result<()> {
        match std::fs::symlink_metadata(self.display_directory.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KinError::io(display, error)),
            Ok(_) => Err(KinError::Config(format!(
                "{label} unexpectedly exists while saving {}",
                self.display_config.display()
            ))),
        }
    }

    /// Prove the published name holds the exact bytes this call wrote.
    ///
    /// Reading the name back is a stronger statement than any metadata
    /// comparison, and it is the one that matters: repository authority is the
    /// bytes, not the file record they happen to live in.
    fn require_published_bytes(&self, contents: &[u8]) -> Result<()> {
        let published = std::fs::read(&self.display_config)
            .map_err(|error| KinError::io(&self.display_config, error))?;
        if published != contents {
            return Err(KinError::Config(format!(
                "published repository config {} does not hold the bytes this save wrote",
                self.display_config.display()
            )));
        }
        Ok(())
    }

    /// Publish into a name that held no config.
    ///
    /// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` fails when the
    /// destination exists, so a config created by anyone else between opening
    /// this authority and publishing is refused rather than overwritten.
    fn publish_first_config(&self, temp: &ConfigTemp, contents: &[u8]) -> Result<()> {
        move_file_no_replace(&temp.display_path, &self.display_config).map_err(|error| {
            if is_destination_exists(&error) {
                KinError::Config(format!(
                    "repository config appeared while saving {}; refusing to replace it",
                    self.display_config.display()
                ))
            } else {
                KinError::io(&self.display_config, error)
            }
        })?;

        let post_publication = self
            .require_named_identity(
                &self.config_name,
                temp.identity,
                &self.display_config,
                "published repository config",
            )
            .and_then(|()| self.require_published_bytes(contents))
            .and_then(|()| {
                self.require_named_absent(&temp.name, &temp.display_path, "config temp file")
            })
            .and_then(|()| self.revalidate_visible_directory());
        if let Err(error) = post_publication {
            let rollback = self.rollback_first_publication(temp);
            return Err(rollback_error(error, rollback));
        }
        Ok(())
    }

    /// Publish over an existing config, keeping the predecessor recoverable.
    ///
    /// `ReplaceFileW` moves the current config to `backup` and the temp file
    /// into the config name in one call, so no reader ever observes the config
    /// name as absent, and the bytes that were authority a moment ago are
    /// still on disk under a name this writer owns.
    fn replace_published_config(
        &self,
        temp: &ConfigTemp,
        expected: ConfigFileIdentity,
        contents: &[u8],
    ) -> Result<()> {
        let backup_name = OsString::from(format!(
            ".config.toml.kin-replaced-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let backup_display = self.display_directory.join(&backup_name);
        self.require_named_absent(&backup_name, &backup_display, "replaced config backup")?;

        replace_file_with_backup(&self.display_config, &temp.display_path, &backup_display)
            .map_err(|error| KinError::io(&self.display_config, error))?;

        let post_publication = self
            .require_published_bytes(contents)
            .and_then(|()| {
                self.require_named_identity(
                    &backup_name,
                    expected,
                    &backup_display,
                    "replaced repository config",
                )
            })
            .and_then(|()| {
                self.require_named_absent(&temp.name, &temp.display_path, "config temp file")
            })
            .and_then(|()| self.revalidate_visible_directory());
        if let Err(error) = post_publication {
            let rollback = self.rollback_replacement(&backup_name, &backup_display, expected);
            return Err(rollback_error(error, rollback));
        }

        self.cleanup_named_identity(
            &backup_name,
            expected,
            &backup_display,
            "replaced repository config",
        )
        .map_err(|error| {
            KinError::Other(format!(
                "repository config was atomically published at {}, but durable cleanup of the \
                 replaced config failed: {error}",
                self.display_config.display()
            ))
        })
    }

    fn rollback_first_publication(&self, temp: &ConfigTemp) -> Result<()> {
        self.require_named_identity(
            &self.config_name,
            temp.identity,
            &self.display_config,
            "published repository config",
        )?;
        self.require_named_absent(&temp.name, &temp.display_path, "config temp file")?;
        move_file_no_replace(&self.display_config, &temp.display_path)
            .map_err(|error| KinError::io(&self.display_config, error))?;
        self.require_named_absent(&self.config_name, &self.display_config, "repository config")?;
        self.require_named_identity(
            &temp.name,
            temp.identity,
            &temp.display_path,
            "rolled-back config temp file",
        )
    }

    /// Put the predecessor back at the config name.
    ///
    /// The backup is moved back with `MOVEFILE_REPLACE_EXISTING` rather than
    /// no-replace, because the name is occupied by the file this transaction
    /// just published and undoing that publication is the whole point.
    fn rollback_replacement(
        &self,
        backup_name: &OsStr,
        backup_display: &Path,
        expected: ConfigFileIdentity,
    ) -> Result<()> {
        self.require_named_identity(
            backup_name,
            expected,
            backup_display,
            "replaced repository config",
        )?;
        move_file_replace(backup_display, &self.display_config)
            .map_err(|error| KinError::io(&self.display_config, error))?;
        self.require_named_absent(backup_name, backup_display, "replaced config backup")?;
        self.require_named_identity(
            &self.config_name,
            expected,
            &self.display_config,
            "restored repository config",
        )
    }

    fn cleanup_named_identity(
        &self,
        name: &OsStr,
        expected: ConfigFileIdentity,
        display: &Path,
        label: &str,
    ) -> Result<()> {
        self.require_named_identity(name, expected, display, label)?;
        std::fs::remove_file(display).map_err(|error| KinError::io(display, error))?;
        self.require_named_absent(name, display, label)
    }

    fn cleanup_exact_temp(&self, temp: &ConfigTemp) -> Result<()> {
        match inspect_config_file(
            &self.display_directory,
            &temp.name,
            &temp.display_path,
            "config temp file",
        )? {
            None => return Ok(()),
            Some(actual) if actual == temp.identity => {}
            Some(_) => {
                return Err(KinError::Config(format!(
                    "refusing to remove a replacement at config temp name {}",
                    temp.display_path.display()
                )));
            }
        }
        std::fs::remove_file(&temp.display_path)
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        self.require_named_absent(&temp.name, &temp.display_path, "config temp file")
    }
}

/// Open the `.kin` directory as the transaction's retained capability.
///
/// The share mode grants read and write and withholds delete, which is what
/// prevents the directory from being renamed or removed while Kin publishes
/// into it. `FILE_FLAG_BACKUP_SEMANTICS` is what allows a directory to be
/// opened at all, and `FILE_FLAG_OPEN_REPARSE_POINT` refuses to follow a
/// reparse point standing where `.kin` should be.
fn open_config_directory_nofollow(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| KinError::io(path, error))?;
    let metadata = directory
        .metadata()
        .map_err(|error| KinError::io(path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(KinError::Config(format!(
            "repository config authority at {} is not a real directory",
            path.display()
        )));
    }
    Ok(directory)
}

/// Read the identity pair Windows binds to an open handle.
///
/// Unlike the same read in `init.rs`, an unreadable identity is an error here
/// rather than an `Unavailable` observation: every check in this module is a
/// comparison of two identities, and a writer that cannot read one has not
/// proved anything and must not publish.
fn handle_identity(file: &File, display: &Path) -> Result<ConfigFileIdentity> {
    let information =
        winapi_util::file::information(file).map_err(|error| KinError::io(display, error))?;
    let volume_serial_number = u32::try_from(information.volume_serial_number()).map_err(|_| {
        KinError::Config(format!(
            "volume serial number of {} does not fit the documented DWORD",
            display.display()
        ))
    })?;
    Ok(ConfigFileIdentity {
        volume_serial_number,
        file_index: information.file_index(),
    })
}

/// Identity of one named entry, or `None` when the name holds nothing.
///
/// One no-follow open answers both questions the Unix arm needs two calls for:
/// the handle's own metadata says what was opened, and the handle's identity
/// says which object it is. There is no window between them for a name to be
/// swapped, because both come from the same handle.
fn inspect_config_file(
    directory: &Path,
    name: &OsStr,
    display: &Path,
    label: &str,
) -> Result<Option<ConfigFileIdentity>> {
    let target = directory.join(name);
    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&target)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(KinError::io(display, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| KinError::io(display, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KinError::Config(format!(
            "{label} at {} is not a regular no-follow file",
            display.display()
        )));
    }
    handle_identity(&file, display).map(Some)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// `RENAME_NOREPLACE`, flushed: fails when the destination exists.
fn move_file_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    move_file(source, destination, MOVEFILE_WRITE_THROUGH)
}

/// A flushed replacing move, used only to undo a publication.
fn move_file_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    move_file(
        source,
        destination,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    )
}

fn move_file(source: &Path, destination: &Path, flags: u32) -> std::io::Result<()> {
    let source = wide(source);
    let destination = wide(destination);
    let moved = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) };
    if moved == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `RENAME_EXCHANGE`'s purpose, by the call Windows provides for it.
///
/// The replaced file survives at `backup`, which is what makes a failed
/// post-publication check recoverable. No ignore flag is passed: a failure to
/// carry the replaced file's attributes or ACL onto the replacement is a real
/// failure of the publication, not something to skip past.
fn replace_file_with_backup(
    replaced: &Path,
    replacement: &Path,
    backup: &Path,
) -> std::io::Result<()> {
    let replaced = wide(replaced);
    let replacement = wide(replacement);
    let backup = wide(backup);
    let replaced_ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            backup.as_ptr(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced_ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn is_destination_exists(error: &std::io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        u32::try_from(code)
            .is_ok_and(|code| code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS)
    })
}

fn rollback_error(error: KinError, rollback: Result<()>) -> KinError {
    match rollback {
        Ok(()) => error,
        Err(rollback) => KinError::Other(format!(
            "{error}; capability-owned config rollback also failed: {rollback}"
        )),
    }
}
