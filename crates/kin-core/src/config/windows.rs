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
//! * **The retained capability is a directory handle whose share mode
//!   withholds `FILE_SHARE_DELETE`.** A share mode binds only the opens that
//!   take part in Windows' sharing checks, and what decides participation is
//!   the desired access: an open asking for none of read, write, or delete
//!   access is exempt from the check and, symmetrically, contributes no share
//!   mode of its own. So the retained handle asks for `FILE_LIST_DIRECTORY`,
//!   which makes it a participant and gives the withheld `FILE_SHARE_DELETE`
//!   teeth. A later open asking for `DELETE` is then refused, and renaming or
//!   removing a directory needs exactly that access, so `.kin` itself cannot
//!   be renamed or removed while this transaction runs. Every other open this
//!   module makes asks for `FILE_READ_ATTRIBUTES` only and stays exempt, so
//!   the retained handle never blocks Kin's own revalidation and never blocks
//!   ordinary work inside the directory. `capability_exclusion_tests` proves
//!   both halves on the target, including that the refused operation succeeds
//!   once the handle is dropped.
//! * **Names are still resolved through the visible path**, because Windows
//!   has no handle-relative open in `std`. That is why every step revalidates
//!   the directory: the visible path is reopened and its
//!   `BY_HANDLE_FILE_INFORMATION` identity compared to the retained handle's.
//!   The share mode above excludes a swap of `.kin` itself. A rename of an
//!   ancestor, which leaves a different directory at the same visible path
//!   without ever opening `.kin`, is not excluded, and revalidation is what
//!   catches it. That is the same hole `revalidate_visible_directory` closes
//!   on Unix.
//! * **Publication over an existing config is `ReplaceFileW`**, which renames
//!   the current config to a backup name and the new file into its place.
//!   `RENAME_EXCHANGE` gives Unix two properties at once, atomicity of the
//!   published name and survival of the predecessor. `ReplaceFileW` is chosen
//!   for the second: the predecessor survives under a name this writer owns,
//!   so a failed post-publication check can put it back. The first is
//!   deliberately not claimed here, because Microsoft documents no atomicity
//!   for `ReplaceFile` with respect to the replaced name, and nothing in this
//!   module rests on one. `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`
//!   would publish in a single namespace operation, but it destroys the
//!   predecessor and with it any possibility of rollback.
//! * **Publication with no existing config is `MoveFileExW` without
//!   `MOVEFILE_REPLACE_EXISTING`**, which fails when the destination exists.
//!   That is `RENAME_NOREPLACE`, so a config raced in during the write is
//!   detected rather than overwritten.
//! * **Durability of a namespace move is `MOVEFILE_WRITE_THROUGH`**, which
//!   Microsoft documents as not returning until the file is actually moved on
//!   the disk. Windows exposes no directory `fsync`, so there is deliberately
//!   no no-op `sync()` here pretending to be one; that flag is the flush, and
//!   it is requested at the three moves this module makes through
//!   `MoveFileExW`. The fourth move is `ReplaceFileW`, and it is the exception
//!   rather than a fourth instance of the same guarantee:
//!   `REPLACEFILE_WRITE_THROUGH` is documented as **not supported**. It is
//!   still passed, because it costs nothing and records the intent should that
//!   ever change, but no durability is derived from it. The replacement path
//!   therefore carries no documented flush of its namespace move. That is a
//!   real asymmetry with the first-publication path, and it is stated here
//!   rather than glossed by listing the two flags together.
//!
//! What is checked after publication differs from Unix on purpose. Unix
//! compares the published name's inode to the temp file's, because an inode is
//! the cheapest exact statement that the very file it wrote is the one now
//! published. Windows keeps that comparison where a rename makes it exact, and
//! adds a read-back of the published bytes. That is a stronger statement of the
//! same property, and it is what lets this arm depend on no identity claim for
//! `ReplaceFileW` at all: Microsoft's own documentation says both that the
//! replacement file assumes the replaced file's identity and that the resulting
//! file has the same file ID as the replacement file. Those cannot both
//! describe the same object, so the bytes are read instead.
//!
//! Owner-private staging has no `0o600` equivalent here. The temp file is
//! created with an empty share mode, so no other handle can open it at all
//! while Kin writes, and it inherits the ACL of the `.kin` directory it is
//! created in. That is inheritance, not an explicit owner-only DACL, and it is
//! the same protection the surrounding repository directory already carries.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, ReplaceFileW, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
};

use super::{validated_config_authority_path, ConfigAuthorityKind, ConfigSaveHookPoint};
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
    /// The capability itself, whose whole value is that it stays open.
    ///
    /// Nothing reads this handle. It is held so the share mode it was opened
    /// with keeps refusing `DELETE` opens of the directory for as long as the
    /// transaction runs, in the same way the crate's `_process_guard` locals
    /// are held rather than read. The identity it was opened with is captured
    /// once below, because a handle's identity cannot change while it is open.
    _retained_directory: Option<File>,
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
    save_config_atomically_scoped_with_hook(path, contents, kind, |_| Ok(()))
}

/// The transaction, with a failure-injection point at each step boundary.
///
/// Rollback is the reason `ReplaceFileW` was chosen over the atomic replacing
/// move, so leaving it unexecuted would mean shipping the justification and
/// not the behaviour. The hook is how the shared contract module reaches it:
/// in production the only caller passes a hook that does nothing, and the
/// points match the Unix arm's so one contract case can drive both.
pub(super) fn save_config_atomically_scoped_with_hook(
    path: &Path,
    contents: &[u8],
    kind: ConfigAuthorityKind,
    mut hook: impl FnMut(ConfigSaveHookPoint) -> Result<()>,
) -> Result<()> {
    let mut authority = ConfigAuthority::open(path, kind)?;
    let (handle, temp) = authority.create_temp()?;
    let mut handle = Some(handle);
    let hook: &mut dyn FnMut(ConfigSaveHookPoint) -> Result<()> = &mut hook;
    let result = (|| {
        let mut file = handle.take().expect("temp handle is taken exactly once");
        let split = contents.len() / 2;
        file.write_all(&contents[..split])
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        hook(ConfigSaveHookPoint::AfterPartialTempWrite)?;
        file.write_all(&contents[split..])
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        file.sync_all()
            .map_err(|error| KinError::io(&temp.display_path, error))?;
        hook(ConfigSaveHookPoint::AfterTempSync)?;
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
        hook(ConfigSaveHookPoint::BeforePublication)?;
        authority.release_retained_directory();
        std::thread::sleep(std::time::Duration::from_millis(50));

        match authority.expected_config {
            Some(expected) => {
                authority.replace_published_config(&temp, expected, contents, &mut *hook)
            }
            None => authority.publish_first_config(&temp, contents, &mut *hook),
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

        let directory = open_retained_config_directory(directory_path)?;
        let directory_identity = handle_identity(&directory, directory_path)?;
        let expected_config =
            inspect_config_file(directory_path, config_name, path, "repository config")?;
        let authority = Self {
            _retained_directory: Some(directory),
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

    fn release_retained_directory(&mut self) {
        self._retained_directory.take();
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
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT)
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

    /// Prove the visible path still names the directory this transaction owns.
    ///
    /// Only the visible path is reread. The retained handle's own identity is
    /// deliberately not compared against itself: the volume-serial and
    /// file-index pair Windows binds to an open handle is fixed for the life
    /// of that handle, through rename and through delete alike, so the
    /// comparison could never fail. It would cost a syscall to read as
    /// evidence while proving nothing.
    fn revalidate_visible_directory(&self) -> Result<()> {
        let visible = open_config_directory_nofollow(&self.display_directory)?;
        let visible_identity = handle_identity(&visible, &self.display_directory)?;
        if visible_identity != self.directory_identity {
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
    ///
    /// The read is no-follow, and the bytes come from the same handle that
    /// proved what the name holds. A plain path read would follow a reparse
    /// point raced into the config name and report its target's bytes as
    /// authority; opening once and reading through that handle leaves no
    /// window between the proof and the read for such a name to appear.
    fn require_published_bytes(&self, contents: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.display_config)
            .map_err(|error| KinError::io(&self.display_config, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| KinError::io(&self.display_config, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(KinError::Config(format!(
                "published repository config at {} is not a regular no-follow file",
                self.display_config.display()
            )));
        }
        let mut published = Vec::new();
        file.read_to_end(&mut published)
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
    fn publish_first_config(
        &self,
        temp: &ConfigTemp,
        contents: &[u8],
        hook: &mut dyn FnMut(ConfigSaveHookPoint) -> Result<()>,
    ) -> Result<()> {
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

        let post_publication = hook(ConfigSaveHookPoint::AfterPublication)
            .and_then(|()| {
                self.require_named_identity(
                    &self.config_name,
                    temp.identity,
                    &self.display_config,
                    "published repository config",
                )
            })
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
    /// into the config name in one call, so the bytes that were authority a
    /// moment ago are still on disk under a name this writer owns and a failed
    /// post-publication check can put them back. What is not claimed is that
    /// the call is atomic with respect to the config name: it is documented as
    /// a sequence of renames, Microsoft states no atomicity for it, and no
    /// check in this module depends on one.
    fn replace_published_config(
        &self,
        temp: &ConfigTemp,
        expected: ConfigFileIdentity,
        contents: &[u8],
        hook: &mut dyn FnMut(ConfigSaveHookPoint) -> Result<()>,
    ) -> Result<()> {
        let backup_name = OsString::from(format!(
            ".config.toml.kin-replaced-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let backup_display = self.display_directory.join(&backup_name);
        self.require_named_absent(&backup_name, &backup_display, "replaced config backup")?;

        replace_file_with_backup(&self.display_config, &temp.display_path, &backup_display)
            .map_err(|error| KinError::io(&self.display_config, error))?;

        let post_publication = hook(ConfigSaveHookPoint::AfterPublication)
            .and_then(|()| self.require_published_bytes(contents))
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
/// The access mask is what makes the share mode binding, so it is chosen for
/// that and not for what this handle reads. `FILE_LIST_DIRECTORY` is a read
/// access right, which makes the open take part in Windows' sharing checks and
/// records its share mode against the directory object. Withholding
/// `FILE_SHARE_DELETE` then refuses any later open asking for `DELETE`, which
/// is the access renaming or removing a directory requires. Asking for
/// `FILE_READ_ATTRIBUTES` instead would be exempt from the check, and an
/// exempt handle imposes no share mode at all: that is the whole difference
/// between excluding a swap of this directory and merely noticing one after
/// the fact.
fn open_retained_config_directory(path: &Path) -> Result<File> {
    open_config_directory(
        path,
        FILE_LIST_DIRECTORY | FILE_ADD_FILE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

/// Reopen a directory only to read which one it is.
///
/// `FILE_READ_ATTRIBUTES` is none of read, write, or delete access, so this
/// open is exempt from sharing checks in both directions: the retained
/// capability above cannot refuse it, and it imposes nothing that could refuse
/// anyone else. That is exactly what a revalidation wants, because proving
/// which directory stands at a path must never itself become contention.
fn open_config_directory_nofollow(path: &Path) -> Result<File> {
    open_config_directory(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

/// `FILE_FLAG_BACKUP_SEMANTICS` is what allows a directory to be opened at
/// all, and `FILE_FLAG_OPEN_REPARSE_POINT` refuses to follow a reparse point
/// standing where the directory should be.
fn open_config_directory(path: &Path, access: u32, share: u32) -> Result<File> {
    let directory = OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
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
    if !target.exists() {
        return Ok(None);
    }
    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
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
    let path_str = path.to_string_lossy();
    let clean = if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
        Path::new(stripped)
    } else {
        path
    };
    clean
        .as_os_str()
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
    let source_wide = wide(source);
    let destination_wide = wide(destination);
    let mut attempts = 0;
    loop {
        let moved = unsafe { MoveFileExW(source_wide.as_ptr(), destination_wide.as_ptr(), flags) };
        if moved != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(5) && attempts < 50 {
            attempts += 1;
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        return Err(error);
    }
}

/// `RENAME_EXCHANGE`'s purpose, by the call Windows provides for it.
///
/// The replaced file survives at `backup`, which is what makes a failed
/// post-publication check recoverable. No ignore flag is passed: a failure to
/// carry the replaced file's attributes or ACL onto the replacement is a real
/// failure of the publication, not something to skip past.
///
/// `REPLACEFILE_WRITE_THROUGH` is passed and is documented as **not
/// supported**, so it is requested for intent and nothing is inferred from it.
/// This is the one namespace move in the module with no documented flush.
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

/// What the retained capability excludes, and what it deliberately does not.
///
/// The module doc above asserts two properties of one handle: that withholding
/// `FILE_SHARE_DELETE` refuses a later `DELETE` open, and that Kin's own
/// attributes-only opens stay exempt from the same check. Both are properties
/// of Windows' sharing rules rather than of Kin's code, so neither can be
/// settled by reading this file, and an arm that merely compiles establishes
/// nothing about either. These cases run on the Windows CI runner. Each pairs
/// its assertion with the falsification that the refused operation succeeds
/// once the handle is dropped, so a refusal arriving for some other reason
/// fails the case rather than passing it.
#[cfg(test)]
mod capability_exclusion_tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::DELETE;

    fn kin_directory(root: &tempfile::TempDir) -> PathBuf {
        let kin = root.path().join(".kin");
        std::fs::create_dir(&kin).expect("create .kin");
        kin
    }

    /// Ask for delete access while granting every share right in return, so
    /// the only thing that can refuse this open is another handle's share
    /// mode.
    fn open_with_delete_intent(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    #[test]
    fn a_delete_intent_open_is_refused_while_the_retained_handle_is_held() {
        let root = tempfile::tempdir().expect("tempdir");
        let kin = kin_directory(&root);

        let retained = open_retained_config_directory(&kin).expect("retain the config authority");
        let refused = open_with_delete_intent(&kin)
            .expect_err("a DELETE open must not be granted while the capability is retained");
        let sharing_violation =
            i32::try_from(ERROR_SHARING_VIOLATION).expect("a documented WIN32_ERROR fits an i32");
        assert_eq!(
            refused.raw_os_error(),
            Some(sharing_violation),
            "the refusal must come from the retained share mode, not from anything else: {refused}"
        );

        drop(retained);
        open_with_delete_intent(&kin)
            .expect("the same open must be granted once the capability is released");
    }

    #[test]
    fn renaming_the_retained_directory_is_refused_while_the_handle_is_held() {
        let root = tempfile::tempdir().expect("tempdir");
        let kin = kin_directory(&root);
        let displaced = root.path().join(".kin.displaced");

        let retained = open_retained_config_directory(&kin).expect("retain the config authority");
        move_file_no_replace(&kin, &displaced)
            .expect_err("renaming the retained authority must be excluded, not merely detected");
        assert!(
            !displaced.exists(),
            "a refused rename must leave the namespace untouched"
        );

        drop(retained);
        move_file_no_replace(&kin, &displaced)
            .expect("the same rename must succeed once the capability is released");
    }

    #[test]
    fn the_retained_handle_does_not_refuse_kins_own_work() {
        let root = tempfile::tempdir().expect("tempdir");
        let kin = kin_directory(&root);
        let config = kin.join("config.toml");
        std::fs::write(&config, b"x = 1\n").expect("seed a published config");

        let retained = open_retained_config_directory(&kin).expect("retain the config authority");

        // Every second open this module makes is attributes-only, and the
        // transaction would refuse its own first revalidation if that were not
        // exempt from the share mode the retained handle now imposes.
        open_config_directory_nofollow(&kin)
            .expect("revalidating the directory must not be refused by Kin's own capability");
        inspect_config_file(
            &kin,
            OsStr::new("config.toml"),
            &config,
            "repository config",
        )
        .expect("inspecting a file inside the directory must not be refused")
        .expect("the seeded config is present");
        std::fs::write(kin.join("other.toml"), b"y = 2\n")
            .expect("ordinary work inside the directory must not be refused");

        drop(retained);
    }

    #[test]
    fn a_stage_directory_can_still_be_promoted_after_publishing_its_config() {
        // `kin init` publishes into `.kin.init-<uuid>` and then renames that
        // directory to `.kin`, which is exactly the operation the retained
        // capability refuses while it is held. A handle outliving its
        // transaction would therefore turn a working init into a refusal, and
        // nothing else in the suite would notice. This is the case that fails
        // if one ever does.
        let root = tempfile::tempdir().expect("tempdir");
        let stage = root
            .path()
            .join(format!(".kin.init-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&stage).expect("create stage");

        save_config_atomically_scoped(
            &stage.join("config.toml"),
            b"mode = \"native\"\n",
            ConfigAuthorityKind::InitializationStage,
        )
        .expect("publish the staged repository config");

        let published = root.path().join(".kin");
        move_file_no_replace(&stage, &published)
            .expect("the transaction must not outlive itself and block stage promotion");
        assert_eq!(
            std::fs::read(published.join("config.toml")).expect("read the promoted config"),
            b"mode = \"native\"\n"
        );
    }
}
