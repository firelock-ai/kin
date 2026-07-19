// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Windows-only path-binding and private-directory support for the updater.
//!
//! Candidate programs are statically inspected by the cross-platform updater
//! and are never launched. Private preflight trees are protected by
//! handle-verified, current-user-only DACLs and handles that deny delete/path
//! replacement for the duration of validation.

use super::{
    component_path, file_identity, ComponentSpec, InstallRootLock, ManagedBundleGeneration,
    ManagedComponentGeneration, PlatformObjectIdentity,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidSid, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TokenUser, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

fn win32_error(context: &str) -> anyhow::Error {
    let error = std::io::Error::last_os_error();
    anyhow::anyhow!("{context}: {error}")
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        anyhow::bail!("Windows updater path or environment value contains an interior NUL");
    }
    wide.push(0);
    Ok(wide)
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE, context: &str) -> Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(win32_error(context));
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_file(mut self) -> File {
        let handle = self.0;
        self.0 = null_mut();
        // SAFETY: ownership of this valid HANDLE is transferred exactly once
        // to File, and Drop is disabled by clearing self.0 above.
        unsafe { File::from_raw_handle(handle) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: self.0 is an owned live HANDLE and is closed once here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct CurrentUserSid {
    storage: Vec<usize>,
}

impl CurrentUserSid {
    fn load() -> Result<Self> {
        let mut token = null_mut();
        // SAFETY: the output pointer is valid and GetCurrentProcess is a
        // process pseudo-handle accepted by OpenProcessToken.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(win32_error("failed to open current process token"));
        }
        let token = OwnedHandle::new(token, "current process token was invalid")?;
        let mut required = 0_u32;
        // SAFETY: a null first buffer is the documented size query.
        let _ =
            unsafe { GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut required) };
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err(win32_error("failed to size current-user token information"));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        // SAFETY: storage is writable and at least `required` bytes long.
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(win32_error("failed to read current-user token information"));
        }
        let current = Self { storage };
        // SAFETY: sid() points into the successfully populated TOKEN_USER.
        if unsafe { IsValidSid(current.sid()) } == 0 {
            anyhow::bail!("current process token returned an invalid user SID");
        }
        Ok(current)
    }

    fn sid(&self) -> PSID {
        // SAFETY: storage was populated as TOKEN_USER and is never reallocated
        // after construction.
        unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

fn build_private_acl(sid: PSID) -> Result<Vec<usize>> {
    // SAFETY: sid was validated when CurrentUserSid was constructed.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    let bytes = size_of::<ACL>()
        .checked_add(size_of::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>())
        .and_then(|value| value.checked_sub(size_of::<u32>()))
        .and_then(|value| value.checked_add(sid_len))
        .context("Windows private ACL size overflow")?;
    let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
    let acl = storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: storage is aligned, writable, and at least `bytes` long.
    if unsafe { InitializeAcl(acl, bytes as u32, ACL_REVISION) } == 0 {
        return Err(win32_error("failed to initialize private updater ACL"));
    }
    // SAFETY: acl and sid are valid. The only ACE grants this user full
    // control and is inherited by both child files and directories.
    if unsafe {
        AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS,
            sid,
        )
    } == 0
    {
        return Err(win32_error(
            "failed to add current user to private updater ACL",
        ));
    }
    Ok(storage)
}

fn create_private_directory(path: &Path, user: &CurrentUserSid) -> Result<bool> {
    let path_wide = wide_null(path.as_os_str())?;
    let mut acl = build_private_acl(user.sid())?;
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    // SAFETY: descriptor is writable and revision one is the documented
    // absolute security-descriptor format.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(win32_error(
            "failed to initialize private temporary-directory security descriptor",
        ));
    }
    // SAFETY: the current-user SID and ACL remain live until CreateDirectoryW
    // returns. Marking the DACL protected prevents parent ACEs from being
    // merged into the directory during creation.
    if unsafe { SetSecurityDescriptorOwner(descriptor_ptr, user.sid(), 0) } == 0
        || unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.as_mut_ptr().cast(), 0) } == 0
        || unsafe {
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
    {
        return Err(win32_error(
            "failed to configure private temporary-directory security descriptor",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    // SAFETY: path and security descriptor buffers remain live for the call.
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } != 0 {
        return Ok(true);
    }
    // SAFETY: GetLastError has no preconditions and is read immediately after
    // the failed CreateDirectoryW call.
    let error = unsafe { GetLastError() };
    if error == ERROR_ALREADY_EXISTS {
        return Ok(false);
    }
    anyhow::bail!(
        "failed to create private updater directory {}: Windows error {error}",
        path.display()
    )
}

fn apply_private_security(handle: HANDLE, user: &CurrentUserSid) -> Result<()> {
    let mut acl = build_private_acl(user.sid())?;
    // SAFETY: handle is live; owner SID and ACL remain valid for the call.
    let result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user.sid(),
            null_mut(),
            acl.as_mut_ptr().cast(),
            null_mut(),
        )
    };
    if result != 0 {
        anyhow::bail!("failed to install private updater DACL: Windows error {result}");
    }
    Ok(())
}

fn validate_private_security(handle: HANDLE, user: &CurrentUserSid) -> Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: output pointers are valid and descriptor is released below.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        anyhow::bail!("failed to inspect private updater DACL: Windows error {result}");
    }
    struct LocalDescriptor(*mut core::ffi::c_void);
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetSecurityInfo allocated this descriptor with
                // LocalAlloc and transfers ownership to the caller.
                let _ = unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
            }
        }
    }
    let _descriptor = LocalDescriptor(descriptor);
    if owner.is_null() || dacl.is_null() {
        anyhow::bail!("private updater path has no explicit owner or DACL");
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor remains live through _descriptor and both output
    // pointers are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(win32_error(
            "failed to inspect private updater DACL protection",
        ));
    }
    if control & SE_DACL_PROTECTED == 0 {
        anyhow::bail!("private updater DACL permits inherited access");
    }
    // SAFETY: both SIDs are valid for the descriptor lifetime.
    if unsafe { EqualSid(owner, user.sid()) } == 0 {
        anyhow::bail!("private updater path is not owned by the current user");
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid for the descriptor lifetime and info is writable.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(win32_error("failed to inspect private updater ACL entries"));
    }
    if info.AceCount != 1 {
        anyhow::bail!(
            "private updater DACL must contain exactly one current-user ACE, found {}",
            info.AceCount
        );
    }
    let mut ace = null_mut();
    // SAFETY: the ACL reports one ACE, so index zero is valid.
    if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
        return Err(win32_error("failed to read private updater ACL entry"));
    }
    // SAFETY: GetAce returned a valid ACCESS_ALLOWED_ACE-sized entry after we
    // verify its type. SidStart is the variable-length SID prefix.
    let allowed = unsafe { &*(ace as *const windows_sys::Win32::Security::ACCESS_ALLOWED_ACE) };
    if allowed.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
        || u32::from(allowed.Header.AceFlags) != OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        || allowed.Mask != FILE_ALL_ACCESS
    {
        anyhow::bail!(
            "private updater DACL grants access outside its current-user full-control ACE"
        );
    }
    let ace_sid = (&allowed.SidStart as *const u32).cast_mut().cast();
    // SAFETY: ace_sid is the SID embedded in the validated ACE.
    if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, user.sid()) } == 0 {
        anyhow::bail!("private updater DACL ACE does not name the current user");
    }
    Ok(())
}

fn object_identity(handle: HANDLE, expect_directory: bool) -> Result<PlatformObjectIdentity> {
    // SAFETY: zero is a valid initialization for this output structure.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: handle is live and info is writable.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(win32_error("failed to inspect updater path handle"));
    }
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != expect_directory {
        anyhow::bail!("updater private path type changed");
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("updater private path is a reparse point");
    }
    if info.nNumberOfLinks != 1 {
        anyhow::bail!(
            "updater private path must have exactly one link, found {}",
            info.nNumberOfLinks
        );
    }
    Ok(PlatformObjectIdentity {
        namespace: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

/// Durable authority over the exact image object mapped by the executing
/// Windows process. Windows keeps the image pathname replacement-protected;
/// this additional read handle supplies stable object identity and bytes for
/// the complete updater preflight lifetime.
pub(super) struct ExecutingFileAuthority {
    path: PathBuf,
    file: File,
    binding: PlatformObjectIdentity,
}

impl ExecutingFileAuthority {
    pub(super) fn capture() -> Result<Self> {
        let path =
            std::env::current_exe().context("failed to locate the running Kin executable")?;
        let path_wide = wide_null(path.as_os_str())?;
        // Deliberately omit FILE_SHARE_WRITE and FILE_SHARE_DELETE. The held
        // handle therefore prevents byte mutation and pathname replacement.
        // SAFETY: path_wide is a live NUL-terminated path for this call.
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                windows_sys::Win32::Foundation::GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(
            handle,
            &format!(
                "failed to retain the running Kin executable {}",
                path.display()
            ),
        )?;
        let binding = object_identity(handle.raw(), false)?;
        Ok(Self {
            path,
            file: handle.into_file(),
            binding,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn binding(&self) -> &PlatformObjectIdentity {
        &self.binding
    }

    pub(super) fn validate(&self) -> Result<()> {
        let handle = self.file.as_raw_handle().cast();
        let current = object_identity(handle, false)?;
        if current != self.binding {
            anyhow::bail!("durable executing Kin image object changed during update preflight");
        }
        Ok(())
    }
}

fn open_path_handle(
    path: &Path,
    expect_directory: bool,
    write_security: bool,
    block_writes: bool,
) -> Result<OwnedHandle> {
    let path_wide = wide_null(path.as_os_str())?;
    let mut access = FILE_READ_ATTRIBUTES | READ_CONTROL;
    if write_security {
        access |= WRITE_DAC | WRITE_OWNER;
    }
    let mut share = FILE_SHARE_READ;
    if expect_directory || !block_writes {
        share |= FILE_SHARE_WRITE;
    }
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if expect_directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    // SAFETY: pointers reference live NUL-terminated buffers for the call.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    OwnedHandle::new(
        handle,
        &format!(
            "failed to open updater path without following reparse points: {}",
            path.display()
        ),
    )
}

struct SecurePathGuard {
    path: PathBuf,
    expect_directory: bool,
    require_private: bool,
    block_writes: bool,
    identity: PlatformObjectIdentity,
    handle: OwnedHandle,
}

impl SecurePathGuard {
    fn open(
        path: &Path,
        expect_directory: bool,
        user: Option<&CurrentUserSid>,
        install_private_acl: bool,
        block_writes: bool,
    ) -> Result<Self> {
        let handle = open_path_handle(path, expect_directory, install_private_acl, block_writes)?;
        if install_private_acl {
            apply_private_security(
                handle.raw(),
                user.context("private updater path validation lost its current-user SID")?,
            )?;
        }
        let identity = object_identity(handle.raw(), expect_directory)?;
        if let Some(user) = user {
            validate_private_security(handle.raw(), user)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            expect_directory,
            require_private: user.is_some(),
            block_writes,
            identity,
            handle,
        })
    }

    fn validate(&self, user: Option<&CurrentUserSid>) -> Result<()> {
        if self.require_private != user.is_some() {
            anyhow::bail!("updater private path validation authority changed");
        }
        let reopened =
            open_path_handle(&self.path, self.expect_directory, false, self.block_writes)?;
        let current = object_identity(reopened.raw(), self.expect_directory)?;
        if current != self.identity {
            anyhow::bail!(
                "updater private path binding changed: {}",
                self.path.display()
            );
        }
        if let Some(user) = user {
            validate_private_security(self.handle.raw(), user)?;
            validate_private_security(reopened.raw(), user)?;
        }
        Ok(())
    }
}

pub(super) struct WindowsPrivateTree {
    guards: Vec<SecurePathGuard>,
    user: CurrentUserSid,
}

impl WindowsPrivateTree {
    pub(super) fn initialize_root(root: &Path) -> Result<Self> {
        let user = CurrentUserSid::load()?;
        let root_guard = SecurePathGuard::open(root, true, Some(&user), true, false)?;
        Ok(Self {
            guards: vec![root_guard],
            user,
        })
    }

    pub(super) fn seal_directory(&mut self, path: &Path) -> Result<()> {
        self.guards.push(SecurePathGuard::open(
            path,
            true,
            Some(&self.user),
            true,
            false,
        )?);
        Ok(())
    }

    pub(super) fn seal_file(&mut self, path: &Path) -> Result<()> {
        self.guards.push(SecurePathGuard::open(
            path,
            false,
            Some(&self.user),
            true,
            false,
        )?);
        Ok(())
    }

    pub(super) fn seal_staged_bundle(
        &mut self,
        stage_root: &Path,
        spec: &[ComponentSpec],
    ) -> Result<()> {
        self.seal_directory(&stage_root.join("bin"))?;
        self.seal_directory(&stage_root.join("lib"))?;
        for component in spec {
            let path = component_path(stage_root, *component);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => self.guards.push(SecurePathGuard::open(
                    &path,
                    false,
                    Some(&self.user),
                    true,
                    true,
                )?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect staged Windows component {}",
                            path.display()
                        )
                    });
                }
            }
        }
        self.validate()
    }

    pub(super) fn validate(&self) -> Result<()> {
        for guard in &self.guards {
            guard.validate(Some(&self.user))?;
        }
        Ok(())
    }
}

pub(super) struct WindowsPrivateTempDir {
    path: PathBuf,
    parent: SecurePathGuard,
    tree: Option<WindowsPrivateTree>,
}

pub(super) fn ensure_private_temp_container(parent: &Path, name: &str) -> Result<PathBuf> {
    let parent_guard = SecurePathGuard::open(parent, true, None, false, false)?;
    parent_guard.validate(None)?;
    let user = CurrentUserSid::load()?;
    let path = parent.join(name);
    let created = create_private_directory(&path, &user)?;
    let container =
        SecurePathGuard::open(&path, true, Some(&user), false, false).with_context(|| {
            format!(
                "private updater container validation failed: {}",
                path.display()
            )
        });
    if let Err(error) = container {
        if created {
            let _ = std::fs::remove_dir(&path);
        }
        return Err(error);
    }
    parent_guard.validate(None)?;
    Ok(path)
}

impl WindowsPrivateTempDir {
    pub(super) fn create(parent: &Path, prefix: &str) -> Result<Self> {
        let user = CurrentUserSid::load()?;
        let parent_guard = SecurePathGuard::open(parent, true, Some(&user), false, false)?;
        parent_guard.validate(Some(&user))?;
        for _ in 0..128 {
            let path = parent.join(format!("{prefix}{}", uuid::Uuid::new_v4()));
            if !create_private_directory(&path, &user)? {
                continue;
            }
            let tree = match WindowsPrivateTree::initialize_root(&path) {
                Ok(tree) => tree,
                Err(error) => {
                    let _ = std::fs::remove_dir(&path);
                    return Err(error);
                }
            };
            if let Err(error) = parent_guard
                .validate(Some(&user))
                .and_then(|()| tree.validate())
            {
                drop(tree);
                let _ = std::fs::remove_dir(&path);
                return Err(error);
            }
            return Ok(Self {
                path,
                parent: parent_guard,
                tree: Some(tree),
            });
        }
        anyhow::bail!(
            "failed to allocate a unique private updater directory under {}",
            parent.display()
        )
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn seal_directory(&mut self, path: &Path) -> Result<()> {
        self.tree
            .as_mut()
            .context("private updater directory security was already released")?
            .seal_directory(path)
    }

    pub(super) fn seal_file(&mut self, path: &Path) -> Result<()> {
        self.tree
            .as_mut()
            .context("private updater directory security was already released")?
            .seal_file(path)
    }

    pub(super) fn seal_staged_bundle(
        &mut self,
        stage_root: &Path,
        spec: &[ComponentSpec],
    ) -> Result<()> {
        self.tree
            .as_mut()
            .context("private updater directory security was already released")?
            .seal_staged_bundle(stage_root, spec)
    }

    pub(super) fn validate(&self) -> Result<()> {
        let user = CurrentUserSid::load()?;
        self.parent.validate(Some(&user))?;
        self.tree
            .as_ref()
            .context("private updater directory security was already released")?
            .validate()
    }
}

pub(super) fn private_directory_identity(path: &Path) -> Result<PlatformObjectIdentity> {
    let user = CurrentUserSid::load()?;
    let guard = SecurePathGuard::open(path, true, Some(&user), false, false)?;
    guard.validate(Some(&user))?;
    Ok(guard.identity.clone())
}

impl Drop for WindowsPrivateTempDir {
    fn drop(&mut self) {
        drop(self.tree.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(super) struct WindowsManagedDirectoryGuard {
    guards: Vec<SecurePathGuard>,
}

impl WindowsManagedDirectoryGuard {
    fn root_identity(&self) -> PlatformObjectIdentity {
        self.guards[0].identity.clone()
    }

    fn validate(&self) -> Result<()> {
        for guard in &self.guards {
            guard.validate(None)?;
        }
        Ok(())
    }
}

pub(super) fn guard_managed_directories(root: &Path) -> Result<WindowsManagedDirectoryGuard> {
    let guards = vec![
        SecurePathGuard::open(root, true, None, false, false)?,
        SecurePathGuard::open(&root.join("bin"), true, None, false, false)?,
        SecurePathGuard::open(&root.join("lib"), true, None, false, false)?,
    ];
    let guard = WindowsManagedDirectoryGuard { guards };
    guard.validate()?;
    Ok(guard)
}

fn capture_component_generation(path: &Path) -> Result<Option<ManagedComponentGeneration>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let guard = SecurePathGuard::open(path, false, None, false, true)?;
            let identity = file_identity(path)?;
            guard.validate(None)?;
            Ok(Some(ManagedComponentGeneration {
                identity,
                binding: guard.identity,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect managed Windows component {}",
                path.display()
            )
        }),
    }
}

pub(super) fn snapshot_managed_bundle_generation(
    root: PathBuf,
    spec: &[ComponentSpec],
) -> Result<ManagedBundleGeneration> {
    let directories = guard_managed_directories(&root)?;
    let mut components = HashMap::new();
    for component in spec {
        components.insert(
            component.name.to_string(),
            capture_component_generation(&component_path(&root, *component))?,
        );
    }
    directories.validate()?;
    Ok(ManagedBundleGeneration {
        root,
        root_binding: directories.root_identity(),
        components,
    })
}

pub(super) fn verify_managed_bundle_generation_locked(
    lock: &InstallRootLock,
    spec: &[ComponentSpec],
    expected: &ManagedBundleGeneration,
) -> Result<()> {
    let directories = guard_managed_directories(lock.root())?;
    if directories.root_identity() != expected.root_binding {
        anyhow::bail!("managed Kin install root generation changed during updater preflight");
    }
    let mut current = HashMap::new();
    for component in spec {
        current.insert(
            component.name.to_string(),
            capture_component_generation(&component_path(lock.root(), *component))?,
        );
    }
    directories.validate()?;
    if current != expected.components {
        anyhow::bail!("managed Kin bundle generation changed during updater preflight");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CMD_COMPONENTS: &[ComponentSpec] = &[ComponentSpec {
        name: "probe.exe",
        location: super::super::ComponentLocation::Bin,
        required: true,
    }];

    fn private_test_container() -> PathBuf {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        ensure_private_temp_container(
            &parent,
            &format!(".kin-private-test-{}", uuid::Uuid::new_v4()),
        )
        .unwrap()
    }

    #[test]
    fn private_temp_tree_is_current_user_only_from_creation_through_cleanup() {
        let container = private_test_container();
        let mut root =
            WindowsPrivateTempDir::create(&container, ".kin-private-tree-test-").unwrap();
        let path = root.path().to_path_buf();
        let child = path.join("child");
        std::fs::create_dir(&child).unwrap();
        root.seal_directory(&child).unwrap();
        root.validate().unwrap();
        drop(root);
        assert!(!path.exists());
        std::fs::remove_dir(container).unwrap();
    }

    #[test]
    fn hardlinked_candidates_and_guarded_path_replacements_fail_closed() {
        let container = private_test_container();
        let mut root = WindowsPrivateTempDir::create(&container, ".kin-path-guard-test-").unwrap();
        std::fs::create_dir(root.path().join("bin")).unwrap();
        std::fs::create_dir(root.path().join("lib")).unwrap();
        let candidate = root.path().join("bin/probe.exe");
        std::fs::write(&candidate, b"candidate").unwrap();
        std::fs::hard_link(&candidate, root.path().join("bin/alias.exe")).unwrap();
        let root_path = root.path().to_path_buf();
        let error = root
            .seal_staged_bundle(&root_path, TEST_CMD_COMPONENTS)
            .unwrap_err();
        assert!(format!("{error:#}").contains("exactly one link"));

        std::fs::remove_file(root.path().join("bin/alias.exe")).unwrap();
        let user = CurrentUserSid::load().unwrap();
        let guard = SecurePathGuard::open(&candidate, false, Some(&user), true, true).unwrap();
        let rename = std::fs::rename(&candidate, root.path().join("bin/moved.exe"));
        assert!(rename.is_err(), "a guarded candidate path was renameable");
        guard.validate(Some(&user)).unwrap();
        drop(guard);
        drop(root);
        std::fs::remove_dir(container).unwrap();
    }
}
