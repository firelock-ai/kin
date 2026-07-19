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
    ManagedComponentGeneration, PlatformObjectIdentity, WindowsFileId,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NOT_ALL_ASSIGNED,
    ERROR_NO_TOKEN, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, AdjustTokenPrivileges, DuplicateTokenEx, EqualSid,
    GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorSacl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidSid, LookupPrivilegeValueW, SecurityImpersonation, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenImpersonation, TokenUser, ACL,
    ACL_REVISION, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, INHERITED_ACE, INHERIT_ONLY_ACE,
    LABEL_SECURITY_INFORMATION, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    SACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_SACL_AUTO_INHERITED,
    SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
    SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileBasicInfo, FileIdInfo, FileStreamInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_ID_INFO, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STREAM_INFO,
    OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_SYSTEM_SECURITY, SYSTEM_ACCESS_FILTER_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
    SYSTEM_MANDATORY_LABEL_NO_READ_UP, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreatedFileValidationFailure {
    Identity,
    Security,
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_CREATED_FILE_VALIDATION: std::cell::Cell<Option<CreatedFileValidationFailure>> =
        const { std::cell::Cell::new(None) };
    static FAIL_NEXT_STAGED_FILE_DISARM: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn inject_created_file_validation_failure(
    failure: Option<CreatedFileValidationFailure>,
) {
    FAIL_NEXT_CREATED_FILE_VALIDATION.with(|configured| configured.set(failure));
}

#[cfg(test)]
pub(crate) fn inject_staged_file_disarm_failure(fail: bool) {
    FAIL_NEXT_STAGED_FILE_DISARM.with(|configured| configured.set(fail));
}

#[cfg(test)]
fn take_created_file_validation_failure() -> Option<CreatedFileValidationFailure> {
    FAIL_NEXT_CREATED_FILE_VALIDATION.with(std::cell::Cell::take)
}

fn win32_error(context: &str) -> anyhow::Error {
    let error = std::io::Error::last_os_error();
    anyhow::Error::new(error).context(context.to_string())
}

fn windows_error_code(error: &anyhow::Error) -> Option<i32> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
    })
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

struct LocalSecurityDescriptor(*mut core::ffi::c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            let _ = unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
        }
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

#[cfg(test)]
thread_local! {
    static FAIL_SE_SECURITY_PRIVILEGE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn inject_se_security_privilege_unavailable(unavailable: bool) {
    FAIL_SE_SECURITY_PRIVILEGE.with(|configured| configured.set(unavailable));
}

fn se_security_privilege_injected_unavailable() -> bool {
    #[cfg(test)]
    {
        return FAIL_SE_SECURITY_PRIVILEGE.with(std::cell::Cell::get);
    }
    #[cfg(not(test))]
    false
}

struct ThreadSeSecurityPrivilege {
    previous_thread_token: Option<OwnedHandle>,
    _impersonation_token: OwnedHandle,
    attached: bool,
}

impl ThreadSeSecurityPrivilege {
    fn enable() -> Result<Self> {
        if se_security_privilege_injected_unavailable() {
            anyhow::bail!(
                "SeSecurityPrivilege is unavailable; strict Windows full-SACL authority refused before any managed config WAL or namespace transition"
            );
        }
        let mut previous_thread_token = null_mut();
        let previous_thread_token = if unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut previous_thread_token,
            )
        } != 0
        {
            Some(OwnedHandle::new(
                previous_thread_token,
                "effective thread token for SeSecurityPrivilege was invalid",
            )?)
        } else if unsafe { GetLastError() } == ERROR_NO_TOKEN {
            None
        } else {
            return Err(win32_error(
                "failed to capture the exact prior thread impersonation token",
            ));
        };
        let process_token = if previous_thread_token.is_none() {
            let mut token = null_mut();
            if unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut token,
                )
            } == 0
            {
                return Err(win32_error(
                    "failed to open the process token for thread-scoped SeSecurityPrivilege",
                ));
            }
            Some(OwnedHandle::new(
                token,
                "process token for thread-scoped SeSecurityPrivilege was invalid",
            )?)
        } else {
            None
        };
        let base_token = previous_thread_token
            .as_ref()
            .or(process_token.as_ref())
            .context("thread-scoped SeSecurityPrivilege lost its effective base token")?
            .raw();
        let mut impersonation_token = null_mut();
        if unsafe {
            DuplicateTokenEx(
                base_token,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut impersonation_token,
            )
        } == 0
        {
            return Err(win32_error(
                "failed to duplicate the effective token for thread-scoped SeSecurityPrivilege",
            ));
        }
        let impersonation_token = OwnedHandle::new(
            impersonation_token,
            "duplicated thread-scoped SeSecurityPrivilege token was invalid",
        )?;
        let mut requested = TOKEN_PRIVILEGES::default();
        requested.PrivilegeCount = 1;
        if unsafe {
            LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut requested.Privileges[0].Luid)
        } == 0
        {
            return Err(win32_error(
                "failed to resolve SeSecurityPrivilege for strict Windows full-SACL authority",
            ));
        }
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        unsafe { SetLastError(ERROR_SUCCESS) };
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                impersonation_token.raw(),
                0,
                &requested,
                0,
                null_mut(),
                null_mut(),
            )
        };
        let last_error = unsafe { GetLastError() };
        if adjusted == 0 {
            return Err(win32_error(
                "failed to enable SeSecurityPrivilege for strict Windows full-SACL authority",
            ));
        }
        match last_error {
            ERROR_SUCCESS => {}
            ERROR_NOT_ALL_ASSIGNED => anyhow::bail!(
                "SeSecurityPrivilege is not assigned to the effective token; strict Windows full-SACL authority refused before any managed config WAL or namespace transition. Run Kin from a token granted Manage auditing and security log"
            ),
            _ => anyhow::bail!(
                "enabling thread-scoped SeSecurityPrivilege returned unexpected Windows error {last_error}; strict Windows full-SACL authority refused"
            ),
        }
        if unsafe { SetThreadToken(null(), impersonation_token.raw()) } == 0 {
            return Err(win32_error(
                "failed to attach the thread-scoped SeSecurityPrivilege token",
            ));
        }
        Ok(Self {
            previous_thread_token,
            _impersonation_token: impersonation_token,
            attached: true,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        let prior = self
            .previous_thread_token
            .as_ref()
            .map_or(null_mut(), OwnedHandle::raw);
        for _ in 0..2 {
            if unsafe { SetThreadToken(null(), prior) } != 0 {
                self.attached = false;
                return Ok(());
            }
        }
        anyhow::bail!(
            "failed to restore the exact prior thread token after thread-scoped SeSecurityPrivilege (Windows error {})",
            unsafe { GetLastError() }
        )
    }
}

impl Drop for ThreadSeSecurityPrivilege {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!(
                "fatal: {error:#}; aborting to prevent a pooled worker from continuing elevated"
            );
            std::process::abort();
        }
    }
}

fn open_with_se_security_privilege(
    context: &str,
    cleanup_new_file_on_restore_failure: bool,
    open: impl FnOnce() -> HANDLE,
) -> Result<OwnedHandle> {
    let mut privilege = ThreadSeSecurityPrivilege::enable()?;
    let opened = OwnedHandle::new(open(), context);
    if let Err(error) = privilege.restore() {
        let cleanup = match opened.as_ref() {
            Ok(handle) if cleanup_new_file_on_restore_failure => {
                mark_newly_created_handle_for_cleanup(handle.raw()).err()
            }
            _ => None,
        };
        drop(opened);
        if let Some(cleanup) = cleanup {
            eprintln!(
                "fatal: {error:#}; exact CREATE_NEW cleanup also failed: {cleanup:#}; aborting to prevent a pooled worker from continuing elevated"
            );
        } else {
            eprintln!(
                "fatal: {error:#}; aborting to prevent a pooled worker from continuing elevated"
            );
        }
        std::process::abort();
    }
    opened
}

fn unsupported_sacl_ace_name(ace_type: u8) -> &'static str {
    match u32::from(ace_type) {
        SYSTEM_AUDIT_ACE_TYPE
        | SYSTEM_AUDIT_OBJECT_ACE_TYPE
        | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
        | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => "audit",
        SYSTEM_ALARM_ACE_TYPE
        | SYSTEM_ALARM_OBJECT_ACE_TYPE
        | SYSTEM_ALARM_CALLBACK_ACE_TYPE
        | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => "alarm",
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => "resource attribute",
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => "central access policy scope",
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE => "process trust label",
        SYSTEM_ACCESS_FILTER_ACE_TYPE => "access filter",
        _ => "unknown",
    }
}

fn validate_supported_full_sacl_bytes(bytes: &[u8]) -> Result<u16> {
    const ACL_HEADER_BYTES: usize = 8;
    const ACE_HEADER_BYTES: usize = 4;
    const MANDATORY_LABEL_FIXED_BYTES: usize = 8;
    const SID_HEADER_BYTES: usize = 8;
    const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];

    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() < ACL_HEADER_BYTES {
        anyhow::bail!("managed config full SACL header is truncated");
    }
    if bytes[0] != ACL_REVISION as u8 && bytes[0] != ACL_REVISION_DS as u8 {
        anyhow::bail!(
            "managed config full SACL has unsupported ACL revision {}",
            bytes[0]
        );
    }
    let allocated = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if allocated < bytes.len() {
        anyhow::bail!("managed config full SACL bytes exceed the ACL allocation");
    }
    let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]);
    let mut offset = ACL_HEADER_BYTES;
    let mut mandatory_labels = 0_u16;
    for index in 0..ace_count {
        let header_end = offset
            .checked_add(ACE_HEADER_BYTES)
            .context("managed config full SACL ACE header offset overflow")?;
        if header_end > bytes.len() {
            anyhow::bail!("managed config full SACL ACE {index} header is truncated");
        }
        let ace_type = bytes[offset];
        let ace_flags = bytes[offset + 1];
        let ace_size = usize::from(u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]));
        if ace_size < ACE_HEADER_BYTES || ace_size % size_of::<u32>() != 0 {
            anyhow::bail!("managed config full SACL ACE {index} has invalid AceSize {ace_size}");
        }
        let ace_end = offset
            .checked_add(ace_size)
            .context("managed config full SACL ACE size overflow")?;
        if ace_end > bytes.len() {
            anyhow::bail!("managed config full SACL ACE {index} escapes AclBytesInUse");
        }
        if u32::from(ace_type) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            let kind = unsupported_sacl_ace_name(ace_type);
            anyhow::bail!(
                "managed config full SACL contains unsupported {kind} ACE type {ace_type}; only one optional mandatory label ACE is supported"
            );
        }
        mandatory_labels = mandatory_labels
            .checked_add(1)
            .context("managed config mandatory label count overflow")?;
        if mandatory_labels > 1 {
            anyhow::bail!("managed config full SACL contains duplicate mandatory label ACEs");
        }
        let supported_ace_flags = (OBJECT_INHERIT_ACE
            | CONTAINER_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | INHERIT_ONLY_ACE
            | INHERITED_ACE) as u8;
        if ace_flags & !supported_ace_flags != 0 {
            anyhow::bail!(
                "managed config mandatory label ACE has unsupported flags 0x{ace_flags:02x}"
            );
        }
        if ace_size < MANDATORY_LABEL_FIXED_BYTES + SID_HEADER_BYTES + size_of::<u32>() {
            anyhow::bail!("managed config mandatory label ACE is structurally truncated");
        }
        let mask = u32::from_le_bytes(
            bytes[offset + ACE_HEADER_BYTES..offset + MANDATORY_LABEL_FIXED_BYTES]
                .try_into()
                .expect("mandatory label mask has a fixed four-byte span"),
        );
        let supported_mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
        if mask & !supported_mask != 0 {
            anyhow::bail!(
                "managed config mandatory label ACE has unsupported policy mask 0x{mask:08x}"
            );
        }
        let sid = &bytes[offset + MANDATORY_LABEL_FIXED_BYTES..ace_end];
        if sid[0] != 1 || sid[1] != 1 || sid[2..8] != MANDATORY_LABEL_AUTHORITY {
            anyhow::bail!("managed config mandatory label ACE has a non-integrity SID");
        }
        let sid_len = SID_HEADER_BYTES
            .checked_add(usize::from(sid[1]) * size_of::<u32>())
            .context("managed config mandatory label SID length overflow")?;
        if sid_len != sid.len() {
            anyhow::bail!("managed config mandatory label SID length is not exact");
        }
        offset = ace_end;
    }
    if offset != bytes.len() {
        anyhow::bail!("managed config full SACL has trailing or unenumerated bytes");
    }
    Ok(mandatory_labels)
}

pub(crate) fn validate_managed_file_full_sacl(file: &File) -> Result<()> {
    validate_full_sacl_handle(file.as_raw_handle().cast())
}

pub(crate) fn managed_file_full_sacl_fingerprint(file: &File) -> Result<String> {
    full_sacl_fingerprint_handle(file.as_raw_handle().cast())
}

pub(crate) fn require_managed_file_full_sacl_fingerprint(
    file: &File,
    expected: &str,
) -> Result<()> {
    let observed = managed_file_full_sacl_fingerprint(file)?;
    if observed != expected {
        anyhow::bail!("managed config full SACL differs from recorded transaction authority");
    }
    Ok(())
}

fn validate_full_sacl_handle(handle: HANDLE) -> Result<()> {
    full_sacl_fingerprint_handle(handle).map(|_| ())
}

fn full_sacl_fingerprint_handle(handle: HANDLE) -> Result<String> {
    let mut sacl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sacl,
            &mut descriptor,
        )
    };
    if result != 0 {
        anyhow::bail!(
            "failed to inspect exact managed config full SACL with retained ACCESS_SYSTEM_SECURITY: Windows error {result}"
        );
    }
    if descriptor.is_null() {
        anyhow::bail!("full-SACL query returned no security descriptor authority");
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    let mut descriptor_sacl = null_mut();
    let mut sacl_present = 0;
    let mut sacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor,
            &mut sacl_present,
            &mut descriptor_sacl,
            &mut sacl_defaulted,
        )
    } == 0
    {
        return Err(win32_error(
            "failed to cross-check exact managed config full SACL presence",
        ));
    }
    if descriptor_sacl != sacl {
        anyhow::bail!("full-SACL query returned inconsistent descriptor and ACL pointers");
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(win32_error(
            "failed to inspect exact managed config full SACL control",
        ));
    }
    if control & SE_SACL_PROTECTED != 0 {
        anyhow::bail!(
            "managed config has SE_SACL_PROTECTED authority that Kin cannot preserve with label-only staging; refusing before Prepared"
        );
    }
    if (control & SE_SACL_PRESENT != 0) != (sacl_present != 0) {
        anyhow::bail!("managed config full SACL presence control is inconsistent");
    }
    if (control & SE_SACL_DEFAULTED != 0) != (sacl_defaulted != 0) {
        anyhow::bail!("managed config full SACL defaulted control is inconsistent");
    }
    let bytes = if sacl.is_null() {
        validate_supported_full_sacl_bytes(&[])?;
        &[][..]
    } else {
        let mut info = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                sacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(win32_error("failed to size exact managed config full SACL"));
        }
        let bytes_in_use = usize::try_from(info.AclBytesInUse)
            .context("managed config full SACL byte length overflow")?;
        if bytes_in_use < size_of::<ACL>() {
            anyhow::bail!("managed config full SACL has an invalid byte length");
        }
        let bytes = unsafe { std::slice::from_raw_parts(sacl.cast::<u8>(), bytes_in_use) };
        let parsed_count = validate_supported_full_sacl_bytes(bytes)?;
        if u32::from(parsed_count) != info.AceCount {
            anyhow::bail!("managed config full SACL parser count differs from GetAclInformation");
        }
        for index in 0..info.AceCount {
            let mut ace = null_mut();
            if unsafe { GetAce(sacl, index, &mut ace) } == 0 {
                return Err(win32_error(
                    "failed to enumerate exact managed config full SACL",
                ));
            }
            let base = sacl as usize;
            let ace_offset = (ace as usize)
                .checked_sub(base)
                .context("managed config full SACL ACE precedes its ACL")?;
            if ace_offset < size_of::<ACL>() || ace_offset >= bytes_in_use {
                anyhow::bail!("managed config full SACL GetAce pointer escapes AclBytesInUse");
            }
        }
        bytes
    };
    let relevant_control = control
        & (SE_SACL_PRESENT
            | SE_SACL_DEFAULTED
            | SE_SACL_PROTECTED
            | SE_SACL_AUTO_INHERITED
            | SE_SACL_AUTO_INHERIT_REQ);
    let mut canonical = Vec::with_capacity(bytes.len() + 24);
    canonical.extend_from_slice(b"KIN_WINDOWS_FULL_SACL_V1\0");
    canonical.extend_from_slice(&relevant_control.to_le_bytes());
    canonical.push(u8::from(sacl_present != 0));
    canonical.push(u8::from(sacl_defaulted != 0));
    canonical.push(u8::from(sacl.is_null()));
    canonical.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    canonical.extend_from_slice(bytes);
    Ok(crate::commands::setup_ledger::sha256_hex(&canonical))
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

/// Validate a private managed file using its already-open, no-reparse handle.
/// This is shared with setup-ledger/config authority on Windows.
pub(crate) fn validate_current_user_private_file(file: &File) -> Result<()> {
    let user = CurrentUserSid::load()?;
    let handle = file.as_raw_handle().cast();
    object_identity(handle, false)?;
    validate_private_security(handle, &user)
}

struct ManagedFileSecurity {
    _descriptor: LocalSecurityDescriptor,
    owner: PSID,
    group: PSID,
    dacl: *mut ACL,
    label: *mut ACL,
    control: u16,
}

fn read_managed_file_security(file: &File) -> Result<ManagedFileSecurity> {
    let mut owner = null_mut();
    let mut group = null_mut();
    let mut dacl = null_mut();
    let mut label = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut label,
            &mut descriptor,
        )
    };
    if result != 0 {
        anyhow::bail!("failed to inspect managed config security: Windows error {result}");
    }
    let descriptor_owner = LocalSecurityDescriptor(descriptor);
    if owner.is_null() || group.is_null() || dacl.is_null() {
        anyhow::bail!("managed config requires explicit owner, group, and non-NULL DACL authority");
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(win32_error(
            "failed to inspect managed config DACL protection",
        ));
    }
    Ok(ManagedFileSecurity {
        _descriptor: descriptor_owner,
        owner,
        group,
        dacl,
        label,
        control,
    })
}

/// Stable proof of the exact owner/DACL/protection attached to a managed
/// config handle. Recovery records use this alongside bytes and file identity.
pub(crate) fn managed_file_security_fingerprint(file: &File) -> Result<String> {
    let security = read_managed_file_security(file)?;
    let owner_len = unsafe { GetLengthSid(security.owner) } as usize;
    let group_len = unsafe { GetLengthSid(security.group) } as usize;
    if owner_len == 0 || group_len == 0 {
        anyhow::bail!("managed config owner/group SID has invalid length");
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            security.dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(win32_error("failed to size managed config DACL"));
    }
    let acl_len = acl_info.AclBytesInUse as usize;
    if acl_len < size_of::<ACL>() {
        anyhow::bail!("managed config DACL has invalid byte length");
    }
    let owner = unsafe { std::slice::from_raw_parts(security.owner.cast::<u8>(), owner_len) };
    let group = unsafe { std::slice::from_raw_parts(security.group.cast::<u8>(), group_len) };
    let dacl = unsafe { std::slice::from_raw_parts(security.dacl.cast::<u8>(), acl_len) };
    let label = if security.label.is_null() {
        &[][..]
    } else {
        let mut label_info = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                security.label,
                (&mut label_info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(win32_error("failed to size managed config mandatory label"));
        }
        let label_len = label_info.AclBytesInUse as usize;
        if label_len < size_of::<ACL>() {
            anyhow::bail!("managed config mandatory label has invalid byte length");
        }
        unsafe { std::slice::from_raw_parts(security.label.cast::<u8>(), label_len) }
    };
    let relevant_control = security.control
        & (SE_DACL_PROTECTED
            | SE_DACL_AUTO_INHERITED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_SACL_PROTECTED
            | SE_SACL_AUTO_INHERITED
            | SE_SACL_AUTO_INHERIT_REQ);
    let mut canonical = Vec::with_capacity(owner_len + group_len + acl_len + label.len() + 18);
    canonical.extend_from_slice(&(owner_len as u32).to_le_bytes());
    canonical.extend_from_slice(owner);
    canonical.extend_from_slice(&(group_len as u32).to_le_bytes());
    canonical.extend_from_slice(group);
    canonical.extend_from_slice(&(acl_len as u32).to_le_bytes());
    canonical.extend_from_slice(dacl);
    canonical.extend_from_slice(&(label.len() as u32).to_le_bytes());
    canonical.extend_from_slice(label);
    canonical.extend_from_slice(&relevant_control.to_le_bytes());
    Ok(crate::commands::setup_ledger::sha256_hex(&canonical))
}

/// Preserve the existing non-private config's owner, DACL, and inheritance
/// policy on its staged replacement before the namespace transition.
pub(crate) fn copy_managed_file_security(source: &File, destination: &File) -> Result<()> {
    object_identity(source.as_raw_handle().cast(), false)?;
    object_identity(destination.as_raw_handle().cast(), false)?;
    let source_fingerprint = managed_file_security_fingerprint(source)?;
    let security = read_managed_file_security(source)?;
    let protection = if security.control & SE_DACL_PROTECTED != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let mut security_information = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | protection;
    if !security.label.is_null() {
        // LABEL_SECURITY_INFORMATION is a READ_CONTROL/WRITE_OWNER surface.
        // SACL protection flags describe the privileged full audit SACL and
        // must never be combined with a label-only ACL.
        security_information |= LABEL_SECURITY_INFORMATION;
    }
    let result = unsafe {
        SetSecurityInfo(
            destination.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security_information,
            security.owner,
            security.group,
            security.dacl,
            security.label,
        )
    };
    if result != 0 {
        anyhow::bail!("failed to preserve managed config owner/DACL: Windows error {result}");
    }
    let destination_fingerprint = managed_file_security_fingerprint(destination)?;
    if destination_fingerprint != source_fingerprint {
        anyhow::bail!("staged managed config owner/DACL differs after security copy");
    }
    Ok(())
}

const SUPPORTED_CONFIG_ATTRIBUTES: u32 = FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

fn managed_config_attributes(file: &File) -> Result<u32> {
    let mut basic = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (&raw mut basic).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(win32_error(
            "failed to inspect managed config basic attributes",
        ));
    }
    let attributes = basic.FileAttributes;
    if attributes & FILE_ATTRIBUTE_NORMAL != 0 && attributes != FILE_ATTRIBUTE_NORMAL {
        anyhow::bail!("managed config combines FILE_ATTRIBUTE_NORMAL with other attributes");
    }
    let unsupported = attributes & !(SUPPORTED_CONFIG_ATTRIBUTES | FILE_ATTRIBUTE_NORMAL);
    if unsupported != 0 {
        anyhow::bail!(
            "managed config carries unsupported Windows attributes 0x{unsupported:08x}; refusing replacement before Prepared"
        );
    }
    Ok(attributes & SUPPORTED_CONFIG_ATTRIBUTES)
}

fn parse_managed_config_stream_buffer(bytes: &[u8]) -> Result<Vec<String>> {
    let header_len = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let next_offset = std::mem::offset_of!(FILE_STREAM_INFO, NextEntryOffset);
    let name_length_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamNameLength);
    let mut offset = 0_usize;
    let mut names = Vec::new();
    loop {
        let remaining = bytes
            .get(offset..)
            .context("managed config stream record offset exceeds its buffer")?;
        if remaining.len() < header_len {
            anyhow::bail!("managed config stream record header is truncated");
        }
        let next_entry = u32::from_ne_bytes(
            remaining[next_offset..next_offset + size_of::<u32>()]
                .try_into()
                .expect("FILE_STREAM_INFO next-entry field fits its header"),
        );
        let name_bytes = usize::try_from(u32::from_ne_bytes(
            remaining[name_length_offset..name_length_offset + size_of::<u32>()]
                .try_into()
                .expect("FILE_STREAM_INFO name-length field fits its header"),
        ))
        .context("managed config stream name length overflow")?;
        if name_bytes == 0 || name_bytes % size_of::<u16>() != 0 {
            anyhow::bail!("managed config stream name has invalid UTF-16 byte length");
        }
        let record_len = header_len
            .checked_add(name_bytes)
            .context("managed config stream record length overflow")?;
        if record_len > remaining.len() {
            anyhow::bail!("managed config stream name exceeds its record buffer");
        }
        let name = remaining[header_len..record_len]
            .chunks_exact(size_of::<u16>())
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        names.push(
            String::from_utf16(&name).context("managed config stream name is invalid UTF-16")?,
        );
        if next_entry == 0 {
            break;
        }
        let next = usize::try_from(next_entry).context("managed config stream offset overflow")?;
        if next < record_len || next % size_of::<usize>() != 0 {
            anyhow::bail!("managed config stream chain has an invalid next-entry offset");
        }
        offset = offset
            .checked_add(next)
            .context("managed config stream chain offset overflow")?;
        if offset >= bytes.len() {
            anyhow::bail!("managed config stream chain escapes its buffer");
        }
    }
    Ok(names)
}

fn managed_config_streams(file: &File) -> Result<Vec<String>> {
    const MAX_STREAM_BUFFER: usize = 16 * 1024 * 1024;
    let mut bytes = 4096_usize;
    loop {
        let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FileStreamInfo,
                storage.as_mut_ptr().cast(),
                u32::try_from(bytes).context("managed config stream buffer exceeds u32")?,
            )
        } != 0
        {
            let buffer = unsafe {
                std::slice::from_raw_parts(
                    storage.as_ptr().cast::<u8>(),
                    storage.len() * size_of::<usize>(),
                )
            };
            let streams = parse_managed_config_stream_buffer(buffer)?;
            if streams != ["::$DATA"] {
                anyhow::bail!(
                    "managed config has alternate or ambiguous data streams; refusing replacement before Prepared: {streams:?}"
                );
            }
            return Ok(streams);
        }
        let error = unsafe { GetLastError() };
        if (error == ERROR_MORE_DATA || error == ERROR_INSUFFICIENT_BUFFER)
            && bytes < MAX_STREAM_BUFFER
        {
            bytes = bytes
                .checked_mul(2)
                .context("managed config stream buffer growth overflow")?;
            continue;
        }
        anyhow::bail!("failed to inspect managed config streams: Windows error {error}");
    }
}

/// Stable handle-derived Windows metadata authority used by setup CAS and WAL.
pub(crate) fn managed_file_metadata_fingerprint(file: &File) -> Result<String> {
    let security = managed_file_security_fingerprint(file)?;
    let attributes = managed_config_attributes(file)?;
    let streams = managed_config_streams(file)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"KIN_WINDOWS_CONFIG_METADATA_V1\0");
    canonical.extend_from_slice(security.as_bytes());
    canonical.extend_from_slice(&attributes.to_le_bytes());
    for stream in streams {
        canonical.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        canonical.extend_from_slice(stream.as_bytes());
    }
    Ok(crate::commands::setup_ledger::sha256_hex(&canonical))
}

/// Preserve the bounded Windows metadata contract on the staged replacement.
pub(crate) fn copy_managed_file_metadata(source: &File, destination: &File) -> Result<()> {
    let source_full_sacl = managed_file_full_sacl_fingerprint(source)
        .context("existing managed config full SACL is unsupported before metadata copy")?;
    managed_file_full_sacl_fingerprint(destination)
        .context("staged managed config full SACL is unsupported before metadata copy")?;
    let source_fingerprint = managed_file_metadata_fingerprint(source)?;
    copy_managed_file_security(source, destination)?;
    let attributes = managed_config_attributes(source)?;
    let basic = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: if attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attributes
        },
    };
    if unsafe {
        SetFileInformationByHandle(
            destination.as_raw_handle().cast(),
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to preserve managed config basic attributes");
    }
    let destination_fingerprint = managed_file_metadata_fingerprint(destination)?;
    if destination_fingerprint != source_fingerprint {
        anyhow::bail!("staged managed config Windows metadata differs after exact copy");
    }
    let source_full_sacl_after = managed_file_full_sacl_fingerprint(source)
        .context("existing managed config full SACL changed during metadata copy")?;
    if source_full_sacl_after != source_full_sacl {
        anyhow::bail!("existing managed config full SACL changed during metadata copy");
    }
    let destination_full_sacl = managed_file_full_sacl_fingerprint(destination)
        .context("staged managed config full SACL is unsupported after metadata copy")?;
    if destination_full_sacl != source_full_sacl {
        anyhow::bail!("staged managed config full SACL differs after label-only metadata copy");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn inject_test_managed_file_dacl_drift(file: &File) -> Result<()> {
    let before = managed_file_metadata_fingerprint(file)?;
    let user = CurrentUserSid::load()?;
    apply_private_security(file.as_raw_handle().cast(), &user)?;
    let after = managed_file_metadata_fingerprint(file)?;
    if after == before {
        anyhow::bail!("test DACL injection did not change managed-file authority");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn inject_test_managed_file_supported_sacl_drift(file: &File) -> Result<()> {
    use windows_sys::Win32::Security::AddMandatoryAce;

    let before = managed_file_full_sacl_fingerprint(file)?;
    let mut label_storage = vec![0_usize; 4];
    let label_bytes = label_storage.len() * size_of::<usize>();
    let label = label_storage.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(label, label_bytes as u32, ACL_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to initialize test mandatory-label ACL");
    }
    let mut sid_storage = [0_usize; 2];
    let sid = unsafe {
        std::slice::from_raw_parts_mut(
            sid_storage.as_mut_ptr().cast::<u8>(),
            sid_storage.len() * size_of::<usize>(),
        )
    };
    sid[..12].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0]);
    if unsafe {
        AddMandatoryAce(
            label,
            ACL_REVISION,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
            sid.as_mut_ptr().cast(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to build test mandatory-label ACE");
    }
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            label,
        )
    };
    if result != 0 {
        anyhow::bail!("failed to inject supported test SACL drift: Windows error {result}");
    }
    let after = managed_file_full_sacl_fingerprint(file)?;
    if after == before {
        anyhow::bail!("test SACL injection did not change managed-file authority");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn inject_test_managed_file_unsupported_sacl(file: &File) -> Result<()> {
    use windows_sys::Win32::Security::AddAuditAccessAceEx;

    let user = CurrentUserSid::load()?;
    let mut sacl_storage = vec![0_usize; 16];
    let sacl_bytes = sacl_storage.len() * size_of::<usize>();
    let sacl = sacl_storage.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(sacl, sacl_bytes as u32, ACL_REVISION) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to initialize unsupported test SACL");
    }
    if unsafe { AddAuditAccessAceEx(sacl, ACL_REVISION, 0, GENERIC_READ, user.sid(), 1, 0) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to build unsupported test audit ACE");
    }
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            sacl,
        )
    };
    if result != 0 {
        anyhow::bail!("failed to inject unsupported test SACL: Windows error {result}");
    }
    let error = managed_file_full_sacl_fingerprint(file)
        .expect_err("test audit ACE must be rejected by strict full-SACL policy");
    if !format!("{error:#}").contains("unsupported") {
        anyhow::bail!("test audit SACL produced an unexpected strict-policy error: {error:#}");
    }
    Ok(())
}

fn create_current_user_private_file_with_disposition(
    path: &Path,
    disposition: u32,
    share_mode: u32,
    additional_access: u32,
    arm_delete_on_close: bool,
) -> Result<File> {
    let user = CurrentUserSid::load()?;
    let path_wide = wide_null(path.as_os_str())?;
    let mut acl = build_private_acl(user.sid())?;
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    // SAFETY: descriptor is writable and all SID/ACL buffers remain live until
    // CreateFileW returns.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0
        || unsafe { SetSecurityDescriptorOwner(descriptor_ptr, user.sid(), 0) } == 0
        || unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.as_mut_ptr().cast(), 0) } == 0
        || unsafe {
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
    {
        return Err(win32_error(
            "failed to configure private managed-file security descriptor",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    let context = format!(
        "failed to create/open private managed file {}",
        path.display()
    );
    let open = || unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | additional_access,
            share_mode,
            &attributes,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT
                | FILE_FLAG_WRITE_THROUGH
                | if arm_delete_on_close {
                    FILE_FLAG_DELETE_ON_CLOSE
                } else {
                    0
                },
            null_mut(),
        )
    };
    let handle = if additional_access & ACCESS_SYSTEM_SECURITY != 0 {
        open_with_se_security_privilege(&context, disposition == CREATE_NEW, open)?
    } else {
        OwnedHandle::new(open(), &context)?
    };
    if let Err(error) = (|| -> Result<()> {
        #[cfg(test)]
        let injected = if disposition == CREATE_NEW {
            take_created_file_validation_failure()
        } else {
            None
        };
        #[cfg(test)]
        if injected == Some(CreatedFileValidationFailure::Identity) {
            anyhow::bail!("injected created-file identity validation failure");
        }
        object_identity(handle.raw(), false)?;
        #[cfg(test)]
        if injected == Some(CreatedFileValidationFailure::Security) {
            anyhow::bail!("injected created-file security validation failure");
        }
        validate_private_security(handle.raw(), &user).and_then(|_| {
            if additional_access & ACCESS_SYSTEM_SECURITY != 0 {
                validate_full_sacl_handle(handle.raw())
            } else {
                Ok(())
            }
        })
    })() {
        if disposition == CREATE_NEW && !arm_delete_on_close {
            if let Err(cleanup) = mark_newly_created_handle_for_cleanup(handle.raw()) {
                return Err(error.context(format!(
                    "new private managed file validation failed and exact-handle cleanup also failed; object retained at {}: {cleanup:#}",
                    path.display()
                )));
            }
        }
        return Err(error);
    }
    Ok(handle.into_file())
}

fn mark_newly_created_handle_for_cleanup(handle: HANDLE) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to mark newly created exact handle for cleanup");
    }
    Ok(())
}

/// Clear the pre-Prepared delete-on-close arm only after the durable Prepared
/// WAL frame has been synced. FILE_FLAG_DELETE_ON_CLOSE is permanent on its
/// original file object, so authority is handed to a second no-flag file
/// object before the armed handle closes and legacy disposition is cleared.
pub(crate) fn disarm_staged_file_delete_on_close(
    armed: File,
    path: &Path,
    private: bool,
    require_full_sacl: bool,
) -> Result<File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, FileStandardInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
        FILE_STANDARD_INFO,
    };

    let armed_identity = object_identity(armed.as_raw_handle().cast(), false)?;
    let durable = if private {
        create_current_user_private_file_with_disposition(
            path,
            OPEN_EXISTING,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | if require_full_sacl {
                    ACCESS_SYSTEM_SECURITY
                } else {
                    0
                },
            false,
        )?
    } else {
        let path_wide = wide_null(path.as_os_str())?;
        let desired_access = GENERIC_READ
            | GENERIC_WRITE
            | FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER
            | DELETE
            | if require_full_sacl {
                ACCESS_SYSTEM_SECURITY
            } else {
                0
            };
        let context = format!("failed to open staged handoff object {}", path.display());
        let open = || unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        let handle = if require_full_sacl {
            open_with_se_security_privilege(&context, false, open)?
        } else {
            OwnedHandle::new(open(), &context)?
        };
        object_identity(handle.raw(), false)?;
        if require_full_sacl {
            validate_full_sacl_handle(handle.raw())?;
        }
        handle.into_file()
    };
    let durable_identity = object_identity(durable.as_raw_handle().cast(), false)?;
    if durable_identity != armed_identity {
        anyhow::bail!("staged handoff reopened a different file identity");
    }
    #[cfg(test)]
    if FAIL_NEXT_STAGED_FILE_DISARM.with(|configured| configured.replace(false)) {
        anyhow::bail!("injected staged-file delete-on-close disarm failure");
    }
    drop(armed);

    let handle = durable.as_raw_handle().cast();
    let mut before = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut before as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to read staged delete-pending state during handoff");
    }
    if !before.DeletePending {
        anyhow::bail!("armed staged object did not become delete-pending during handoff");
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: false };
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to disarm exact staged object after durable Prepared WAL");
    }
    let mut after = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut after as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to verify staged delete-on-close state after disarm");
    }
    if after.DeletePending {
        anyhow::bail!("staged object remained delete-pending after exact disarm");
    }
    if object_identity(handle, false)? != armed_identity {
        anyhow::bail!("staged handoff identity changed after disposition clear");
    }
    revalidate_managed_file_path(path, &durable, private, require_full_sacl)?;
    Ok(durable)
}

/// Create one current-user-only marker with exact-object cleanup authority.
/// DELETE is requested on the returned handle and FILE_SHARE_DELETE remains
/// absent, so callers can dispose only this CREATE_NEW object by handle if a
/// write/sync fails without ever unlinking a replacement pathname.
pub(crate) fn create_current_user_private_file_for_exact_commit(path: &Path) -> Result<File> {
    create_current_user_private_file_with_disposition(
        path,
        CREATE_NEW,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        DELETE,
        false,
    )
}

/// Create a private staged file whose live handle remains the rename
/// authority. DELETE access authorizes FileRenameInfoEx on this exact handle;
/// sharing remains read-only so no writer or path replacement can race it.
pub(crate) fn create_current_user_private_staged_file(
    path: &Path,
    require_full_sacl: bool,
) -> Result<File> {
    create_current_user_private_file_with_disposition(
        path,
        CREATE_NEW,
        FILE_SHARE_READ,
        DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | if require_full_sacl {
                ACCESS_SYSTEM_SECURITY
            } else {
                0
            },
        true,
    )
}

/// Create a non-private managed config staging file while retaining exact
/// rename and disposition authority on its handle.
pub(crate) fn create_managed_config_staged_file(
    path: &Path,
    require_full_sacl: bool,
) -> Result<File> {
    let path_wide = wide_null(path.as_os_str())?;
    let desired_access = GENERIC_READ
        | GENERIC_WRITE
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | DELETE
        | if require_full_sacl {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        };
    let context = format!(
        "failed to create managed config staging file {}",
        path.display()
    );
    let open = || unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_DELETE_ON_CLOSE,
            null_mut(),
        )
    };
    let handle = if require_full_sacl {
        open_with_se_security_privilege(&context, true, open)?
    } else {
        OwnedHandle::new(open(), &context)?
    };
    let validated = (|| -> Result<()> {
        #[cfg(test)]
        if take_created_file_validation_failure() == Some(CreatedFileValidationFailure::Identity) {
            anyhow::bail!("injected created-file identity validation failure");
        }
        object_identity(handle.raw(), false)?;
        if require_full_sacl {
            validate_full_sacl_handle(handle.raw())?;
        }
        Ok(())
    })();
    if let Err(error) = validated {
        return Err(error);
    }
    Ok(handle.into_file())
}

/// Open the exact destination config with DELETE authority while deliberately
/// denying delete sharing. The retained handle prevents a non-cooperating
/// writer from replacing the pathname between validation and quarantine.
pub(crate) fn open_managed_config_for_exact_quarantine(
    path: &Path,
    require_full_sacl: bool,
) -> Result<File> {
    open_managed_config_for_exact_quarantine_inner(path, require_full_sacl, true)
}

/// Open one exact regular object for initial crash-recovery inventory.
///
/// The handle retains DELETE and, when requested, ACCESS_SYSTEM_SECURITY so
/// the caller can relocate it and later perform strict validation. Initial
/// inventory deliberately does not parse the SACL: a corrupt replacement must
/// not prevent the exact original from being restored first.
pub(crate) fn open_managed_config_for_exact_inventory(
    path: &Path,
    request_full_sacl_access: bool,
) -> Result<File> {
    open_managed_config_for_exact_quarantine_inner(path, request_full_sacl_access, false)
}

fn open_managed_config_for_exact_quarantine_inner(
    path: &Path,
    require_full_sacl: bool,
    validate_full_sacl: bool,
) -> Result<File> {
    let path_wide = wide_null(path.as_os_str())?;
    let context = format!(
        "failed to retain exact managed config destination {} with full-SACL authority",
        path.display()
    );
    let desired_access = GENERIC_READ
        | GENERIC_WRITE
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | DELETE
        | if require_full_sacl {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        };
    let open = || unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    let handle = if require_full_sacl {
        open_with_se_security_privilege(&context, false, open)?
    } else {
        OwnedHandle::new(open(), &context)?
    };
    object_identity(handle.raw(), false)?;
    if require_full_sacl && validate_full_sacl {
        validate_full_sacl_handle(handle.raw())?;
    }
    Ok(handle.into_file())
}

/// Open a managed config for a terminal authority check without requesting
/// mutation rights or blocking retained exact handles. Strict replacement
/// recovery still receives ACCESS_SYSTEM_SECURITY on this thread-scoped open.
pub(crate) fn open_managed_config_for_terminal_observation(
    path: &Path,
    require_full_sacl: bool,
) -> Result<File> {
    let path_wide = wide_null(path.as_os_str())?;
    let desired_access = GENERIC_READ
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | if require_full_sacl {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        };
    let context = format!(
        "failed to open managed config terminal observation {}",
        path.display()
    );
    let open = || unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = if require_full_sacl {
        open_with_se_security_privilege(&context, false, open)?
    } else {
        OwnedHandle::new(open(), &context)?
    };
    object_identity(handle.raw(), false)?;
    if require_full_sacl {
        validate_full_sacl_handle(handle.raw())?;
    }
    Ok(handle.into_file())
}

/// Rename the exact private object named by `file` to an absolute destination.
/// The variable-size FILE_RENAME_INFO buffer is pointer-aligned and carries
/// FileRenameInfoEx's replace flag; the source pathname is never reopened.
pub(crate) fn rename_private_file_handle_exact(
    file: &File,
    destination: &Path,
    replace: bool,
) -> Result<()> {
    validate_current_user_private_file(file)?;
    rename_managed_file_handle_exact(file, destination, replace)
}

/// Rename an already validated regular managed-file handle. The handle, not a
/// source pathname reopened after validation, is the mutation authority.
pub(crate) fn rename_managed_file_handle_exact(
    file: &File,
    destination: &Path,
    replace: bool,
) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, FILE_RENAME_INFO,
    };

    if !destination.is_absolute() {
        anyhow::bail!(
            "private handle rename destination is not absolute: {}",
            destination.display()
        );
    }
    object_identity(file.as_raw_handle().cast(), false)?;
    let destination_path = destination.to_path_buf();
    let destination_wide = destination.as_os_str().encode_wide().collect::<Vec<_>>();
    if destination_wide.is_empty() || destination_wide.contains(&0) {
        anyhow::bail!("private handle rename destination is empty or contains an interior NUL");
    }
    let name_bytes = destination_wide
        .len()
        .checked_mul(size_of::<u16>())
        .context("private handle rename destination length overflow")?;
    let buffer_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .and_then(|value| value.checked_add(size_of::<u16>()))
        .context("private handle rename buffer length overflow")?;
    let file_name_length = u32::try_from(name_bytes)
        .context("private handle rename destination exceeds Windows length limit")?;
    let buffer_length = u32::try_from(buffer_bytes)
        .context("private handle rename buffer exceeds Windows length limit")?;
    let mut storage = vec![0_usize; buffer_bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // FileRenameInfoEx uses the union's Flags member. Bit zero is the
    // documented FILE_RENAME_FLAG_REPLACE_IF_EXISTS value.
    unsafe {
        (*info).Anonymous.Flags = u32::from(replace);
        (*info).RootDirectory = null_mut();
        (*info).FileNameLength = file_name_length;
        std::ptr::copy_nonoverlapping(
            destination_wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            destination_wide.len(),
        );
        *std::ptr::addr_of_mut!((*info).FileName)
            .cast::<u16>()
            .add(destination_wide.len()) = 0;
    }
    let renamed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileRenameInfoEx,
            info.cast(),
            buffer_length,
        )
    };
    if renamed == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to rename exact private handle to {}",
                destination_path.display()
            )
        });
    }
    // Crossing this boundary commits the exact object at `destination`.
    // Do not perform any fallible post-commit work here: callers must first
    // mark the object committed, then validate/sync it without ever disposing
    // the destination handle on a post-commit failure.
    Ok(())
}

/// Delete the exact private object retained by `file`. The handle is validated
/// before disposition so a substituted pathname can never become cleanup
/// authority.
pub(crate) fn dispose_private_file_handle_exact(
    file: &File,
    path: &Path,
    label: &str,
) -> Result<()> {
    validate_current_user_private_file(file).with_context(|| {
        format!(
            "{label} exact handle lost object authority at {}",
            path.display()
        )
    })?;
    dispose_managed_file_handle_exact(file, label)
}

/// Delete the exact regular managed-file object retained by `file`.
pub(crate) fn dispose_managed_file_handle_exact(file: &File, label: &str) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    object_identity(file.as_raw_handle().cast(), false)
        .with_context(|| format!("{label} exact handle lost object authority"))?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let removed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to dispose exact {label}; object retained"));
    }
    Ok(())
}

/// Open or create the persistent setup ConfigLock sidecar. A new file receives
/// its protected current-user-only DACL in the CreateFileW call; an existing
/// file must already satisfy the same authority.
pub(crate) fn open_or_create_current_user_private_file(path: &Path) -> Result<File> {
    open_or_create_current_user_private_file_with_status(path).map(|(file, _)| file)
}

pub(crate) fn open_or_create_current_user_private_file_with_status(
    path: &Path,
) -> Result<(File, bool)> {
    const ATTEMPTS: usize = 200;
    for attempt in 0..ATTEMPTS {
        match create_current_user_private_file_with_disposition(
            path,
            CREATE_NEW,
            FILE_SHARE_READ,
            DELETE,
            false,
        ) {
            Ok(file) => return Ok((file, true)),
            Err(error)
                if matches!(
                    windows_error_code(&error),
                    Some(code)
                        if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
                ) =>
            {
                match create_current_user_private_file_with_disposition(
                    path,
                    OPEN_EXISTING,
                    FILE_SHARE_READ,
                    0,
                    false,
                ) {
                    Ok(file) => return Ok((file, false)),
                    Err(open_error)
                        if windows_error_code(&open_error)
                            == Some(ERROR_SHARING_VIOLATION as i32)
                            && attempt + 1 < ATTEMPTS =>
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(open_error)
                        if matches!(
                            windows_error_code(&open_error),
                            Some(code)
                                if code == ERROR_FILE_NOT_FOUND as i32
                                    || code == ERROR_PATH_NOT_FOUND as i32
                        ) && attempt + 1 < ATTEMPTS => {}
                    Err(open_error) => return Err(open_error),
                }
            }
            Err(error)
                if windows_error_code(&error) == Some(ERROR_SHARING_VIOLATION as i32)
                    && attempt + 1 < ATTEMPTS =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded Windows private-file retry loop always returns")
}

/// Reopen an already-created private sidecar without permitting recreation.
/// This is used to prove that the durable directory entry still names the
/// full FILE_ID_INFO captured before its identity-keyed WAL is acquired.
pub(crate) fn open_current_user_private_file_existing(path: &Path) -> Result<File> {
    const ATTEMPTS: usize = 200;
    for attempt in 0..ATTEMPTS {
        match create_current_user_private_file_with_disposition(
            path,
            OPEN_EXISTING,
            FILE_SHARE_READ,
            0,
            false,
        ) {
            Ok(file) => return Ok(file),
            Err(error)
                if windows_error_code(&error) == Some(ERROR_SHARING_VIOLATION as i32)
                    && attempt + 1 < ATTEMPTS =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded Windows existing-private-file retry loop always returns")
}

/// Open a private sidecar read-only with permissive sharing so an already-held
/// strict ConfigLock handle can be compared against a recorded namespace slot.
pub(crate) fn open_current_user_private_file_existing_shared(path: &Path) -> Result<File> {
    let path_wide = wide_null(path.as_os_str())?;
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = OwnedHandle::new(
        handle,
        &format!(
            "failed to open shared private managed file {}",
            path.display()
        ),
    )?;
    object_identity(handle.raw(), false)?;
    let file = handle.into_file();
    validate_current_user_private_file(&file)?;
    Ok(file)
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
    // FILE_ID_INFO carries the full 128-bit file identity. The legacy
    // BY_HANDLE_FILE_INFORMATION index is only 64 bits and can alias on modern
    // filesystems, so it is never used as durable namespace authority.
    let mut id: FILE_ID_INFO = unsafe { zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut id).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(win32_error(
            "failed to inspect full Windows updater object identity",
        ));
    }
    let identity = PlatformObjectIdentity {
        namespace: id.VolumeSerialNumber,
        file: WindowsFileId::from_bytes(id.FileId.Identifier),
    };
    if identity.namespace == 0 || identity.file.is_zero() {
        anyhow::bail!(
            "Windows updater object returned an invalid zero volume or FILE_ID_128 authority"
        );
    }
    Ok(identity)
}

pub(crate) struct WindowsParentGuard {
    path: PathBuf,
    file: File,
    identity: PlatformObjectIdentity,
}

impl WindowsParentGuard {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let path_wide = wide_null(path.as_os_str())?;
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(
            handle,
            &format!("failed to retain managed config parent {}", path.display()),
        )?;
        let identity = object_identity(handle.raw(), true)?;
        let guard = Self {
            path: path.to_path_buf(),
            file: handle.into_file(),
            identity,
        };
        guard.revalidate_visible()?;
        Ok(guard)
    }

    pub(crate) fn revalidate_visible(&self) -> Result<()> {
        if object_identity(self.file.as_raw_handle().cast(), true)? != self.identity {
            anyhow::bail!("retained managed config parent changed identity");
        }
        let path_wide = wide_null(self.path.as_os_str())?;
        let visible = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let visible = OwnedHandle::new(
            visible,
            &format!(
                "failed to revalidate visible managed config parent {}",
                self.path.display()
            ),
        )?;
        if object_identity(visible.raw(), true)? != self.identity {
            anyhow::bail!(
                "visible managed config parent binding changed: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> (u64, WindowsFileId) {
        (self.identity.namespace, self.identity.file)
    }
}

pub(crate) fn managed_object_identity(
    file: &File,
    expect_directory: bool,
) -> Result<(u64, WindowsFileId)> {
    let identity = object_identity(file.as_raw_handle().cast(), expect_directory)?;
    Ok((identity.namespace, identity.file))
}

/// Resolve an existing final component through its exact no-follow handle.
/// This expands 8.3 aliases and preserves the filesystem's stored long-name
/// spelling before ConfigLock derives the adjacent sidecar namespace.
pub(crate) fn managed_file_stored_final_component(path: &Path) -> Result<Option<OsString>> {
    let path_wide = wide_null(path.as_os_str())?;
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(code)
                if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32 =>
            {
                Ok(None)
            }
            _ => Err(error).with_context(|| {
                format!(
                    "failed to open managed config target for long-name resolution {}",
                    path.display()
                )
            }),
        };
    }
    let handle = OwnedHandle::new(
        raw,
        &format!(
            "failed to retain managed config target for long-name resolution {}",
            path.display()
        ),
    )?;
    object_identity(handle.raw(), false)?;
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let mut capacity = 256_usize;
    loop {
        let mut buffer = vec![0_u16; capacity];
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle.raw(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).context("Windows final path buffer is too large")?,
                flags,
            )
        };
        if written == 0 {
            return Err(win32_error(
                "failed to resolve managed config long final path",
            ));
        }
        let written = usize::try_from(written).context("Windows final path length overflow")?;
        if written >= buffer.len() {
            capacity = written
                .checked_add(1)
                .context("Windows final path length overflow")?;
            continue;
        }
        buffer.truncate(written);
        let resolved = PathBuf::from(OsString::from_wide(&buffer));
        let component = resolved.file_name().with_context(|| {
            format!(
                "resolved managed config target has no final component: {}",
                resolved.display()
            )
        })?;
        return Ok(Some(component.to_os_string()));
    }
}

/// Reopen a renamed object through its visible path without requesting write
/// or delete authority, then prove it still names the retained strict handle.
pub(crate) fn revalidate_managed_file_path(
    path: &Path,
    authority: &File,
    private: bool,
    require_full_sacl: bool,
) -> Result<()> {
    let expected = object_identity(authority.as_raw_handle().cast(), false)?;
    let expected_security = managed_file_metadata_fingerprint(authority)?;
    let expected_full_sacl = require_full_sacl
        .then(|| managed_file_full_sacl_fingerprint(authority))
        .transpose()?;
    let path_wide = wide_null(path.as_os_str())?;
    let desired_access = GENERIC_READ
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | if require_full_sacl {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        };
    let open = || unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let context = format!(
        "failed to revalidate managed config path {}",
        path.display()
    );
    let visible = if require_full_sacl {
        open_with_se_security_privilege(&context, false, open)?
    } else {
        OwnedHandle::new(open(), &context)?
    };
    if object_identity(visible.raw(), false)? != expected {
        anyhow::bail!("managed config path no longer names its retained exact handle");
    }
    let visible_file = visible.into_file();
    if private {
        validate_current_user_private_file(&visible_file)?;
    }
    if managed_file_metadata_fingerprint(&visible_file)? != expected_security {
        anyhow::bail!("managed config metadata changed during path revalidation");
    }
    if let Some(expected_full_sacl) = expected_full_sacl {
        if managed_file_full_sacl_fingerprint(&visible_file)? != expected_full_sacl {
            anyhow::bail!(
                "visible managed config full SACL differs from retained exact-handle authority"
            );
        }
    }
    Ok(())
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

pub(crate) fn ensure_private_temp_container(parent: &Path, name: &str) -> Result<PathBuf> {
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

    #[cfg(test)]
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
    use windows_sys::Win32::Security::AddMandatoryAce;

    fn test_acl(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
        let mut acl = vec![0_u8; size];
        acl[0] = revision;
        acl[2..4].copy_from_slice(&u16::try_from(size).unwrap().to_le_bytes());
        acl[4..6].copy_from_slice(&u16::try_from(aces.len()).unwrap().to_le_bytes());
        let mut offset = 8;
        for ace in aces {
            acl[offset..offset + ace.len()].copy_from_slice(ace);
            offset += ace.len();
        }
        acl
    }

    fn test_mandatory_label_ace(flags: u8) -> Vec<u8> {
        let mut ace = vec![0_u8; 20];
        ace[0] = SYSTEM_MANDATORY_LABEL_ACE_TYPE as u8;
        ace[1] = flags;
        ace[2..4].copy_from_slice(&(20_u16).to_le_bytes());
        ace[4..8].copy_from_slice(&SYSTEM_MANDATORY_LABEL_NO_WRITE_UP.to_le_bytes());
        ace[8] = 1;
        ace[9] = 1;
        ace[10..16].copy_from_slice(&[0, 0, 0, 0, 0, 16]);
        ace[16..20].copy_from_slice(&4096_u32.to_le_bytes());
        ace
    }

    fn test_unsupported_ace(ace_type: u8) -> Vec<u8> {
        let mut ace = vec![0_u8; 8];
        ace[0] = ace_type;
        ace[2..4].copy_from_slice(&(8_u16).to_le_bytes());
        ace
    }

    #[test]
    fn windows_staged_delete_on_close_arm_and_disarm_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let armed_path = dir.path().join("armed-stage.json");
        let armed = create_managed_config_staged_file(&armed_path, false).unwrap();
        assert!(armed.metadata().unwrap().is_file());
        drop(armed);
        assert!(
            !armed_path.exists(),
            "an armed pre-Prepared stage must disappear when its exact handle closes"
        );

        let durable_path = dir.path().join("durable-stage.json");
        let durable = create_managed_config_staged_file(&durable_path, false).unwrap();
        let durable =
            disarm_staged_file_delete_on_close(durable, &durable_path, false, false).unwrap();
        drop(durable);
        assert!(
            durable_path.is_file(),
            "a stage disarmed after durable Prepared WAL must survive handle close"
        );
        std::fs::remove_file(durable_path).unwrap();

        let failed_disarm_path = dir.path().join("failed-disarm-stage.json");
        let failed_disarm = create_managed_config_staged_file(&failed_disarm_path, false).unwrap();
        inject_staged_file_disarm_failure(true);
        let error =
            disarm_staged_file_delete_on_close(failed_disarm, &failed_disarm_path, false, false)
                .expect_err("injected disarm failure must retain delete-on-close");
        assert!(format!("{error:#}").contains("injected staged-file"));
        assert!(
            !failed_disarm_path.exists(),
            "a failed disarm must not leave an unjournaled named stage"
        );
    }

    fn process_privileges_snapshot() -> Vec<u8> {
        use windows_sys::Win32::Security::TokenPrivileges;

        let mut token = null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let token = OwnedHandle::new(token, "test process token").unwrap();
        let mut required = 0_u32;
        let _ = unsafe {
            GetTokenInformation(token.raw(), TokenPrivileges, null_mut(), 0, &mut required)
        };
        assert!(required > 0);
        let mut storage = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.raw(),
                    TokenPrivileges,
                    storage.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            },
            0
        );
        unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), required as usize).to_vec()
        }
    }

    fn current_thread_token_id() -> Option<(u32, i32)> {
        use windows_sys::Win32::Security::{TokenStatistics, TOKEN_STATISTICS};

        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
            return None;
        }
        let token = OwnedHandle::new(token, "test thread token").unwrap();
        let mut statistics = TOKEN_STATISTICS::default();
        let mut required = 0_u32;
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.raw(),
                    TokenStatistics,
                    (&mut statistics as *mut TOKEN_STATISTICS).cast(),
                    size_of::<TOKEN_STATISTICS>() as u32,
                    &mut required,
                )
            },
            0
        );
        Some((statistics.TokenId.LowPart, statistics.TokenId.HighPart))
    }

    #[test]
    fn full_sacl_parser_accepts_only_empty_or_one_valid_mandatory_label() {
        validate_supported_full_sacl_bytes(&[]).unwrap();
        validate_supported_full_sacl_bytes(&test_acl(ACL_REVISION as u8, &[])).unwrap();
        let inheritance_flags = (OBJECT_INHERIT_ACE
            | CONTAINER_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | INHERIT_ONLY_ACE
            | INHERITED_ACE) as u8;
        for revision in [ACL_REVISION as u8, ACL_REVISION_DS as u8] {
            assert_eq!(
                validate_supported_full_sacl_bytes(&test_acl(
                    revision,
                    &[test_mandatory_label_ace(inheritance_flags)],
                ))
                .unwrap(),
                1
            );
        }
    }

    #[test]
    fn full_sacl_parser_rejects_unsupported_duplicate_and_malformed_aces() {
        for ace_type in [
            SYSTEM_AUDIT_ACE_TYPE as u8,
            SYSTEM_ALARM_ACE_TYPE as u8,
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE as u8,
            SYSTEM_SCOPED_POLICY_ID_ACE_TYPE as u8,
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE as u8,
            SYSTEM_ACCESS_FILTER_ACE_TYPE as u8,
            0xfe,
        ] {
            let error = validate_supported_full_sacl_bytes(&test_acl(
                ACL_REVISION_DS as u8,
                &[test_unsupported_ace(ace_type)],
            ))
            .unwrap_err();
            assert!(format!("{error:#}").contains("unsupported"));
        }

        let label = test_mandatory_label_ace(0);
        assert!(validate_supported_full_sacl_bytes(&test_acl(
            ACL_REVISION as u8,
            &[label.clone(), label],
        ))
        .is_err());

        let mut escaping = test_mandatory_label_ace(0);
        escaping[2..4].copy_from_slice(&(24_u16).to_le_bytes());
        assert!(
            validate_supported_full_sacl_bytes(&test_acl(ACL_REVISION as u8, &[escaping],))
                .is_err()
        );

        let mut unsupported_flags = test_mandatory_label_ace(0x40);
        unsupported_flags[1] = 0x40;
        assert!(validate_supported_full_sacl_bytes(&test_acl(
            ACL_REVISION as u8,
            &[unsupported_flags],
        ))
        .is_err());
    }

    #[test]
    fn mandatory_label_round_trips_through_managed_metadata_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.json");
        let destination_path = dir.path().join("destination.json");
        let source = create_managed_config_staged_file(&source_path, true).unwrap();
        let destination = create_managed_config_staged_file(&destination_path, true).unwrap();

        let mut label_storage = vec![0_usize; 4];
        let label_bytes = label_storage.len() * size_of::<usize>();
        let label = label_storage.as_mut_ptr().cast::<ACL>();
        assert_ne!(
            unsafe { InitializeAcl(label, label_bytes as u32, ACL_REVISION) },
            0
        );
        let mut sid_storage = [0_usize; 2];
        let sid = unsafe {
            std::slice::from_raw_parts_mut(
                sid_storage.as_mut_ptr().cast::<u8>(),
                sid_storage.len() * size_of::<usize>(),
            )
        };
        sid[..12].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0]);
        assert_ne!(
            unsafe {
                AddMandatoryAce(
                    label,
                    ACL_REVISION,
                    0,
                    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid.as_mut_ptr().cast(),
                )
            },
            0
        );
        let result = unsafe {
            SetSecurityInfo(
                source.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                label,
            )
        };
        assert_eq!(result, 0);

        let expected = managed_file_full_sacl_fingerprint(&source).unwrap();
        copy_managed_file_metadata(&source, &destination).unwrap();
        assert_eq!(
            managed_file_full_sacl_fingerprint(&destination).unwrap(),
            expected
        );
    }

    #[test]
    fn se_security_privilege_is_thread_scoped_and_restores_prior_token() {
        let process_before = process_privileges_snapshot();
        let thread_before = current_thread_token_id();
        let mut privilege = match ThreadSeSecurityPrivilege::enable() {
            Ok(privilege) => privilege,
            Err(error) if format!("{error:#}").contains("not assigned") => {
                assert_eq!(process_privileges_snapshot(), process_before);
                assert_eq!(current_thread_token_id(), thread_before);
                return;
            }
            Err(error) => panic!("unexpected thread-scoped privilege failure: {error:#}"),
        };
        assert_ne!(current_thread_token_id(), thread_before);
        assert_eq!(process_privileges_snapshot(), process_before);
        let concurrent = std::thread::spawn(process_privileges_snapshot)
            .join()
            .unwrap();
        assert_eq!(concurrent, process_before);
        privilege.restore().unwrap();
        assert_eq!(current_thread_token_id(), thread_before);
        assert_eq!(process_privileges_snapshot(), process_before);
    }

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

    fn stream_info_buffer(names: &[&str]) -> Vec<u8> {
        let header_len = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
        let next_offset = std::mem::offset_of!(FILE_STREAM_INFO, NextEntryOffset);
        let name_length_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamNameLength);
        let alignment = size_of::<usize>();
        let mut buffer = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let name = name.encode_utf16().collect::<Vec<_>>();
            let name_bytes = name.len() * size_of::<u16>();
            let record_len = header_len + name_bytes;
            let padded_len = record_len.div_ceil(alignment) * alignment;
            let next = if index + 1 == names.len() {
                0
            } else {
                u32::try_from(padded_len).unwrap()
            };
            let start = buffer.len();
            buffer.resize(start + padded_len, 0);
            buffer[start + next_offset..start + next_offset + size_of::<u32>()]
                .copy_from_slice(&next.to_ne_bytes());
            buffer[start + name_length_offset..start + name_length_offset + size_of::<u32>()]
                .copy_from_slice(&u32::try_from(name_bytes).unwrap().to_ne_bytes());
            for (unit_index, unit) in name.into_iter().enumerate() {
                let offset = start + header_len + unit_index * size_of::<u16>();
                buffer[offset..offset + size_of::<u16>()].copy_from_slice(&unit.to_ne_bytes());
            }
        }
        buffer
    }

    #[test]
    fn stream_inventory_parser_is_bounded_and_preserves_exact_names() {
        let default = stream_info_buffer(&["::$DATA"]);
        assert_eq!(
            parse_managed_config_stream_buffer(&default).unwrap(),
            ["::$DATA"]
        );

        let alternate = stream_info_buffer(&["::$DATA", ":zone.identifier:$DATA"]);
        assert_eq!(
            parse_managed_config_stream_buffer(&alternate).unwrap(),
            ["::$DATA", ":zone.identifier:$DATA"]
        );

        let mut malformed = default;
        malformed[..size_of::<u32>()].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_managed_config_stream_buffer(&malformed).is_err());
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
