// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared subprocess isolation for daemon integration tests.

use std::ops::{Deref, DerefMut};
use std::process::{ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;
use tokio::process::{Child, Command};

const DAEMON_REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a containment spawn waits for its guardian to publish readiness.
///
/// This is the tightest budget on the cold-start path of every containment
/// spawn in this suite, and it runs before any test's own readiness clock
/// starts, so it expires as a spawn failure rather than as the readiness
/// message a reader would expect. Reaching it costs two re-execs of the test
/// binary, and nothing asserts how long that may take, so the number is a hang
/// guard only.
#[cfg(unix)]
const GUARDIAN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(20);
const DAEMON_TEST_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
/// Maximum rendered UTF-8 bytes, including any truncation marker.
const DAEMON_TEST_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const DAEMON_TEST_DIAGNOSTIC_MARKER: &str = "\n[bounded capture truncated]";
#[cfg(unix)]
const DAEMON_TEST_RUNTIME_OWNER_ENV: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";
#[cfg(unix)]
const DAEMON_TEST_RUNTIME_PROCESS_GROUP_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP";

/// Remove all inherited Kin authority and loader injection before a scratch
/// daemon applies its intentional test environment.
///
/// Production daemon launches retain their supported environment. This helper
/// is compiled only into integration-test binaries.
pub fn isolate_daemon_test_command(command: &mut Command) {
    scrub_daemon_test_authority(command, is_daemon_test_authority);
    command.env("KIN_VFS_DISABLE", "1");
}

fn scrub_daemon_test_authority(command: &mut Command, predicate: fn(&std::ffi::OsStr) -> bool) {
    let explicit_authority = command
        .as_std_mut()
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| predicate(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| predicate(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
}

fn is_daemon_test_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
        || is_external_daemon_test_authority(key)
}

fn is_external_daemon_test_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
}

/// Re-scrub external process authority at the final spawn boundary.
///
/// Callers first use `isolate_daemon_test_command`, which removes inherited
/// Kin and external authority, then add the Kin settings their fixture
/// intentionally exercises. Re-removing all `KIN_*` here would erase that
/// explicit test configuration. Git and loader authority have no supported
/// post-isolation override, so they are removed again after all caller
/// mutation and immediately before spawn.
fn prepare_daemon_test_command_for_spawn(command: &mut Command) {
    scrub_daemon_test_authority(command, is_external_daemon_test_authority);
    prepare_contained_test_command(command);
}

fn prepare_contained_test_command(command: &mut Command) {
    command.kill_on_drop(true).stdin(Stdio::null());
}

#[cfg(windows)]
fn env_name_eq(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

#[cfg(not(windows))]
fn env_name_eq(actual: &str, expected: &str) -> bool {
    actual == expected
}

#[cfg(windows)]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

#[cfg(windows)]
#[test]
fn daemon_isolation_treats_windows_environment_names_case_insensitively() {
    for hostile in [
        "kin_registry_path",
        "_kin_vfs_last_dir",
        "git_config_count",
        "Dyld_Library_Path",
        "Ld_Custom_Injection",
    ] {
        assert!(
            is_daemon_test_authority(std::ffi::OsStr::new(hostile)),
            "{hostile} bypassed Windows environment-name isolation"
        );
    }
}

const DAEMON_AUTHORITY_SCRUB_WORKER: &str = "KIN_TEST_DAEMON_AUTHORITY_SCRUB_WORKER";

#[tokio::test(flavor = "current_thread")]
async fn daemon_isolation_scrubs_ambient_and_command_local_git_and_loader_authority() {
    const HOSTILE_KEYS: &[&str] = &[
        "GIT_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_DEFAULT_HASH",
        "GIT_DEFAULT_REF_FORMAT",
        "LD_CUSTOM_INJECTION",
    ];
    if let Some(marker) = std::env::var_os(DAEMON_AUTHORITY_SCRUB_WORKER) {
        for phase in ["ambient", "command-local-before", "command-local-after"] {
            let mut command =
                Command::new(std::env::current_exe().expect("current test executable"));
            if phase == "command-local-before" {
                for key in HOSTILE_KEYS {
                    command.env(key, "command-local-hostile");
                }
            }
            isolate_daemon_test_command(&mut command);
            if phase == "command-local-after" {
                for key in HOSTILE_KEYS {
                    command.env(key, "post-isolation-hostile");
                }
                command.env("KIN_DAEMON_DISABLE_LSP", "1");
                prepare_daemon_test_command_for_spawn(&mut command);
                let intentional_kin = command
                    .as_std()
                    .get_envs()
                    .find(|(configured, _)| {
                        env_name_eq(&configured.to_string_lossy(), "KIN_DAEMON_DISABLE_LSP")
                    })
                    .and_then(|(_, value)| value)
                    .map(std::ffi::OsStr::to_os_string);
                assert_eq!(
                    intentional_kin,
                    Some("1".into()),
                    "final external-authority scrub erased intentional Kin config"
                );
            }
            for key in HOSTILE_KEYS {
                let configured = command
                    .as_std()
                    .get_envs()
                    .find(|(configured, _)| env_name_eq(&configured.to_string_lossy(), key))
                    .map(|(_, value)| value.map(std::ffi::OsStr::to_os_string));
                assert_eq!(
                    configured,
                    Some(None),
                    "{key} survived {phase} daemon test isolation"
                );
            }
        }
        std::fs::write(marker, b"scrubbed").expect("write daemon authority scrub marker");
        return;
    }

    let root = tempfile::TempDir::new().expect("tempdir");
    let marker = root.path().join("authority-scrub.marker");
    let mut worker = Command::new(std::env::current_exe().expect("current test executable"));
    worker
        .args([
            "--exact",
            "common::daemon_isolation_scrubs_ambient_and_command_local_git_and_loader_authority",
            "--nocapture",
        ])
        .env(DAEMON_AUTHORITY_SCRUB_WORKER, &marker)
        .stdin(Stdio::null());
    for key in HOSTILE_KEYS {
        worker.env(key, "ambient-hostile");
    }
    let output = adversarial_authority_worker_output(
        worker,
        "daemon authority scrub worker",
        Duration::from_secs(10),
    )
    .await
    .expect("run daemon authority scrub worker");
    assert!(
        output.status.success(),
        "daemon authority scrub worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&marker).expect("read daemon authority scrub marker"),
        b"scrubbed"
    );
}

#[cfg(unix)]
struct DaemonContainment {
    guardian: std::sync::Mutex<Option<kin_daemon_spawn::ProcessGroupGuardian>>,
    signaled: bool,
    runtime_owner: String,
    _guardian_root: tempfile::TempDir,
}

/// Exact test-harness entrypoint for the shared process-group guardian.
#[cfg(unix)]
#[test]
fn daemon_containment_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run daemon-test process-group guardian worker");
    assert_eq!(dispatched, requested);
}

#[cfg(unix)]
fn scrub_daemon_test_guardian_environment(
    environment: &mut kin_daemon_spawn::ProcessGroupGuardianEnvironment,
) {
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_daemon_test_authority(key))
    {
        environment.env_remove(key);
    }
    environment.env("KIN_VFS_DISABLE", "1");
}

#[cfg(unix)]
impl DaemonContainment {
    fn start_guardian(label: &str) -> std::io::Result<Self> {
        let guardian_root = tempfile::Builder::new()
            .prefix("kin-daemon-containment-guardian-")
            .tempdir()?;
        let ready = guardian_root.path().join("ready");
        let runtime_owner = uuid::Uuid::new_v4().to_string();
        let launcher = kin_daemon_spawn::ProcessGroupGuardianLauncher::exact_test(
            std::env::current_exe()?,
            "common::daemon_containment_guardian_worker",
        )
        .with_env(DAEMON_TEST_RUNTIME_OWNER_ENV, &runtime_owner);
        let guardian = launcher
            .spawn_with(
                &ready,
                Instant::now() + GUARDIAN_HANDSHAKE_TIMEOUT,
                scrub_daemon_test_guardian_environment,
            )
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("spawn {label} containment guardian: {error}"),
                )
            })?;
        Ok(Self {
            guardian: std::sync::Mutex::new(Some(guardian)),
            signaled: false,
            runtime_owner,
            _guardian_root: guardian_root,
        })
    }

    fn spawn(mut command: Command, label: &str) -> std::io::Result<(Child, Self)> {
        let mut containment = Self::start_guardian(label)?;
        let spawn = {
            let mut guardian = containment
                .guardian
                .lock()
                .map_err(|_| std::io::Error::other("daemon containment guardian lock poisoned"))?;
            let guardian = guardian.as_mut().ok_or_else(|| {
                std::io::Error::other("daemon containment guardian exited before child spawn")
            })?;
            let process_group = guardian.process_group();
            command
                .env(DAEMON_TEST_RUNTIME_OWNER_ENV, &containment.runtime_owner)
                .env(
                    DAEMON_TEST_RUNTIME_PROCESS_GROUP_ENV,
                    process_group.to_string(),
                );
            guardian.spawn_tokio(command)
        };
        match spawn {
            Ok(child) => Ok((child, containment)),
            Err(error) => {
                let cleanup = containment.terminate();
                let quiescence =
                    confirm_containment_empty_blocking(&containment, "unlaunched daemon fixture");
                let reap = if quiescence.is_ok() {
                    containment.reap_guardian()
                } else {
                    Err(std::io::Error::other(
                        "daemon containment guardian retained because quiescence was not proven",
                    ))
                };
                Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "spawn {label}: {error}; guardian cleanup={cleanup:?}; \
                         quiescence={quiescence:?}; reap={reap:?}"
                    ),
                ))
            }
        }
    }

    /// Seal guardian admission and transfer repeated cleanup to the watcher.
    fn terminate(&mut self) -> std::io::Result<()> {
        if std::mem::replace(&mut self.signaled, true) {
            return Ok(());
        }
        let guardian = self
            .guardian
            .get_mut()
            .map_err(|_| std::io::Error::other("daemon containment guardian lock poisoned"))?;
        let guardian = guardian.as_mut().ok_or_else(|| {
            std::io::Error::other("daemon containment lost its guardian before termination")
        })?;
        guardian.request_cleanup();
        Ok(())
    }

    fn reap_guardian(&mut self) -> std::io::Result<()> {
        let guardian = self
            .guardian
            .get_mut()
            .map_err(|_| std::io::Error::other("daemon containment guardian lock poisoned"))?;
        let Some(guardian_handle) = guardian.as_mut() else {
            return Ok(());
        };
        guardian_handle.reap_until(Instant::now() + DAEMON_REAP_TIMEOUT)?;
        guardian.take();
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        let mut guardian = self
            .guardian
            .lock()
            .map_err(|_| std::io::Error::other("daemon containment guardian lock poisoned"))?;
        let Some(guardian_handle) = guardian.as_mut() else {
            return Ok(true);
        };
        if guardian_handle.try_reap()?.is_some() {
            guardian.take();
            return Ok(true);
        }
        Ok(false)
    }

    fn take_guardian(&mut self) -> Option<kin_daemon_spawn::ProcessGroupGuardian> {
        match self.guardian.get_mut() {
            Ok(guardian) => guardian.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

#[cfg(unix)]
impl Drop for DaemonContainment {
    fn drop(&mut self) {
        // DaemonChild owns the ordered path: terminate containment, reap the
        // direct child, then prove the group empty and reap the guardian.
        // This catastrophic fallback intentionally leaks the exact guardian
        // handle rather than let its Drop finalize before the direct status.
        let _ = self.terminate();
        if let Some(mut guardian) = self.take_guardian() {
            guardian.request_cleanup();
            std::mem::forget(guardian);
        }
    }
}

#[cfg(windows)]
struct DaemonContainment {
    job: windows_sys::Win32::Foundation::HANDLE,
    signaled: bool,
}

#[cfg(windows)]
struct WindowsOwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsOwnedHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
impl DaemonContainment {
    fn spawn(mut command: Command, label: &str) -> std::io::Result<(Child, Self)> {
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::Foundation::{
            GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        use windows_sys::Win32::System::Threading::{
            GetProcessIdOfThread, OpenThread, ResumeThread, CREATE_SUSPENDED,
            THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut containment = Self {
            job,
            signaled: false,
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                containment.job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        command.as_std_mut().creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn().map_err(|error| {
            std::io::Error::new(error.kind(), format!("spawn {label}: {error}"))
        })?;
        let child_id = child.id().ok_or_else(|| {
            let _ = child.start_kill();
            std::io::Error::other(format!("{label} exited before Job Object assignment"))
        })?;
        let child_handle = child.raw_handle().ok_or_else(|| {
            let _ = child.start_kill();
            std::io::Error::other(format!("{label} has no process handle"))
        })?;
        if unsafe { AssignProcessToJobObject(containment.job, child_handle.cast()) } == 0 {
            let error = std::io::Error::last_os_error();
            let _ = child.start_kill();
            return Err(std::io::Error::new(
                error.kind(),
                format!("assign {label} to test Job Object: {error}"),
            ));
        }

        let thread_id = (|| -> std::io::Result<u32> {
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let snapshot = WindowsOwnedHandle(snapshot);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                return if error == ERROR_NO_MORE_FILES {
                    Err(std::io::Error::other(
                        "suspended daemon test process has no primary thread",
                    ))
                } else {
                    Err(std::io::Error::from_raw_os_error(error as i32))
                };
            }
            let expected_size = std::mem::size_of::<THREADENTRY32>() as u32;
            let minimum_size = (std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID)
                + std::mem::size_of::<u32>()) as u32;
            let mut matches = Vec::new();
            loop {
                if entry.dwSize < minimum_size {
                    return Err(std::io::Error::other(format!(
                        "suspended daemon thread entry is too small: {} < {minimum_size}",
                        entry.dwSize
                    )));
                }
                if entry.th32OwnerProcessID == child_id {
                    matches.push(entry.th32ThreadID);
                }
                entry.dwSize = expected_size;
                if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
                    let error = unsafe { GetLastError() };
                    if error == ERROR_NO_MORE_FILES {
                        break;
                    }
                    return Err(std::io::Error::from_raw_os_error(error as i32));
                }
            }
            if matches.len() != 1 {
                return Err(std::io::Error::other(format!(
                    "suspended daemon test process must have one primary thread, found {}",
                    matches.len()
                )));
            }
            Ok(matches[0])
        })();
        let thread_id = match thread_id {
            Ok(thread_id) => thread_id,
            Err(error) => {
                let _ = containment.terminate();
                let _ = child.start_kill();
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("enumerate {label} primary thread: {error}"),
                ));
            }
        };
        let thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                thread_id,
            )
        };
        if thread.is_null() {
            let error = std::io::Error::last_os_error();
            let _ = containment.terminate();
            let _ = child.start_kill();
            return Err(std::io::Error::new(
                error.kind(),
                format!("open {label} primary thread: {error}"),
            ));
        }
        let thread = WindowsOwnedHandle(thread);
        if unsafe { GetProcessIdOfThread(thread.0) } != child_id {
            let _ = containment.terminate();
            let _ = child.start_kill();
            return Err(std::io::Error::other(format!(
                "{label} primary-thread owner changed"
            )));
        }
        let previous_suspend_count = unsafe { ResumeThread(thread.0) };
        if previous_suspend_count != 1 {
            let error = std::io::Error::last_os_error();
            let _ = containment.terminate();
            let _ = child.start_kill();
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "resume {label} primary thread returned {previous_suspend_count}, expected 1: {error}"
                ),
            ));
        }
        Ok((child, containment))
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if std::mem::replace(&mut self.signaled, true) {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn reap_guardian(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(accounting.ActiveProcesses == 0)
        }
    }
}

#[cfg(windows)]
impl Drop for DaemonContainment {
    fn drop(&mut self) {
        let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(self.job) };
    }
}

#[cfg(not(any(unix, windows)))]
struct DaemonContainment {
    signaled: bool,
}

#[cfg(not(any(unix, windows)))]
impl DaemonContainment {
    fn spawn(mut command: Command, label: &str) -> std::io::Result<(Child, Self)> {
        let child = command.spawn().map_err(|error| {
            std::io::Error::new(error.kind(), format!("spawn {label}: {error}"))
        })?;
        Ok((child, Self { signaled: false }))
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        self.signaled = true;
        Ok(())
    }

    fn reap_guardian(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        Ok(true)
    }
}

/// A directly spawned daemon plus OS containment that owns every descendant.
///
/// Unix uses a stable guardian-led process group with a parent-death watchdog.
/// Windows assigns the suspended child to a kill-on-close Job Object before it
/// can execute. Drop terminates the whole tree; explicit shutdown additionally
/// reaps the direct child and proves the containment empty.
pub struct DaemonChild {
    child: Option<Child>,
    containment: DaemonContainment,
    label: String,
}

#[cfg(unix)]
struct RetainedDaemonCleanup {
    guardian: kin_daemon_spawn::ProcessGroupGuardian,
    child: Child,
}

#[cfg(unix)]
impl RetainedDaemonCleanup {
    fn run(mut self) {
        self.guardian.request_cleanup();
        let _ = self.child.start_kill();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) | Err(_) => std::thread::sleep(DAEMON_POLL_INTERVAL),
            }
        }
        // The direct daemon status is now reaped. Guardian finalization is
        // permitted only after this point.
        let _ = self
            .guardian
            .reap_until(Instant::now() + DAEMON_REAP_TIMEOUT);
    }
}

#[cfg(unix)]
fn retain_failed_daemon_child(child: &mut DaemonChild, label: &str) -> Result<(), String> {
    let Some(direct_child) = child.child.take() else {
        if let Some(mut guardian) = child.containment.take_guardian() {
            guardian.request_cleanup();
            std::mem::forget(guardian);
        }
        return Err(format!(
            "{label} lost its direct child; guardian intentionally retained"
        ));
    };
    let Some(guardian) = child.containment.take_guardian() else {
        std::mem::forget(direct_child);
        return Err(format!(
            "{label} lost its guardian; exact direct-child handle intentionally leaked"
        ));
    };
    let retained = std::mem::ManuallyDrop::new(RetainedDaemonCleanup {
        guardian,
        child: direct_child,
    });
    std::thread::Builder::new()
        .name("kin-test-retained-daemon".to_string())
        .spawn(move || {
            let retained = std::mem::ManuallyDrop::into_inner(retained);
            retained.run();
        })
        .map(|_| ())
        .map_err(|error| {
            format!(
                "spawn retained daemon cleanup owner for {label}: {error}; exact guardian and \
                 direct-child handles intentionally leaked"
            )
        })
}

#[cfg(not(unix))]
fn retain_failed_daemon_child(child: &mut DaemonChild, label: &str) -> Result<(), String> {
    if let Some(direct_child) = child.child.take() {
        std::mem::forget(direct_child);
    }
    Err(format!(
        "{label} direct-child handle intentionally retained after failed reap"
    ))
}

impl Deref for DaemonChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.child.as_ref().expect("daemon child handle retained")
    }
}

impl DerefMut for DaemonChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child.as_mut().expect("daemon child handle retained")
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let label = self.label.clone();
        if let Err(mut error) = terminate_daemon_blocking(self, &label) {
            let retention = retain_failed_daemon_child(self, &label);
            error.push_str(&format!("; failed-reap retention={retention:?}"));
            if std::thread::panicking() {
                eprintln!("{error}");
            } else {
                panic!("{error}");
            }
        }
    }
}

/// Spawn a direct daemon fixture with closed stdin and stable tree ownership.
pub fn spawn_daemon_test_command(
    mut command: Command,
    label: &str,
) -> std::io::Result<DaemonChild> {
    prepare_daemon_test_command_for_spawn(&mut command);
    spawn_contained_test_command(command, label)
}

fn spawn_contained_test_command(command: Command, label: &str) -> std::io::Result<DaemonChild> {
    let (child, containment) = DaemonContainment::spawn(command, label)?;
    Ok(DaemonChild {
        child: Some(child),
        containment,
        label: label.to_string(),
    })
}

fn confirm_containment_empty_blocking(
    containment: &DaemonContainment,
    label: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + DAEMON_REAP_TIMEOUT;
    loop {
        match containment.is_empty() {
            Ok(true) => return Ok(()),
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(DAEMON_POLL_INTERVAL);
            }
            Ok(false) => {
                return Err(format!(
                    "{label} descendants survived for {DAEMON_REAP_TIMEOUT:?}"
                ));
            }
            Err(error) => return Err(format!("inspect {label} containment: {error}")),
        }
    }
}

async fn confirm_containment_empty(
    containment: &DaemonContainment,
    label: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + DAEMON_REAP_TIMEOUT;
    loop {
        match containment.is_empty() {
            Ok(true) => return Ok(()),
            Ok(false) if Instant::now() < deadline => {
                tokio::time::sleep(DAEMON_POLL_INTERVAL).await;
            }
            Ok(false) => {
                return Err(format!(
                    "{label} descendants survived for {DAEMON_REAP_TIMEOUT:?}"
                ));
            }
            Err(error) => return Err(format!("inspect {label} containment: {error}")),
        }
    }
}

fn terminate_daemon_blocking(child: &mut DaemonChild, label: &str) -> Result<ExitStatus, String> {
    let initial_probe = child
        .child
        .as_mut()
        .expect("daemon child handle retained")
        .try_wait();
    let probe_error = initial_probe.as_ref().err().map(ToString::to_string);
    let initial_status = initial_probe.ok().flatten();
    let containment_error = child.containment.terminate().err();
    let direct_kill_error = if initial_status.is_none() {
        child
            .child
            .as_mut()
            .expect("daemon child handle retained")
            .start_kill()
            .err()
    } else {
        None
    };
    let status = match initial_status {
        Some(status) => Ok(status),
        None => {
            let deadline = Instant::now() + DAEMON_REAP_TIMEOUT;
            loop {
                match child
                    .child
                    .as_mut()
                    .expect("daemon child handle retained")
                    .try_wait()
                {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(DAEMON_POLL_INTERVAL);
                    }
                    Ok(None) => {
                        break Err(format!(
                            "{label} was not reaped within {DAEMON_REAP_TIMEOUT:?}"
                        ));
                    }
                    Err(error) => break Err(format!("reap {label}: {error}")),
                }
            }
        }
    };
    let (quiescence, guardian_reap) = if status.is_ok() {
        let quiescence = confirm_containment_empty_blocking(&child.containment, label);
        let guardian_reap = if quiescence.is_ok() {
            child.containment.reap_guardian()
        } else {
            Err(std::io::Error::other(
                "daemon containment guardian retained because quiescence was not proven",
            ))
        };
        (quiescence, guardian_reap)
    } else {
        (
            Err(format!(
                "{label} containment proof skipped because the direct child was not reaped"
            )),
            Err(std::io::Error::other(
                "daemon containment guardian retained because the direct child was not reaped",
            )),
        )
    };
    match (
        probe_error,
        containment_error,
        status,
        quiescence,
        guardian_reap,
    ) {
        (None, None, Ok(status), Ok(()), Ok(())) => Ok(status),
        (probe_error, containment_error, status, quiescence, guardian_reap) => Err(format!(
            "{label} cleanup failed: initial probe={probe_error:?}; \
             containment termination={containment_error:?}; \
             direct kill={direct_kill_error:?}; direct reap={status:?}; \
             containment quiescence={quiescence:?}; guardian reap={guardian_reap:?}"
        )),
    }
}

/// Force a directly spawned test daemon tree down and explicitly reap its
/// direct child within a fixed wall-clock budget.
///
/// The containment signal is authoritative for descendants; the direct kill
/// is a backstop for a malformed containment setup.
pub async fn terminate_daemon(child: &mut DaemonChild, label: &str) -> Result<ExitStatus, String> {
    let initial_probe = child
        .child
        .as_mut()
        .expect("daemon child handle retained")
        .try_wait();
    let probe_error = initial_probe.as_ref().err().map(ToString::to_string);
    let initial_status = initial_probe.ok().flatten();
    let containment_error = child.containment.terminate().err();
    let direct_kill_error = if initial_status.is_none() {
        child
            .child
            .as_mut()
            .expect("daemon child handle retained")
            .start_kill()
            .err()
    } else {
        None
    };
    let status = match initial_status {
        Some(status) => Ok(status),
        None => match tokio::time::timeout(
            DAEMON_REAP_TIMEOUT,
            child
                .child
                .as_mut()
                .expect("daemon child handle retained")
                .wait(),
        )
        .await
        {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(error)) => Err(format!("reap {label}: {error}")),
            Err(_) => Err(format!(
                "{label} was not reaped within {DAEMON_REAP_TIMEOUT:?}"
            )),
        },
    };
    let (quiescence, guardian_reap) = if status.is_ok() {
        let quiescence = confirm_containment_empty(&child.containment, label).await;
        let guardian_reap = if quiescence.is_ok() {
            child.containment.reap_guardian()
        } else {
            Err(std::io::Error::other(
                "daemon containment guardian retained because quiescence was not proven",
            ))
        };
        (quiescence, guardian_reap)
    } else {
        (
            Err(format!(
                "{label} containment proof skipped because the direct child was not reaped"
            )),
            Err(std::io::Error::other(
                "daemon containment guardian retained because the direct child was not reaped",
            )),
        )
    };
    match (
        probe_error,
        containment_error,
        status,
        quiescence,
        guardian_reap,
    ) {
        (None, None, Ok(status), Ok(()), Ok(())) => Ok(status),
        (probe_error, containment_error, status, quiescence, guardian_reap) => Err(format!(
            "{label} cleanup failed: initial probe={probe_error:?}; \
             containment termination={containment_error:?}; \
             direct kill={direct_kill_error:?}; direct reap={status:?}; \
             containment quiescence={quiescence:?}; guardian reap={guardian_reap:?}"
        )),
    }
}

/// Run a short-lived daemon binary mode with bounded output capture and the
/// same authority/containment contract as long-lived daemon fixtures.
#[allow(dead_code)]
pub async fn daemon_test_output(
    command: Command,
    label: &str,
    timeout: Duration,
) -> Result<Output, String> {
    contained_test_output(command, label, timeout, true).await
}

/// Deliberately bypass only the final external-authority scrub so the
/// adversarial scrub test can inject ambient Git/loader variables into its
/// worker. Lifecycle bounds and OS descendant containment remain identical to
/// every other direct daemon test launch.
async fn adversarial_authority_worker_output(
    command: Command,
    label: &str,
    timeout: Duration,
) -> Result<Output, String> {
    contained_test_output(command, label, timeout, false).await
}

#[derive(Debug)]
struct CapturedDaemonTestStream {
    bytes: Vec<u8>,
    observed_bytes: u64,
    truncated: bool,
}

struct BoundedDaemonTestCapture {
    stdout: Option<tokio::task::JoinHandle<std::io::Result<CapturedDaemonTestStream>>>,
    stderr: Option<tokio::task::JoinHandle<std::io::Result<CapturedDaemonTestStream>>>,
    overflowed: Arc<AtomicBool>,
}

impl BoundedDaemonTestCapture {
    fn configure(command: &mut Command) {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    fn start(child: &mut Child, label: &str) -> Result<Self, String> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("{label} did not expose captured stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| format!("{label} did not expose captured stderr"))?;
        let overflowed = Arc::new(AtomicBool::new(false));
        let stdout_overflow = overflowed.clone();
        let stderr_overflow = overflowed.clone();
        Ok(Self {
            stdout: Some(tokio::spawn(async move {
                drain_daemon_test_stream(stdout, stdout_overflow).await
            })),
            stderr: Some(tokio::spawn(async move {
                drain_daemon_test_stream(stderr, stderr_overflow).await
            })),
            overflowed,
        })
    }

    fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    async fn finish_until(
        mut self,
        deadline: Instant,
    ) -> Result<(CapturedDaemonTestStream, CapturedDaemonTestStream), String> {
        let stdout = finish_daemon_capture_task(
            self.stdout
                .take()
                .expect("bounded stdout capture task remains owned"),
            "stdout",
            deadline,
        )
        .await?;
        let stderr = finish_daemon_capture_task(
            self.stderr
                .take()
                .expect("bounded stderr capture task remains owned"),
            "stderr",
            deadline,
        )
        .await?;
        Ok((stdout, stderr))
    }
}

impl Drop for BoundedDaemonTestCapture {
    fn drop(&mut self) {
        if let Some(task) = self.stdout.take() {
            task.abort();
        }
        if let Some(task) = self.stderr.take() {
            task.abort();
        }
    }
}

async fn finish_daemon_capture_task(
    mut task: tokio::task::JoinHandle<std::io::Result<CapturedDaemonTestStream>>,
    stream: &str,
    deadline: Instant,
) -> Result<CapturedDaemonTestStream, String> {
    let wait = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(wait, &mut task).await {
        Ok(result) => result
            .map_err(|error| format!("bounded {stream} capture task failed: {error}"))?
            .map_err(|error| format!("bounded {stream} capture failed: {error}")),
        Err(_) => {
            task.abort();
            let _ = tokio::time::timeout(DAEMON_POLL_INTERVAL.saturating_mul(4), &mut task).await;
            Err(format!(
                "bounded {stream} capture was aborted after its EOF deadline"
            ))
        }
    }
}

async fn drain_daemon_test_stream(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    overflowed: Arc<AtomicBool>,
) -> std::io::Result<CapturedDaemonTestStream> {
    let mut bytes = Vec::with_capacity(DAEMON_TEST_CAPTURE_LIMIT.min(64 * 1024));
    let mut observed_bytes = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        observed_bytes = observed_bytes.saturating_add(read as u64);
        let remaining = DAEMON_TEST_CAPTURE_LIMIT.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining {
            overflowed.store(true, Ordering::Release);
        }
    }
    Ok(CapturedDaemonTestStream {
        truncated: observed_bytes > DAEMON_TEST_CAPTURE_LIMIT as u64,
        bytes,
        observed_bytes,
    })
}

#[tokio::test]
async fn bounded_daemon_capture_sink_never_retains_past_the_ceiling() {
    let overflowed = Arc::new(AtomicBool::new(false));
    let input = vec![b'x'; DAEMON_TEST_CAPTURE_LIMIT + 16 * 1024];
    let captured = drain_daemon_test_stream(&input[..], overflowed.clone())
        .await
        .expect("drain bounded daemon capture fixture");

    assert_eq!(captured.bytes.len(), DAEMON_TEST_CAPTURE_LIMIT);
    assert_eq!(
        captured.observed_bytes,
        (DAEMON_TEST_CAPTURE_LIMIT + 16 * 1024) as u64
    );
    assert!(captured.truncated);
    assert!(overflowed.load(Ordering::Acquire));
    assert!(compact_daemon_test_capture(&captured).len() <= DAEMON_TEST_DIAGNOSTIC_LIMIT);
}

#[tokio::test]
async fn compact_daemon_capture_hard_bounds_invalid_utf8_after_lossy_expansion() {
    let captured = CapturedDaemonTestStream {
        bytes: vec![0xff; DAEMON_TEST_DIAGNOSTIC_LIMIT],
        observed_bytes: DAEMON_TEST_DIAGNOSTIC_LIMIT as u64,
        truncated: false,
    };
    let diagnostic = compact_daemon_test_capture(&captured);

    assert!(diagnostic.len() <= DAEMON_TEST_DIAGNOSTIC_LIMIT);
    assert!(diagnostic.ends_with(DAEMON_TEST_DIAGNOSTIC_MARKER));
    assert!(diagnostic.contains('\u{FFFD}'));
}

#[tokio::test]
async fn never_eof_daemon_capture_is_aborted_at_its_deadline() {
    let (_writer, reader) = tokio::io::duplex(64);
    let task = tokio::spawn(drain_daemon_test_stream(
        reader,
        Arc::new(AtomicBool::new(false)),
    ));
    let started = Instant::now();
    let error = finish_daemon_capture_task(
        task,
        "never-eof",
        Instant::now() + Duration::from_millis(50),
    )
    .await
    .expect_err("never-EOF capture must be aborted");

    assert!(error.contains("aborted after its EOF deadline"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "async capture abort exceeded its bounded join window"
    );
}

fn compact_daemon_test_capture(stream: &CapturedDaemonTestStream) -> String {
    let prefix = &stream.bytes[..stream.bytes.len().min(DAEMON_TEST_DIAGNOSTIC_LIMIT)];
    let lossy = String::from_utf8_lossy(prefix);
    let needs_marker = stream.truncated
        || stream.bytes.len() > DAEMON_TEST_DIAGNOSTIC_LIMIT
        || lossy.len() > DAEMON_TEST_DIAGNOSTIC_LIMIT;
    let content_budget = if needs_marker {
        DAEMON_TEST_DIAGNOSTIC_LIMIT.saturating_sub(DAEMON_TEST_DIAGNOSTIC_MARKER.len())
    } else {
        DAEMON_TEST_DIAGNOSTIC_LIMIT
    };
    let mut content_end = lossy.len().min(content_budget);
    while !lossy.is_char_boundary(content_end) {
        content_end -= 1;
    }
    let mut rendered = lossy[..content_end].to_owned();
    if needs_marker {
        rendered.push_str(DAEMON_TEST_DIAGNOSTIC_MARKER);
    }
    debug_assert!(rendered.len() <= DAEMON_TEST_DIAGNOSTIC_LIMIT);
    rendered
}

async fn contained_test_output(
    mut command: Command,
    label: &str,
    timeout: Duration,
    apply_final_authority_scrub: bool,
) -> Result<Output, String> {
    BoundedDaemonTestCapture::configure(&mut command);
    let mut child = if apply_final_authority_scrub {
        spawn_daemon_test_command(command, label)
    } else {
        prepare_contained_test_command(&mut command);
        spawn_contained_test_command(command, label)
    }
    .map_err(|error| format!("{error}"))?;
    let capture = match BoundedDaemonTestCapture::start(
        child.child.as_mut().expect("daemon child handle retained"),
        label,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            let cleanup = terminate_daemon(&mut child, label).await;
            return Err(format!(
                "initialize bounded capture for {label}: {error}; cleanup={cleanup:?}"
            ));
        }
    };
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut capture_overflowed = false;
    loop {
        if capture.overflowed() {
            capture_overflowed = true;
            break;
        }
        match child
            .child
            .as_mut()
            .expect("daemon child handle retained")
            .try_wait()
        {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                tokio::time::sleep(DAEMON_POLL_INTERVAL).await;
            }
            Ok(None) => {
                timed_out = true;
                break;
            }
            Err(error) => {
                let cleanup = terminate_daemon(&mut child, label).await;
                let captured = if cleanup.is_ok() {
                    capture
                        .finish_until(Instant::now() + DAEMON_REAP_TIMEOUT)
                        .await
                        .map(|(stdout, stderr)| {
                            format!(
                                "stdout={} stderr={}",
                                compact_daemon_test_capture(&stdout),
                                compact_daemon_test_capture(&stderr)
                            )
                        })
                        .unwrap_or_else(|capture_error| format!("capture-error={capture_error}"))
                } else {
                    drop(capture);
                    "capture aborted because process-tree quiescence was not proven".to_string()
                };
                return Err(format!(
                    "wait for {label}: {error}; cleanup={cleanup:?}; {captured}"
                ));
            }
        }
    }
    let status = terminate_daemon(&mut child, label).await?;
    let (stdout, stderr) = capture
        .finish_until(Instant::now() + DAEMON_REAP_TIMEOUT)
        .await?;
    if capture_overflowed || stdout.truncated || stderr.truncated {
        return Err(format!(
            "{label} exceeded the {DAEMON_TEST_CAPTURE_LIMIT}-byte per-stream capture limit \
             (stdout={}, stderr={}); stdout={} stderr={}",
            stdout.observed_bytes,
            stderr.observed_bytes,
            compact_daemon_test_capture(&stdout),
            compact_daemon_test_capture(&stderr)
        ));
    }
    if timed_out {
        return Err(format!(
            "{label} did not exit within {timeout:?}; stdout={} stderr={}",
            compact_daemon_test_capture(&stdout),
            compact_daemon_test_capture(&stderr)
        ));
    }
    Ok(Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}
