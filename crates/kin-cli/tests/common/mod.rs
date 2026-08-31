// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared bounded-subprocess support for the CLI integration tests.
//!
//! Every process an integration test drives — `kin`, `kin-daemon`, `cargo`,
//! `rustc` — waits on something the machine may not be able to supply: a daemon
//! that never becomes ready, a cargo build-directory lock another checkout
//! holds, a model that is not downloaded. `Command::output()` waits on all of
//! them without a deadline and with this process's stdin attached, so the
//! default test suite can block forever while printing nothing. Every spawn
//! here closes stdin and carries a wall-clock cap, so the suite always reaches
//! a verdict and names the process that did not finish.

// Each integration test binary includes this module and uses a different
// subset of it.
#![allow(dead_code)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use sysinfo::System;

static BUILD_DAEMON: OnceLock<()> = OnceLock::new();

/// Wall-clock cap for a single test-driven subprocess.
///
/// Generous enough that a cold daemon start on a loaded machine still passes,
/// short enough that a wait which is never going to end fails the run instead
/// of pinning the machine.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);

/// Wall-clock cap for the in-test `cargo build` fallback, which competes for
/// the same build-directory lock as the `cargo test` invocation that is running
/// this suite.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_QUIESCENCE: Duration = Duration::from_millis(100);
const COMMAND_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
/// Maximum rendered UTF-8 bytes, including any truncation marker.
const COMMAND_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const COMMAND_DIAGNOSTIC_MARKER: &str = "\n[bounded capture truncated]";
const RUNTIME_OWNER_ENV: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";
const RUNTIME_CONTAINMENT_GROUP_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP";
pub const IDLE_SHUTDOWN_DISABLED_ENV: &str = "KIN_DAEMON_IDLE_TIMEOUT_SECS";
pub const SUPERVISOR_IDLE_SHUTDOWN_DISABLED_ENV: &str = "KIN_SUPERVISOR_IDLE_TIMEOUT_SECS";
/// The value both idle-shutdown controls read as "never idle out".
///
/// `kin-daemon` treats an empty value or `0` as no idle window at all; every
/// other value is a number of seconds after which it retires itself.
pub const IDLE_SHUTDOWN_DISABLED: &str = "0";

/// Whether a configured idle-shutdown value leaves the daemon's idle clock off,
/// applying the daemon's own parsing rule rather than matching one literal.
pub fn disables_idle_shutdown(value: Option<&OsStr>) -> bool {
    value
        .and_then(OsStr::to_str)
        .is_some_and(|value| matches!(value.trim(), "" | "0"))
}

#[cfg(unix)]
struct RuntimeContainment {
    process_group: libc::pid_t,
    guardian: Mutex<Option<kin_daemon_spawn::ProcessGroupGuardian>>,
    termination_requested: AtomicBool,
}

#[cfg(unix)]
impl RuntimeContainment {
    fn new(runtime_root: &Path, owner_token: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(runtime_root)?;
        let ready = runtime_root.join(format!("guardian-{owner_token}.ready"));
        let launcher = kin_daemon_spawn::ProcessGroupGuardianLauncher::exact_test(
            std::env::current_exe()?,
            "common::kin_process_group_guardian_worker",
        )
        .with_env(RUNTIME_OWNER_ENV, owner_token);
        let guardian = launcher.spawn_with(
            &ready,
            Instant::now() + PROCESS_REAP_TIMEOUT,
            scrub_inherited_kin_guardian_authority,
        )?;
        let process_group = guardian.process_group();
        Ok(Self {
            process_group,
            guardian: Mutex::new(Some(guardian)),
            termination_requested: AtomicBool::new(false),
        })
    }

    fn spawn(&self, command: std::process::Command, _label: &str) -> std::io::Result<Child> {
        if self.termination_requested.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "runtime containment was already terminated",
            ));
        }
        let mut guardian = self
            .guardian
            .lock()
            .map_err(|_| std::io::Error::other("runtime containment guardian lock poisoned"))?;
        let Some(guardian_handle) = guardian.as_mut() else {
            return Err(std::io::Error::other(
                "runtime containment was already terminated",
            ));
        };
        if guardian_handle.try_reap()?.is_some() {
            guardian.take();
            return Err(std::io::Error::other(
                "runtime containment guardian exited before child spawn",
            ));
        }
        guardian_handle.spawn(command)
    }

    fn terminate(&self) -> std::io::Result<()> {
        if self.termination_requested.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut guardian = self
            .guardian
            .lock()
            .map_err(|_| std::io::Error::other("runtime containment guardian lock poisoned"))?;
        let guardian = guardian.as_mut().ok_or_else(|| {
            std::io::Error::other("runtime containment lost its guardian before termination")
        })?;
        guardian.request_cleanup();
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        let mut guardian = self
            .guardian
            .lock()
            .map_err(|_| std::io::Error::other("runtime containment guardian lock poisoned"))?;
        let Some(guardian_handle) = guardian.as_mut() else {
            return Ok(true);
        };
        if guardian_handle.try_reap()?.is_some() {
            guardian.take();
            return Ok(true);
        }
        Ok(false)
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        if self
            .guardian
            .get_mut()
            .map_err(|_| "runtime containment guardian lock poisoned".to_string())?
            .is_none()
        {
            return Ok(());
        }
        let terminate_error = self.terminate().err();
        let tree_result = confirm_containment_empty(self, Instant::now() + PROCESS_REAP_TIMEOUT);
        let reap_result = if tree_result.is_err() {
            Err(
                "runtime containment guardian retained because quiescence was not proven"
                    .to_string(),
            )
        } else {
            Ok(())
        };
        combine_containment_results(terminate_error, tree_result, reap_result)
    }

    fn take_guardian(&self) -> Option<kin_daemon_spawn::ProcessGroupGuardian> {
        match self.guardian.lock() {
            Ok(mut guardian) => guardian.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

#[cfg(unix)]
impl Drop for RuntimeContainment {
    fn drop(&mut self) {
        // The owning runtime must reap every direct child before the guardian
        // can complete its final process-group proof. CommandContainment and
        // IsolatedDaemonRuntime perform that ordered finalization explicitly;
        // this catastrophic fallback seals admission and intentionally leaks
        // the exact guardian handle so its own Drop cannot finalize first.
        let _ = self.terminate();
        if let Some(mut guardian) = self.take_guardian() {
            guardian.request_cleanup();
            std::mem::forget(guardian);
        }
    }
}

#[cfg(unix)]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run exact process-group guardian worker");
    assert_eq!(dispatched, requested);
}

#[cfg(unix)]
struct CommandContainment {
    runtime: RuntimeContainment,
}

#[cfg(unix)]
impl CommandContainment {
    fn spawn(mut command: std::process::Command, label: &str) -> std::io::Result<(Child, Self)> {
        let root = tempfile::tempdir()?;
        let owner_token = uuid::Uuid::new_v4().to_string();
        let runtime = RuntimeContainment::new(root.path(), &owner_token)?;
        command.env(RUNTIME_OWNER_ENV, owner_token).env(
            RUNTIME_CONTAINMENT_GROUP_ENV,
            runtime.process_group.to_string(),
        );
        let child = runtime.spawn(command, label)?;
        Ok((child, Self { runtime }))
    }

    fn terminate(&self) -> std::io::Result<()> {
        self.runtime.terminate()
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        self.runtime.is_empty()
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        self.runtime.terminate_and_confirm()
    }

    fn retain_unreaped_child(&mut self, child: Child, label: String) -> Result<(), String> {
        let Some(guardian) = self.runtime.take_guardian() else {
            std::mem::forget(child);
            return Err(
                "command containment lost its guardian; exact direct-child handle intentionally \
                 leaked"
                    .to_string(),
            );
        };
        retain_unreaped_process_group(
            guardian,
            vec![Arc::new(Mutex::new(RuntimeOwnedChildState {
                child: Some(child),
                status: None,
                label,
            }))],
            "command containment",
        )
    }
}

#[cfg(unix)]
impl Drop for CommandContainment {
    fn drop(&mut self) {
        // Explicit command cleanup reaps the direct child before final proof.
        // RuntimeContainment's fallback intentionally retains the guardian if
        // an unwind reaches field destruction before that proof.
        let _ = self.terminate();
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl WindowsJob {
    fn new() -> std::io::Result<Self> {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self {
            // SAFETY: CreateJobObjectW returned a fresh, non-null owned
            // handle. OwnedHandle closes it exactly once, including on later
            // configuration failure.
            handle: unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) },
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.raw_handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle as _;

        self.handle.as_raw_handle()
    }

    fn spawn(&self, command: std::process::Command, label: &str) -> std::io::Result<Child> {
        spawn_in_windows_job(command, self.raw_handle(), label)
    }

    fn terminate(&self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(self.raw_handle(), 1) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.raw_handle(),
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(accounting.ActiveProcesses == 0)
        }
    }
}

#[cfg(windows)]
#[test]
fn isolated_daemon_runtime_is_send_and_sync() {
    fn assert_send_and_sync<T: Send + Sync>() {}

    assert_send_and_sync::<IsolatedDaemonRuntime>();
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
fn spawn_in_windows_job(
    mut command: std::process::Command,
    job: windows_sys::Win32::Foundation::HANDLE,
    label: &str,
) -> std::io::Result<Child> {
    use std::os::windows::io::AsRawHandle as _;
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, TerminateJobObject};
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, ResumeThread, CREATE_SUSPENDED,
        THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    command.creation_flags(CREATE_SUSPENDED);
    let mut child = command
        .spawn()
        .map_err(|error| std::io::Error::new(error.kind(), format!("spawn {label}: {error}")))?;
    if unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
        let error = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::new(
            error.kind(),
            format!("assign {label} to test job: {error}"),
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
                    "suspended test process has no primary thread",
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
                    "suspended thread entry is too small: {} < {minimum_size}",
                    entry.dwSize
                )));
            }
            if entry.th32OwnerProcessID == child.id() {
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
                "suspended test process must have one primary thread, found {}",
                matches.len()
            )));
        }
        Ok(matches[0])
    })();
    let thread_id = match thread_id {
        Ok(thread_id) => thread_id,
        Err(error) => {
            let _ = unsafe { TerminateJobObject(job, 1) };
            let _ = child.kill();
            let _ = child.wait();
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
        let _ = unsafe { TerminateJobObject(job, 1) };
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::new(
            error.kind(),
            format!("open {label} primary thread: {error}"),
        ));
    }
    let thread = WindowsOwnedHandle(thread);
    if unsafe { GetProcessIdOfThread(thread.0) } != child.id() {
        let _ = unsafe { TerminateJobObject(job, 1) };
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(format!(
            "{label} primary-thread owner changed"
        )));
    }
    let previous_suspend_count = unsafe { ResumeThread(thread.0) };
    if previous_suspend_count != 1 {
        let error = std::io::Error::last_os_error();
        let _ = unsafe { TerminateJobObject(job, 1) };
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::new(
            error.kind(),
            format!(
                "resume {label} primary thread returned {previous_suspend_count}, expected 1: {error}"
            ),
        ));
    }
    Ok(child)
}

#[cfg(windows)]
struct RuntimeContainment {
    job: WindowsJob,
}

#[cfg(windows)]
impl RuntimeContainment {
    fn new(_runtime_root: &Path, _owner_token: &str) -> std::io::Result<Self> {
        Ok(Self {
            job: WindowsJob::new()?,
        })
    }

    fn spawn(&self, command: std::process::Command, label: &str) -> std::io::Result<Child> {
        self.job.spawn(command, label)
    }

    fn terminate(&self) -> std::io::Result<()> {
        self.job.terminate()
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        self.job.is_empty()
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        let terminate_error = self.terminate().err();
        let tree_result = confirm_containment_empty(self, Instant::now() + PROCESS_REAP_TIMEOUT);
        combine_containment_results(terminate_error, tree_result, Ok(()))
    }
}

#[cfg(windows)]
struct CommandContainment {
    job: WindowsJob,
}

#[cfg(windows)]
impl CommandContainment {
    fn spawn(command: std::process::Command, label: &str) -> std::io::Result<(Child, Self)> {
        let containment = Self {
            job: WindowsJob::new()?,
        };
        let child = containment.job.spawn(command, label)?;
        Ok((child, containment))
    }

    fn terminate(&self) -> std::io::Result<()> {
        self.job.terminate()
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        self.job.is_empty()
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        let terminate_error = self.terminate().err();
        let quiescence = confirm_containment_empty(self, Instant::now() + PROCESS_REAP_TIMEOUT);
        combine_containment_results(terminate_error, quiescence, Ok(()))
    }

    fn retain_unreaped_child(&mut self, child: Child, _label: String) -> Result<(), String> {
        std::mem::forget(child);
        Err("unreaped Windows command child handle intentionally retained".to_string())
    }
}

#[cfg(not(any(unix, windows)))]
struct RuntimeContainment;

#[cfg(not(any(unix, windows)))]
impl RuntimeContainment {
    fn new(_runtime_root: &Path, _owner_token: &str) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn spawn(&self, mut command: std::process::Command, _label: &str) -> std::io::Result<Child> {
        command.spawn()
    }

    fn terminate(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        Ok(true)
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
struct CommandContainment;

#[cfg(not(any(unix, windows)))]
impl CommandContainment {
    fn spawn(mut command: std::process::Command, _label: &str) -> std::io::Result<(Child, Self)> {
        Ok((command.spawn()?, Self))
    }

    fn terminate(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        Ok(true)
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn retain_unreaped_child(&mut self, child: Child, _label: String) -> Result<(), String> {
        std::mem::forget(child);
        Err("unreaped command child handle intentionally retained".to_string())
    }
}

trait ProcessContainment {
    fn terminate(&self) -> std::io::Result<()>;
    fn is_empty(&self) -> std::io::Result<bool>;
}

impl ProcessContainment for RuntimeContainment {
    fn terminate(&self) -> std::io::Result<()> {
        self.terminate()
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        self.is_empty()
    }
}

impl ProcessContainment for CommandContainment {
    fn terminate(&self) -> std::io::Result<()> {
        self.terminate()
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        self.is_empty()
    }
}

fn confirm_containment_empty(
    containment: &impl ProcessContainment,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        match containment.is_empty() {
            Ok(true) => return Ok(()),
            Ok(false) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(false) => return Err("test process containment remained live".to_string()),
            Err(error) => return Err(format!("inspect test process containment: {error}")),
        }
    }
}

fn combine_containment_results(
    terminate_error: Option<std::io::Error>,
    tree_result: Result<(), String>,
    reap_result: Result<(), String>,
) -> Result<(), String> {
    if terminate_error.is_none() && tree_result.is_ok() && reap_result.is_ok() {
        return Ok(());
    }
    Err(format!(
        "containment termination={}; quiescence={}; reap={}",
        terminate_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "ok".to_string()),
        tree_result.err().unwrap_or_else(|| "ok".to_string()),
        reap_result.err().unwrap_or_else(|| "ok".to_string())
    ))
}

#[derive(Debug)]
struct CleanupCommand {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

struct RuntimeOwnedChildState {
    child: Option<Child>,
    status: Option<ExitStatus>,
    label: String,
}

impl RuntimeOwnedChildState {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("runtime-owned child lost its process handle"))?;
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };
        self.status = Some(status);
        self.child.take();
        Ok(Some(status))
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("runtime-owned child lost its process handle"))?
            .wait()?;
        self.status = Some(status);
        self.child.take();
        Ok(status)
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        self.child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("runtime-owned child lost its process handle"))?
            .kill()
    }

    fn terminate_and_reap_until(&mut self, deadline: Instant) -> Result<ExitStatus, String> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let initial = self
            .try_wait()
            .map_err(|error| format!("inspect {} before cleanup: {error}", self.label))?;
        if let Some(status) = initial {
            return Ok(status);
        }

        // A kill can race a natural exit. Reaping is the authority: if a
        // status is obtained, preserve and return it even if the preceding
        // kill observed that the process had already gone away.
        let kill_error = self.kill().err();
        loop {
            match self.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
                Ok(None) => {
                    return Err(format!(
                        "{} was not reaped within {PROCESS_REAP_TIMEOUT:?}; kill={kill_error:?}",
                        self.label
                    ));
                }
                Err(error) => {
                    return Err(format!("reap {}: {error}; kill={kill_error:?}", self.label));
                }
            }
        }
    }
}

impl Drop for RuntimeOwnedChildState {
    fn drop(&mut self) {
        if self.status.is_some() || self.child.is_none() {
            return;
        }
        if let Err(error) = self.terminate_and_reap_until(Instant::now() + PROCESS_REAP_TIMEOUT) {
            if let Some(child) = self.child.take() {
                // The exact wait handle must outlive the unreaped status. The
                // owning containment is retained separately and may not run
                // its final guardian proof while this catastrophic fallback
                // remains unresolved.
                std::mem::forget(child);
            }
            if std::thread::panicking() {
                eprintln!("runtime-owned child state cleanup failed: {error}");
            } else {
                panic!("runtime-owned child state cleanup failed: {error}");
            }
        }
    }
}

#[cfg(unix)]
struct RetainedProcessGroupCleanup {
    guardian: kin_daemon_spawn::ProcessGroupGuardian,
    children: Vec<Arc<Mutex<RuntimeOwnedChildState>>>,
}

#[cfg(unix)]
impl RetainedProcessGroupCleanup {
    fn run(mut self) {
        self.guardian.request_cleanup();
        loop {
            let mut all_reaped = true;
            for child in &self.children {
                let mut state = match child.try_lock() {
                    Ok(state) => state,
                    Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        all_reaped = false;
                        continue;
                    }
                };
                if state
                    .terminate_and_reap_until(Instant::now() + PROCESS_REAP_TIMEOUT)
                    .is_err()
                {
                    all_reaped = false;
                }
            }
            if all_reaped {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        // Every direct status is now cached. Only now may the guardian run its
        // irreversible sentinel reap and exact empty-group proof.
        let _ = self
            .guardian
            .reap_until(Instant::now() + PROCESS_REAP_TIMEOUT);
    }
}

#[cfg(unix)]
fn retain_unreaped_process_group(
    guardian: kin_daemon_spawn::ProcessGroupGuardian,
    children: Vec<Arc<Mutex<RuntimeOwnedChildState>>>,
    label: &str,
) -> Result<(), String> {
    let retained = std::mem::ManuallyDrop::new(RetainedProcessGroupCleanup { guardian, children });
    std::thread::Builder::new()
        .name("kin-test-retained-process-group".to_string())
        .spawn(move || {
            let retained = std::mem::ManuallyDrop::into_inner(retained);
            retained.run();
        })
        .map(|_| ())
        .map_err(|error| {
            format!(
                "spawn retained cleanup owner for {label}: {error}; exact guardian and child \
                 handles intentionally leaked"
            )
        })
}

/// A direct child whose wait status is shared with its owning runtime.
///
/// The runtime can therefore terminate and reap this child before finalizing
/// guardian containment even when a test deliberately keeps the handle alive
/// across `drop(runtime)`. The cached status remains observable afterward.
pub struct RuntimeOwnedChild {
    pid: u32,
    state: Arc<Mutex<RuntimeOwnedChildState>>,
}

impl RuntimeOwnedChild {
    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("runtime-owned child lock poisoned"))?
            .try_wait()
    }

    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("runtime-owned child lock poisoned"))?
            .wait()
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("runtime-owned child lock poisoned"))?
            .kill()
    }
}

impl Drop for RuntimeOwnedChild {
    fn drop(&mut self) {
        let cleanup = self
            .state
            .lock()
            .map_err(|_| "runtime-owned child lock poisoned".to_string())
            .and_then(|mut state| {
                state.terminate_and_reap_until(Instant::now() + PROCESS_REAP_TIMEOUT)
            });
        if let Err(error) = cleanup {
            if std::thread::panicking() {
                eprintln!("runtime-owned child cleanup failed: {error}");
            } else {
                panic!("runtime-owned child cleanup failed: {error}");
            }
        }
    }
}

/// Per-test supervisor and registry state with fail-closed lifecycle cleanup.
///
/// Daemon-backed integration tests must never discover the user's real Kin
/// registry. Runtime-only state lives in an owned system temporary directory,
/// outside the repository: constructing this harness before `kin init` must not
/// create the product-owned `.kin` control directory and make initialization
/// reject an otherwise fresh repository. Its `Drop` path first asks the product
/// CLI to stop every process, then terminates the stable OS containment created
/// before any child was launched. A final owner-token scan is verification only:
/// it never signals a PID, so PID reuse cannot authorize killing an unrelated
/// process. Direct child wait authority is registered with the runtime: Drop
/// terminates containment, reaps and caches every direct status, and only then
/// permits the guardian's irreversible final empty-group proof.
pub struct IsolatedDaemonRuntime {
    repository: PathBuf,
    registry_path: PathBuf,
    home_path: PathBuf,
    owner_token: String,
    owned_children: Mutex<Vec<Arc<Mutex<RuntimeOwnedChildState>>>>,
    containment: RuntimeContainment,
    cleanup_command: Option<CleanupCommand>,
    cleanup_timeout: Duration,
    _runtime_root: tempfile::TempDir,
}

impl IsolatedDaemonRuntime {
    pub fn new(repository: &Path) -> Self {
        let runtime_root = tempfile::Builder::new()
            .prefix("kin-isolated-runtime-")
            .tempdir()
            .unwrap_or_else(|error| panic!("create isolated runtime root: {error}"));
        let home_path = runtime_root.path().join("home");
        let owner_token = uuid::Uuid::new_v4().to_string();
        let containment = RuntimeContainment::new(runtime_root.path(), &owner_token)
            .unwrap_or_else(|error| panic!("create isolated runtime containment: {error}"));
        Self {
            repository: repository.to_path_buf(),
            registry_path: runtime_root.path().join("registry.toml"),
            home_path,
            owner_token,
            owned_children: Mutex::new(Vec::new()),
            containment,
            cleanup_command: None,
            cleanup_timeout: Duration::from_secs(15),
            _runtime_root: runtime_root,
        }
    }

    pub fn with_cleanup_command_for_test(
        repository: &Path,
        program: PathBuf,
        args: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
        timeout: Duration,
    ) -> Self {
        let mut runtime = Self::new(repository);
        runtime.cleanup_command = Some(CleanupCommand { program, args, env });
        runtime.cleanup_timeout = timeout;
        runtime
    }

    pub fn process_command_for_test<S: AsRef<OsStr>>(&self, program: S) -> Command<'_> {
        self.command(program)
    }

    pub fn kin_command(&self) -> Command<'_> {
        self.command(env!("CARGO_BIN_EXE_kin"))
    }

    pub fn daemon_bin(&self) -> PathBuf {
        fresh_daemon_bin(self)
    }

    /// Resolve or build the compatible daemon without outliving `deadline`.
    ///
    /// A smoke test with one total wall-clock budget must include harness
    /// preparation. Otherwise the compatibility probe or fallback Cargo build
    /// can wait longer than the product sequence the test claims to bound.
    pub fn daemon_bin_before(&self, deadline: Instant) -> PathBuf {
        fresh_daemon_bin_before(self, deadline)
    }

    pub fn daemon_command(&self) -> Command<'_> {
        self.command(self.daemon_bin())
    }

    pub fn registry_path(&self) -> &Path {
        &self.registry_path
    }

    #[cfg(unix)]
    pub fn process_group_for_test(&self) -> libc::pid_t {
        self.containment.process_group
    }

    #[cfg(unix)]
    pub fn spawn_owned_process_for_test(
        &self,
        mut command: std::process::Command,
    ) -> std::io::Result<RuntimeOwnedChild> {
        command.env(RUNTIME_OWNER_ENV, &self.owner_token).env(
            RUNTIME_CONTAINMENT_GROUP_ENV,
            self.containment.process_group.to_string(),
        );
        let label = "runtime-owned test process";
        let child = self.containment.spawn(command, label)?;
        self.register_owned_child(child, label)
    }

    fn command<S: AsRef<OsStr>>(&self, program: S) -> Command<'_> {
        let mut command = std::process::Command::new(program);
        self.apply_isolated_environment(&mut command);
        Command {
            inner: Some(command),
            runtime: Some(self),
            intentional_env: Vec::new(),
        }
    }

    fn apply_isolated_environment(&self, command: &mut std::process::Command) {
        scrub_inherited_kin_authority(command);
        command
            .env("KIN_REGISTRY_PATH", &self.registry_path)
            // Bind the managed install and store root explicitly. HOME and
            // USERPROFILE remain a fail-closed fallback for any child boundary
            // that intentionally rebuilds its environment instead of
            // inheriting the override.
            .env("KIN_HOME", self.home_path.join(".kin"))
            .env("HOME", &self.home_path)
            .env("USERPROFILE", &self.home_path)
            .env("XDG_CONFIG_HOME", self.home_path.join(".config"))
            .env(RUNTIME_OWNER_ENV, &self.owner_token)
            .env("KIN_VFS_DISABLE", "1")
            // Idle shutdown is disabled because this runtime already bounds
            // daemon lifetime with evidence rather than a clock. `Drop` stops
            // every process through the product CLI, terminates the
            // guardian-owned process group, reaps each direct child, and only
            // then accepts the final empty-group proof; a killed test binary
            // reaches the same end through the guardian's own parent-death
            // watch, and a daemon whose temporary repository disappears exits
            // on its control-plane check. An idle window adds nothing to that
            // and races the test holding the daemon: the window is measured
            // from daemon readiness, so a loaded machine can retire a daemon
            // between the moment a command proves the endpoint healthy and the
            // moment it dispatches, and the command then fails against an
            // endpoint that was live when it was read. Any value short enough
            // to retire daemons promptly is short enough to lose that race.
            .env(IDLE_SHUTDOWN_DISABLED_ENV, IDLE_SHUTDOWN_DISABLED)
            .env(
                SUPERVISOR_IDLE_SHUTDOWN_DISABLED_ENV,
                IDLE_SHUTDOWN_DISABLED,
            )
            // Production deliberately allows ~18s for graceful daemon
            // shutdown and force-exits after ~25s. Integration cleanup has a
            // tighter independent bound, so use the daemon's supported grace
            // controls instead of assuming LSP/enrichment work will drain in
            // under the CLI's five-second stop window.
            .env("KIN_DAEMON_SHUTDOWN_GRACE_SECS", "3")
            .env("KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS", "1")
            // `daemon stop --all` can wait once per worker and once for the
            // supervisor. Keep both waits below Drop's independent wall cap.
            .env("KIN_DAEMON_STOP_TIMEOUT_SECS", "5");
        #[cfg(unix)]
        command.env(
            RUNTIME_CONTAINMENT_GROUP_ENV,
            self.containment.process_group.to_string(),
        );
    }

    fn register_owned_child(
        &self,
        child: Child,
        label: impl Into<String>,
    ) -> std::io::Result<RuntimeOwnedChild> {
        let pid = child.id();
        let state = Arc::new(Mutex::new(RuntimeOwnedChildState {
            child: Some(child),
            status: None,
            label: label.into(),
        }));
        let mut registry = match self.owned_children.lock() {
            Ok(registry) => registry,
            Err(poisoned) => {
                // The caller cannot safely receive a wrapper from a poisoned
                // registry, but the exact child handle still belongs to the
                // runtime. Retain it so Drop can reap or transfer it with the
                // guardian instead of losing wait authority on this error.
                poisoned.into_inner().push(state);
                return Err(std::io::Error::other(
                    "runtime-owned child registry lock poisoned; direct child retained",
                ));
            }
        };
        registry.push(Arc::clone(&state));
        Ok(RuntimeOwnedChild { pid, state })
    }

    fn retain_unreaped_direct_child(&self, child: Child, label: String) -> Result<(), String> {
        let state = Arc::new(Mutex::new(RuntimeOwnedChildState {
            child: Some(child),
            status: None,
            label,
        }));
        match self.owned_children.lock() {
            Ok(mut registry) => {
                registry.push(state);
                Ok(())
            }
            Err(poisoned) => {
                // Poison does not invalidate the owned handles. Recover the
                // registry and retain the exact child so runtime Drop can
                // retry or transfer it with the guardian.
                poisoned.into_inner().push(state);
                Err(
                    "runtime-owned child registry was poisoned; unreaped handle retained"
                        .to_string(),
                )
            }
        }
    }

    fn terminate_and_reap_owned_children(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
        let mut failures = Vec::new();
        let children = match self.owned_children.get_mut() {
            Ok(children) => children,
            Err(poisoned) => {
                failures.push("runtime-owned child registry lock poisoned".to_string());
                poisoned.into_inner()
            }
        };
        for child in children {
            let mut state = match child.try_lock() {
                Ok(state) => state,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    failures.push("runtime-owned child lock poisoned".to_string());
                    poisoned.into_inner()
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    failures.push(
                        "runtime-owned child was concurrently borrowed during cleanup".to_string(),
                    );
                    continue;
                }
            };
            if let Err(error) = state.terminate_and_reap_until(deadline) {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    #[cfg(unix)]
    fn retain_failed_owned_children(&mut self) -> Result<(), String> {
        let children = match self.owned_children.get_mut() {
            Ok(children) => std::mem::take(children),
            Err(poisoned) => std::mem::take(poisoned.into_inner()),
        };
        let Some(guardian) = self.containment.take_guardian() else {
            for child in children {
                std::mem::forget(child);
            }
            return Err(
                "runtime containment lost its guardian; exact direct-child states intentionally \
                 leaked"
                    .to_string(),
            );
        };
        retain_unreaped_process_group(guardian, children, "runtime containment")
    }

    #[cfg(not(unix))]
    fn retain_failed_owned_children(&mut self) -> Result<(), String> {
        let children = match self.owned_children.get_mut() {
            Ok(children) => std::mem::take(children),
            Err(poisoned) => std::mem::take(poisoned.into_inner()),
        };
        for child in children {
            std::mem::forget(child);
        }
        Err("unreaped runtime child handles intentionally retained".to_string())
    }

    fn cleanup_invocation(&self) -> Command<'_> {
        if let Some(cleanup) = &self.cleanup_command {
            let mut command = self.command(&cleanup.program);
            command
                .args(&cleanup.args)
                .envs(cleanup.env.iter().map(|(key, value)| (key, value)));
            command
        } else {
            let mut command = self.kin_command();
            command.args(["daemon", "stop", "--all"]);
            command
        }
    }

    fn runtime_repository_paths(&self) -> Vec<PathBuf> {
        let mut paths = BTreeSet::from([self.repository.clone()]);
        if let Ok(contents) = std::fs::read_to_string(&self.registry_path) {
            if let Ok(registry) = toml::from_str::<kin_core::registry::KinRegistry>(&contents) {
                paths.extend(registry.repos.into_iter().map(|repo| repo.path));
            }
        }
        paths.into_iter().collect()
    }

    fn remove_stale_endpoint_files(&self) {
        for repository in self.runtime_repository_paths() {
            let kin_root = repository.join(".kin");
            for name in ["daemon.pid", "daemon.port", "daemon.token"] {
                let _ = std::fs::remove_file(kin_root.join(name));
            }
        }
        if let Some(parent) = self.registry_path.parent() {
            for name in ["supervisor.pid", "supervisor.port", "supervisor.token"] {
                let _ = std::fs::remove_file(parent.join(name));
            }
        }
    }
}

/// What a repository's recorded daemon endpoint can be proven to be.
///
/// The published record and the listener it names are separate pieces of state,
/// so a probe has to separate "no daemon is advertised" from "a daemon is
/// advertised and does not answer". Only the second breaks a caller: a command
/// reads the record, proves the endpoint healthy, and dispatches against a
/// listener that is already gone.
#[derive(Debug)]
pub enum RecordedDaemonEndpoint {
    Unrecorded,
    Listening { port: u16 },
    NotListening { port: u16, error: String },
    Unreadable { detail: String },
}

const ENDPOINT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Probe the endpoint `kin_root`'s daemon record names, without spawning one.
///
/// `kin_root` is the `.kin/` directory, the same one the daemon publishes into.
pub fn probe_recorded_daemon_endpoint(kin_root: &Path) -> RecordedDaemonEndpoint {
    let port_path = kin_root.join(kin_daemon_spawn::PORT_FILE_NAME);
    let recorded = match std::fs::read_to_string(&port_path) {
        Ok(recorded) => recorded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RecordedDaemonEndpoint::Unrecorded;
        }
        Err(error) => {
            return RecordedDaemonEndpoint::Unreadable {
                detail: format!("read {}: {error}", port_path.display()),
            };
        }
    };
    let Ok(port) = recorded.trim().parse::<u16>() else {
        return RecordedDaemonEndpoint::Unreadable {
            detail: format!("{} does not name a port: {recorded:?}", port_path.display()),
        };
    };
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    match std::net::TcpStream::connect_timeout(&address, ENDPOINT_PROBE_TIMEOUT) {
        Ok(_) => RecordedDaemonEndpoint::Listening { port },
        Err(error) => RecordedDaemonEndpoint::NotListening {
            port,
            error: error.to_string(),
        },
    }
}

impl Drop for IsolatedDaemonRuntime {
    fn drop(&mut self) {
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cleanup_invocation()
                .current_dir(&self.repository)
                .output_within(self.cleanup_timeout)
        }));
        let graceful_failure = match cleanup {
            Ok(Ok(output)) if output.status.success() => None,
            Ok(Ok(output)) => Some(render_failed_cleanup_output(
                &output.status.to_string(),
                &output.stdout,
                &output.stderr,
            )),
            Ok(Err(error)) => Some(format!("isolated daemon cleanup could not run: {error}")),
            Err(_) => Some("isolated daemon cleanup exceeded its wall-clock bound".to_string()),
        };
        let containment_termination_failure = self
            .containment
            .terminate()
            .err()
            .map(|error| format!("terminate runtime containment: {error}"));
        let owned_child_failure = self.terminate_and_reap_owned_children().err();
        let retained_cleanup_failure = if owned_child_failure.is_some() {
            self.retain_failed_owned_children().err()
        } else {
            None
        };
        let containment_failure = if owned_child_failure.is_none() {
            self.containment.terminate_and_confirm().err()
        } else {
            Some(
                "runtime containment final proof transferred with unreaped direct children"
                    .to_string(),
            )
        };
        let quiescence_failure = wait_for_owned_process_quiescence(
            RUNTIME_OWNER_ENV,
            &self.owner_token,
            Instant::now() + PROCESS_REAP_TIMEOUT,
        )
        .err();
        self.remove_stale_endpoint_files();

        let failure = [
            graceful_failure,
            containment_termination_failure,
            owned_child_failure,
            retained_cleanup_failure,
            containment_failure,
            quiescence_failure,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        if !failure.is_empty() {
            if std::thread::panicking() {
                eprintln!("{failure}");
            } else {
                panic!("{failure}");
            }
        }
    }
}

/// A drop-in replacement for `std::process::Command` whose `output()` cannot
/// block forever.
///
/// Two differences from the standard type, both load-bearing:
///
/// - Dedicated reader sinks drain stdout and stderr continuously while
///   retaining at most a fixed byte ceiling per stream. A runtime-bound
///   `kin-daemon` may inherit those streams; the caller snapshots a quiescent
///   bounded prefix rather than waiting for descendant-owned EOF, then
///   explicitly cancels and joins both readers within a bounded grace period.
/// - The wait carries a wall-clock deadline. At the deadline the child is
///   killed and the test fails naming the command, instead of leaving a silent,
///   idle process the developer has to notice and kill by hand.
pub struct Command<'runtime> {
    inner: Option<std::process::Command>,
    runtime: Option<&'runtime IsolatedDaemonRuntime>,
    intentional_env: Vec<(OsString, Option<OsString>)>,
}

impl Command<'static> {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let program = program.as_ref();
        let mut inner = std::process::Command::new(program);
        if is_git_program(program) {
            inner.args(FIXTURE_GIT_MAINTENANCE_SUPPRESSION);
        }
        Self {
            inner: Some(inner),
            runtime: None,
            intentional_env: Vec::new(),
        }
    }
}

/// Command-scope configuration prepended to every fixture Git launch.
///
/// Integration fixtures commit a repository and then admit it. Git otherwise
/// ends a commit by spawning `git maintenance run --auto --quiet --detach`,
/// which outlives the commit, and whose incremental-repack task runs
/// `git multi-pack-index write` and holds
/// `objects/pack/multi-pack-index.lock` for the width of that write. Kin's
/// admission preflight reads any lock under `objects/pack` as concurrent
/// repository mutation and refuses, so the fixture was racing a background
/// process it never asked for.
///
/// This rides on the argument list rather than in the environment on purpose.
/// The environment of a fixture command is inherited by the `kin` binary under
/// test and by every Git process it spawns, and the fixture boundary keeps that
/// environment free of Git configuration scope so the product is exercised with
/// the Git behavior a user would get.
const FIXTURE_GIT_MAINTENANCE_SUPPRESSION: [&str; 4] =
    ["-c", "maintenance.auto=false", "-c", "gc.auto=0"];

/// Whether a program name launches Git, so the suppression above reaches every
/// fixture Git command without each call site having to remember it.
///
/// Matched on the file stem so an absolute path and a `.exe` suffix both
/// resolve, and case-insensitively because Windows paths do.
fn is_git_program(program: &OsStr) -> bool {
    std::path::Path::new(program)
        .file_stem()
        .is_some_and(|stem| stem.eq_ignore_ascii_case("git"))
}

#[test]
fn fixture_git_commands_prepend_maintenance_suppression() {
    for program in ["git", "/usr/bin/git", "git.exe", "GIT"] {
        assert!(
            is_git_program(OsStr::new(program)),
            "{program} was not recognized as Git, so its commits would detach maintenance"
        );
    }
    for program in ["sh", "kin", "gitk", "git-upload-pack", "/usr/bin/legit"] {
        assert!(
            !is_git_program(OsStr::new(program)),
            "{program} was misread as Git"
        );
    }

    let git = Command::new("git");
    let arguments = git
        .inner_ref()
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        arguments.iter().map(String::as_str).collect::<Vec<_>>(),
        FIXTURE_GIT_MAINTENANCE_SUPPRESSION.to_vec(),
        "a fixture Git command did not lead with the maintenance suppression"
    );

    // The suppression is Git configuration, so it must not reach anything else.
    assert!(
        Command::new("sh").inner_ref().get_args().next().is_none(),
        "a non-Git fixture command was given Git configuration arguments"
    );
}

impl<'runtime> Command<'runtime> {
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.inner_mut().arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner_mut().args(args);
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        let key = key.as_ref();
        let value = value.as_ref();
        self.inner_mut().env(key, value);
        if is_allowed_test_override(self.runtime.is_some(), key) {
            upsert_intentional_env(
                &mut self.intentional_env,
                key.to_os_string(),
                Some(value.to_os_string()),
            );
        }
        self
    }

    /// Preserve one explicit timestamp for both halves of fixture commit
    /// identity across the final Git-authority scrub.
    ///
    /// This is deliberately typed around the exact safe intent. General
    /// `GIT_*` environment overrides remain fail-closed, and callers cannot use
    /// this surface to replay repository/configuration authority after
    /// `kin_git::test_support::isolate_fixture_git`.
    pub fn fixture_git_commit_dates<V: AsRef<OsStr>>(&mut self, value: V) -> &mut Self {
        let value = value.as_ref().to_os_string();
        for key in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
            self.inner_mut().env(key, &value);
            upsert_intentional_env(
                &mut self.intentional_env,
                OsString::from(key),
                Some(value.clone()),
            );
        }
        self
    }

    /// Preserve one explicit daemon endpoint for a runtime-bound negative-path
    /// fixture after the final Kin-authority scrub.
    ///
    /// General `KIN_DAEMON_URL` overrides remain fail-closed. This narrow
    /// surface exists only for tests that must prove behavior against a
    /// deliberately unreachable endpoint without silently autostarting the
    /// isolated runtime's daemon.
    pub fn fixture_daemon_url<V: AsRef<OsStr>>(&mut self, value: V) -> &mut Self {
        assert!(
            self.runtime.is_some(),
            "fixture_daemon_url requires an IsolatedDaemonRuntime command"
        );
        let key = OsString::from("KIN_DAEMON_URL");
        let value = value.as_ref().to_os_string();
        self.inner_mut().env(&key, &value);
        upsert_intentional_env(&mut self.intentional_env, key, Some(value));
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (key, value) in vars {
            self.env(key, value);
        }
        self
    }

    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        let key = key.as_ref();
        self.inner_mut().env_remove(key);
        if is_allowed_test_override(self.runtime.is_some(), key) {
            upsert_intentional_env(&mut self.intentional_env, key.to_os_string(), None);
        }
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.inner_mut().current_dir(dir);
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner_mut().stdin(cfg);
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner_mut().stdout(cfg);
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner_mut().stderr(cfg);
        self
    }

    pub fn configured_env_for_test(&self, key: &OsStr) -> Option<Option<OsString>> {
        self.inner_ref()
            .get_envs()
            .find(|(configured, _)| env_os_names_equal(configured, key))
            .map(|(_, value)| value.map(OsStr::to_os_string))
    }

    pub fn prepare_for_launch_for_test(&mut self) {
        self.prepare_for_launch();
    }

    /// Run to completion under [`COMMAND_TIMEOUT`] with stdin closed.
    pub fn output(&mut self) -> std::io::Result<Output> {
        self.output_within(COMMAND_TIMEOUT)
    }

    pub fn output_within(&mut self, timeout: Duration) -> std::io::Result<Output> {
        self.output_within_after_path(None, timeout)
    }

    /// Wait for `ready_path` before starting the command's execution deadline.
    ///
    /// Process-tree tests use this to distinguish slow process startup from the
    /// behavior under test. Readiness itself remains independently bounded, and
    /// either deadline uses the same fail-closed descendant cleanup.
    pub fn output_after_path_ready_within(
        &mut self,
        ready_path: &Path,
        readiness_timeout: Duration,
        timeout: Duration,
    ) -> std::io::Result<Output> {
        self.output_within_after_path(Some((ready_path, readiness_timeout)), timeout)
    }

    fn output_within_after_path(
        &mut self,
        readiness: Option<(&Path, Duration)>,
        timeout: Duration,
    ) -> std::io::Result<Output> {
        if self.inner.is_none() {
            return Err(Self::consumed_error());
        }
        self.prepare_for_launch();
        let label = self
            .inner_ref()
            .get_program()
            .to_string_lossy()
            .into_owned();
        let command = self.take_inner()?;
        run_bounded_within(command, &label, self.runtime, readiness, timeout)
    }

    /// Spawn a long-lived child inside this runtime's stable OS containment.
    ///
    /// Direct daemon tests need to probe a live child before stopping it, so
    /// `output()` is the wrong lifecycle. This keeps the same authority scrub,
    /// protected runtime capability, Unix process group, and Windows Job
    /// Object as bounded commands while leaving the direct child handle with
    /// the test.
    pub fn spawn_owned(&mut self) -> std::io::Result<RuntimeOwnedChild> {
        let runtime = self.runtime.ok_or_else(|| {
            std::io::Error::other("spawn_owned requires a command from IsolatedDaemonRuntime")
        })?;
        if self.inner.is_none() {
            return Err(Self::consumed_error());
        }
        self.prepare_for_launch();
        let label = self
            .inner_ref()
            .get_program()
            .to_string_lossy()
            .into_owned();
        let child = runtime.containment.spawn(self.take_inner()?, &label)?;
        runtime.register_owned_child(child, label)
    }

    fn prepare_for_launch(&mut self) {
        let command = self
            .inner
            .as_mut()
            .expect("bounded test command was already consumed");
        scrub_inherited_kin_authority(command);
        if let Some(runtime) = self.runtime {
            runtime.apply_isolated_environment(command);
        }
        // This must be the final general authority transform. In particular,
        // `apply_isolated_environment` scrubs every GIT_* key, so applying it
        // after fixture isolation would silently remove the null-config,
        // no-prompt, and protocol guards installed here.
        kin_git::test_support::isolate_fixture_git(command);
        for (key, value) in &self.intentional_env {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
    }

    fn inner_mut(&mut self) -> &mut std::process::Command {
        self.inner
            .as_mut()
            .expect("bounded test command was already consumed")
    }

    fn inner_ref(&self) -> &std::process::Command {
        self.inner
            .as_ref()
            .expect("bounded test command was already consumed")
    }

    fn take_inner(&mut self) -> std::io::Result<std::process::Command> {
        self.inner.take().ok_or_else(Self::consumed_error)
    }

    fn consumed_error() -> std::io::Error {
        std::io::Error::other("bounded test command was already consumed")
    }
}

fn upsert_intentional_env(
    configured: &mut Vec<(OsString, Option<OsString>)>,
    key: OsString,
    value: Option<OsString>,
) {
    if let Some((_, configured_value)) = configured
        .iter_mut()
        .find(|(configured_key, _)| env_os_names_equal(configured_key, &key))
    {
        *configured_value = value;
    } else {
        configured.push((key, value));
    }
}

fn is_allowed_runtime_override(key: &OsStr) -> bool {
    const ALLOWED: &[&str] = &[
        "KIN_DAEMON_BIN",
        "KIN_DAEMON_DISABLE_LSP",
        "KIN_DAEMON_IDLE_TIMEOUT_SECS",
        "KIN_SUPERVISOR_IDLE_TIMEOUT_SECS",
        "KIN_DAEMON_READY_TIMEOUT_SECS",
        "KIN_BYPASS_EMBEDDING_COVERAGE_CHECK",
        "KIN_EMBED_BACKEND",
        // A runtime-bound command that sets this and is not carried proves the
        // opposite of what its test asserts: the child embeds, and the test
        // reads that as the product ignoring an operator. That is how the
        // toggle was first reported dead on the CLI spawn path. The value is
        // per-command configuration rather than repository or session
        // authority, so carrying it costs the isolation boundary nothing.
        "KIN_DAEMON_AUTO_EMBED",
    ];
    !is_internal_runtime_capability(key)
        && (ALLOWED.iter().any(|allowed| env_os_name_eq(key, allowed))
            || env_os_name_starts_with(key, "KIN_TEST_"))
}

fn is_allowed_test_override(runtime_bound: bool, key: &OsStr) -> bool {
    if runtime_bound {
        return is_allowed_runtime_override(key);
    }
    is_kin_environment_name(key) && !is_internal_runtime_capability(key)
}

fn is_internal_runtime_capability(key: &OsStr) -> bool {
    env_os_name_starts_with(key, "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_")
        || [RUNTIME_OWNER_ENV, RUNTIME_CONTAINMENT_GROUP_ENV]
            .iter()
            .any(|protected| env_os_name_eq(key, protected))
}

fn is_kin_environment_name(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_") || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
}

fn scrub_inherited_kin_authority(command: &mut std::process::Command) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_kin_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_kin_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command.env("KIN_VFS_DISABLE", "1");
}

#[cfg(unix)]
fn scrub_inherited_kin_guardian_authority(
    environment: &mut kin_daemon_spawn::ProcessGroupGuardianEnvironment,
) {
    let explicit_authority = environment
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_kin_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_kin_authority(key))
        .chain(explicit_authority)
    {
        environment.env_remove(key);
    }
    environment.env("KIN_VFS_DISABLE", "1");
}

fn is_kin_authority(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
        || env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
}

#[cfg(windows)]
#[test]
fn runtime_authority_names_are_case_insensitive_on_windows() {
    for hostile in [
        "kin_registry_path",
        "_kin_vfs_last_dir",
        "git_config_count",
        "Dyld_Library_Path",
        "Ld_Custom_Injection",
    ] {
        assert!(
            is_kin_authority(OsStr::new(hostile)),
            "{hostile} bypassed Windows runtime isolation"
        );
    }
    assert!(
        !is_allowed_runtime_override(OsStr::new("kin_test_runtime_owner_token")),
        "mixed-case owner token became an allowed runtime override"
    );
}

fn env_os_names_equal(left: &OsStr, right: &OsStr) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn env_os_name_eq(actual: &OsStr, expected: &str) -> bool {
    env_name_eq(&actual.to_string_lossy(), expected)
}

fn env_os_name_starts_with(actual: &OsStr, expected: &str) -> bool {
    env_name_starts_with(&actual.to_string_lossy(), expected)
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

fn owned_process_ids(owner_env: &'static str, owner_token: &str) -> Vec<u32> {
    let system = System::new_all();
    let mut pids = system
        .processes()
        .values()
        // A thread inherits its owning process's environment, so an unfiltered
        // scan reports one owned process once per thread and every failure
        // message counts tids as strays (FIR-2823).
        .filter(|process| process.thread_kind().is_none())
        .filter(|process| process_has_owner_token(process, owner_env, owner_token))
        .map(|process| process.pid().as_u32())
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

fn wait_for_owned_process_quiescence(
    owner_env: &'static str,
    owner_token: &str,
    deadline: Instant,
) -> Result<(), String> {
    let mut quiescent_since = None;
    loop {
        let live = owned_process_ids(owner_env, owner_token);
        if live.is_empty() {
            let empty_since = quiescent_since.get_or_insert_with(Instant::now);
            if Instant::now() >= *empty_since + PROCESS_QUIESCENCE {
                return Ok(());
            }
        } else {
            quiescent_since = None;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "runtime-owned processes remained after stable containment cleanup: {live:?}"
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn process_has_owner_token(
    process: &sysinfo::Process,
    owner_env: &'static str,
    owner_token: &str,
) -> bool {
    let expected = format!("{owner_env}={owner_token}");
    process
        .environ()
        .iter()
        .any(|entry| entry == OsStr::new(&expected))
}

#[derive(Clone, Debug, Default)]
struct CapturedCommandStream {
    bytes: Vec<u8>,
    observed_bytes: u64,
    post_exit_empty_read_attempts: u64,
    truncated: bool,
    error: Option<String>,
    done: bool,
}

struct CommandCaptureReader {
    name: &'static str,
    state: Arc<Mutex<CapturedCommandStream>>,
    thread: Option<std::thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
    post_exit: Arc<AtomicBool>,
}

struct BoundedCommandCapture {
    stdout: CommandCaptureReader,
    stderr: CommandCaptureReader,
    overflowed: Arc<AtomicBool>,
}

#[derive(Debug)]
struct CapturedCommandOutput {
    stdout: CapturedCommandStream,
    stderr: CapturedCommandStream,
}

impl BoundedCommandCapture {
    fn configure(command: &mut std::process::Command) {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    fn start(child: &mut Child, label: &str) -> std::io::Result<Self> {
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::other(format!("{label} did not expose captured stdout"))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            std::io::Error::other(format!("{label} did not expose captured stderr"))
        })?;
        let overflowed = Arc::new(AtomicBool::new(false));
        Ok(Self {
            stdout: CommandCaptureReader::spawn(stdout, "stdout", overflowed.clone())?,
            stderr: CommandCaptureReader::spawn(stderr, "stderr", overflowed.clone())?,
            overflowed,
        })
    }

    fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    fn finish(self, descendants_were_closed: bool) -> std::io::Result<CapturedCommandOutput> {
        self.finish_with_timeout(descendants_were_closed, PROCESS_REAP_TIMEOUT)
    }

    fn finish_with_timeout(
        self,
        descendants_were_closed: bool,
        reap_timeout: Duration,
    ) -> std::io::Result<CapturedCommandOutput> {
        self.finish_with_timeout_and_quiet_threshold_hook(
            descendants_were_closed,
            reap_timeout,
            None,
        )
    }

    fn finish_with_timeout_and_quiet_threshold_hook(
        mut self,
        descendants_were_closed: bool,
        reap_timeout: Duration,
        mut quiet_threshold_hook: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> std::io::Result<CapturedCommandOutput> {
        let join_deadline = Instant::now() + reap_timeout;
        let mut quiescence_error = None;
        if descendants_were_closed {
            while !self.both_done()? && Instant::now() < join_deadline {
                std::thread::sleep(POLL_INTERVAL);
            }
        } else {
            // The direct child has exited, so every byte it wrote is already
            // visible to the pipe. Require each live reader to perform a
            // post-exit empty/EOF probe before a quiet prefix can authorize
            // cancellation. A data read is not enough: more bytes may remain
            // in the pipe if the reader is descheduled between chunks. Under
            // runner saturation a reader thread may not have been scheduled
            // at all during the old fixed quiet window; cancelling it then
            // returned a successful command with incomplete stdout and
            // converted a harness race into a product assertion.
            let initial_stdout = self.stdout.snapshot()?;
            let initial_stderr = self.stderr.snapshot()?;
            self.stdout.post_exit.store(true, Ordering::Release);
            self.stderr.post_exit.store(true, Ordering::Release);
            let deadline = Instant::now() + reap_timeout;
            let mut prior = (initial_stdout.observed_bytes, initial_stderr.observed_bytes);
            let mut quiet_since = None;
            let mut quiet_probe_baseline: Option<(u64, u64)> = None;
            loop {
                let stdout = self.stdout.snapshot()?;
                let stderr = self.stderr.snapshot()?;
                if stdout.done && stderr.done {
                    break;
                }
                if Instant::now() >= deadline {
                    quiescence_error = Some(std::io::Error::other(
                        "bounded command capture readers did not observe post-exit pipe quiescence",
                    ));
                    break;
                }
                let both_probed_after_exit = (initial_stdout.done
                    || stdout.done
                    || stdout.post_exit_empty_read_attempts
                        > initial_stdout.post_exit_empty_read_attempts)
                    && (initial_stderr.done
                        || stderr.done
                        || stderr.post_exit_empty_read_attempts
                            > initial_stderr.post_exit_empty_read_attempts);
                if !both_probed_after_exit {
                    std::thread::sleep(POLL_INTERVAL);
                    continue;
                }

                let current = (stdout.observed_bytes, stderr.observed_bytes);
                if current != prior {
                    prior = current;
                    quiet_since = Some(Instant::now());
                    quiet_probe_baseline = None;
                } else {
                    let now = Instant::now();
                    if quiet_since.is_none() {
                        quiet_since = Some(now);
                        quiet_probe_baseline = None;
                    }
                    let quiet_since = quiet_since.expect("quiet interval was initialized");
                    if now >= quiet_since + PROCESS_QUIESCENCE {
                        if let Some(hook) = quiet_threshold_hook.take() {
                            let _ = hook.send(());
                        }
                        if let Some(probe_baseline) = quiet_probe_baseline {
                            // A reader can be descheduled for the whole quiet
                            // interval after its first empty probe. Require a
                            // fresh empty/EOF observation after the far side
                            // of the interval so queued pipe bytes cannot be
                            // mistaken for quiescence merely because the
                            // reader did not run.
                            let stdout_reprobed = stdout.done
                                || stdout.post_exit_empty_read_attempts > probe_baseline.0;
                            let stderr_reprobed = stderr.done
                                || stderr.post_exit_empty_read_attempts > probe_baseline.1;
                            if stdout_reprobed && stderr_reprobed {
                                break;
                            }
                        } else {
                            quiet_probe_baseline = Some((
                                stdout.post_exit_empty_read_attempts,
                                stderr.post_exit_empty_read_attempts,
                            ));
                        }
                    }
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        self.stdout
            .cancel_and_join_until(Instant::now() + reap_timeout)?;
        self.stderr
            .cancel_and_join_until(Instant::now() + reap_timeout)?;

        if let Some(error) = quiescence_error {
            return Err(error);
        }

        let output = CapturedCommandOutput {
            stdout: self.stdout.snapshot()?,
            stderr: self.stderr.snapshot()?,
        };
        if let Some(error) = output
            .stdout
            .error
            .as_ref()
            .or(output.stderr.error.as_ref())
        {
            return Err(std::io::Error::other(format!(
                "bounded command capture failed: {error}"
            )));
        }
        Ok(output)
    }

    fn both_done(&self) -> std::io::Result<bool> {
        Ok(self.stdout.snapshot()?.done && self.stderr.snapshot()?.done)
    }
}

impl CommandCaptureReader {
    fn spawn(
        stream: impl CommandCapturePipe,
        name: &'static str,
        overflowed: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        stream.prepare_nonblocking()?;
        let state = Arc::new(Mutex::new(CapturedCommandStream::default()));
        let reader_state = state.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancel.clone();
        let post_exit = Arc::new(AtomicBool::new(false));
        let reader_post_exit = post_exit.clone();
        let thread = std::thread::Builder::new()
            .name(format!("kin-integration-{name}-capture"))
            .spawn(move || {
                drain_command_stream(
                    stream,
                    &reader_state,
                    &overflowed,
                    &reader_cancel,
                    &reader_post_exit,
                );
            })?;
        Ok(Self {
            name,
            state,
            thread: Some(thread),
            cancel,
            post_exit,
        })
    }

    fn snapshot(&self) -> std::io::Result<CapturedCommandStream> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| std::io::Error::other("bounded command capture state was poisoned"))
    }

    fn cancel_and_join_until(&mut self, deadline: Instant) -> std::io::Result<()> {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        while !self.snapshot()?.done {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(format!(
                    "{} capture reader ignored cancellation past its deadline",
                    self.name
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| {
                std::io::Error::other(format!("{} capture thread panicked", self.name))
            })?;
        }
        Ok(())
    }
}

impl Drop for CommandCaptureReader {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        let deadline = Instant::now() + POLL_INTERVAL.saturating_mul(4);
        while self.snapshot().is_ok_and(|state| !state.done) && Instant::now() < deadline {
            std::thread::sleep(POLL_INTERVAL);
        }
        if self.snapshot().is_ok_and(|state| state.done) {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

enum CommandCaptureRead {
    Data(usize),
    Pending,
    Eof,
}

trait CommandCapturePipe: Read + Send + 'static {
    fn prepare_nonblocking(&self) -> std::io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead>;
}

macro_rules! impl_command_capture_pipe {
    ($pipe:ty) => {
        impl CommandCapturePipe for $pipe {
            fn prepare_nonblocking(&self) -> std::io::Result<()> {
                prepare_command_capture_pipe(self)
            }

            fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead> {
                read_command_capture_pipe(self, buffer)
            }
        }
    };
}

impl_command_capture_pipe!(std::process::ChildStdout);
impl_command_capture_pipe!(std::process::ChildStderr);

impl CommandCapturePipe for std::io::Cursor<Vec<u8>> {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead> {
        match self.read(buffer)? {
            0 => Ok(CommandCaptureRead::Eof),
            read => Ok(CommandCaptureRead::Data(read)),
        }
    }
}

#[cfg(unix)]
fn prepare_command_capture_pipe(
    pipe: &(impl std::os::fd::AsRawFd + ?Sized),
) -> std::io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn read_command_capture_pipe(
    pipe: &mut impl Read,
    buffer: &mut [u8],
) -> std::io::Result<CommandCaptureRead> {
    match pipe.read(buffer) {
        Ok(0) => Ok(CommandCaptureRead::Eof),
        Ok(read) => Ok(CommandCaptureRead::Data(read)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(CommandCaptureRead::Pending)
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn prepare_command_capture_pipe(
    _pipe: &(impl std::os::windows::io::AsRawHandle + ?Sized),
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_command_capture_pipe(
    pipe: &mut (impl Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> std::io::Result<CommandCaptureRead> {
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let mut available = 0_u32;
    let peeked = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if peeked == 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => {
                Ok(CommandCaptureRead::Eof)
            }
            _ => Err(error),
        };
    }
    if available == 0 {
        return Ok(CommandCaptureRead::Pending);
    }
    let request = buffer
        .len()
        .min(usize::try_from(available).unwrap_or(usize::MAX));
    match pipe.read(&mut buffer[..request]) {
        Ok(0) => Ok(CommandCaptureRead::Eof),
        Ok(read) => Ok(CommandCaptureRead::Data(read)),
        Err(error)
            if error.kind() == std::io::ErrorKind::BrokenPipe
                || matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) =>
        {
            Ok(CommandCaptureRead::Eof)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
fn prepare_command_capture_pipe<T: ?Sized>(_pipe: &T) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_command_capture_pipe(
    pipe: &mut impl Read,
    buffer: &mut [u8],
) -> std::io::Result<CommandCaptureRead> {
    match pipe.read(buffer)? {
        0 => Ok(CommandCaptureRead::Eof),
        read => Ok(CommandCaptureRead::Data(read)),
    }
}

fn drain_command_stream(
    mut stream: impl CommandCapturePipe,
    state: &Arc<Mutex<CapturedCommandStream>>,
    overflowed: &Arc<AtomicBool>,
    cancel: &Arc<AtomicBool>,
    post_exit: &Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let read_started_after_exit = post_exit.load(Ordering::Acquire);
        match stream.read_available(&mut buffer) {
            Ok(CommandCaptureRead::Eof) => {
                let Ok(mut state) = state.lock() else {
                    return;
                };
                if read_started_after_exit {
                    state.post_exit_empty_read_attempts =
                        state.post_exit_empty_read_attempts.saturating_add(1);
                }
                break;
            }
            Ok(CommandCaptureRead::Pending) => {
                let Ok(mut state) = state.lock() else {
                    return;
                };
                if read_started_after_exit {
                    state.post_exit_empty_read_attempts =
                        state.post_exit_empty_read_attempts.saturating_add(1);
                }
                drop(state);
                std::thread::park_timeout(POLL_INTERVAL);
            }
            Ok(CommandCaptureRead::Data(read)) => {
                let Ok(mut state) = state.lock() else {
                    return;
                };
                state.observed_bytes = state.observed_bytes.saturating_add(read as u64);
                let remaining = COMMAND_CAPTURE_LIMIT.saturating_sub(state.bytes.len());
                state
                    .bytes
                    .extend_from_slice(&buffer[..read.min(remaining)]);
                if read > remaining {
                    state.truncated = true;
                    overflowed.store(true, Ordering::Release);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                if let Ok(mut state) = state.lock() {
                    state.error = Some(error.to_string());
                }
                break;
            }
        }
    }
    if let Ok(mut state) = state.lock() {
        state.done = true;
    }
}

struct NeverEofCommandCapturePipe;

impl Read for NeverEofCommandCapturePipe {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl CommandCapturePipe for NeverEofCommandCapturePipe {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, _buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead> {
        Ok(CommandCaptureRead::Pending)
    }
}

struct GatedTwoChunkCommandCapturePipe {
    stage: u8,
    first_attempt_entered: std::sync::mpsc::SyncSender<()>,
    release_pre_exit_pending: std::sync::mpsc::Receiver<()>,
    release_first_chunk: std::sync::mpsc::Receiver<()>,
    release_second_chunk: std::sync::mpsc::Receiver<()>,
    cancel: Arc<AtomicBool>,
}

impl Read for GatedTwoChunkCommandCapturePipe {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "gated command capture must use read_available",
        ))
    }
}

impl CommandCapturePipe for GatedTwoChunkCommandCapturePipe {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead> {
        let chunk = match self.stage {
            0 => {
                self.first_attempt_entered
                    .send(())
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                self.release_pre_exit_pending
                    .recv()
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                self.stage = 1;
                return Ok(CommandCaptureRead::Pending);
            }
            1 => {
                self.release_first_chunk
                    .recv()
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                if self.cancel.load(Ordering::Acquire) {
                    return Ok(CommandCaptureRead::Pending);
                }
                b"first chunk ".as_slice()
            }
            2 => {
                self.release_second_chunk
                    .recv()
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                if self.cancel.load(Ordering::Acquire) {
                    return Ok(CommandCaptureRead::Pending);
                }
                b"second chunk".as_slice()
            }
            _ => return Ok(CommandCaptureRead::Pending),
        };
        self.stage = self.stage.saturating_add(1);
        buffer[..chunk.len()].copy_from_slice(chunk);
        Ok(CommandCaptureRead::Data(chunk.len()))
    }
}

struct ContinuousAfterPostExitQuiescencePipe {
    post_exit_pending_observations: u8,
    post_exit: Arc<AtomicBool>,
    before_continuous_data: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}

impl Read for ContinuousAfterPostExitQuiescencePipe {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "continuous command capture must use read_available",
        ))
    }
}

impl CommandCapturePipe for ContinuousAfterPostExitQuiescencePipe {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<CommandCaptureRead> {
        if self.post_exit_pending_observations < 2 {
            if self.post_exit.load(Ordering::Acquire) {
                self.post_exit_pending_observations =
                    self.post_exit_pending_observations.saturating_add(1);
            }
            return Ok(CommandCaptureRead::Pending);
        }
        if let Some((entered, release)) = self.before_continuous_data.take() {
            entered.send(()).map_err(|_| {
                std::io::Error::other("continuous capture gate observer was dropped")
            })?;
            release.recv().map_err(|_| {
                std::io::Error::other("continuous capture gate release was dropped")
            })?;
        }
        std::thread::sleep(Duration::from_millis(1));
        buffer[0] = b'x';
        Ok(CommandCaptureRead::Data(1))
    }
}

#[test]
fn bounded_command_capture_sink_never_retains_past_the_ceiling() {
    let state = Arc::new(Mutex::new(CapturedCommandStream::default()));
    let overflowed = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    let post_exit = Arc::new(AtomicBool::new(false));
    let input = vec![b'x'; COMMAND_CAPTURE_LIMIT + 16 * 1024];
    drain_command_stream(
        std::io::Cursor::new(input),
        &state,
        &overflowed,
        &cancel,
        &post_exit,
    );
    let captured = state.lock().expect("capture state").clone();

    assert_eq!(captured.bytes.len(), COMMAND_CAPTURE_LIMIT);
    assert_eq!(
        captured.observed_bytes,
        (COMMAND_CAPTURE_LIMIT + 16 * 1024) as u64
    );
    assert!(captured.truncated);
    assert!(captured.done);
    assert!(overflowed.load(Ordering::Acquire));
    assert!(compact_command_capture(&captured).len() <= COMMAND_DIAGNOSTIC_LIMIT);
}

#[test]
fn compact_command_capture_hard_bounds_invalid_utf8_after_lossy_expansion() {
    let captured = CapturedCommandStream {
        bytes: vec![0xff; COMMAND_DIAGNOSTIC_LIMIT],
        observed_bytes: COMMAND_DIAGNOSTIC_LIMIT as u64,
        ..CapturedCommandStream::default()
    };
    let diagnostic = compact_command_capture(&captured);

    assert!(diagnostic.len() <= COMMAND_DIAGNOSTIC_LIMIT);
    assert!(diagnostic.ends_with(COMMAND_DIAGNOSTIC_MARKER));
    assert!(diagnostic.contains('\u{FFFD}'));
}

#[test]
fn failed_cleanup_output_is_hard_bounded_after_lossy_expansion() {
    let invalid = vec![0xff; COMMAND_CAPTURE_LIMIT];
    let diagnostic = render_failed_cleanup_output("exit status: 1", &invalid, &invalid);

    assert!(diagnostic.contains("isolated daemon cleanup failed with exit status: 1"));
    assert_eq!(
        diagnostic.matches(COMMAND_DIAGNOSTIC_MARKER).count(),
        2,
        "both cleanup streams should disclose truncation"
    );
    assert!(
        diagnostic.len() <= COMMAND_DIAGNOSTIC_LIMIT * 2 + 128,
        "cleanup diagnostic expanded past the two bounded streams: {} bytes",
        diagnostic.len()
    );
}

#[test]
fn never_eof_command_capture_is_cancelled_and_joined() {
    let mut reader = CommandCaptureReader::spawn(
        NeverEofCommandCapturePipe,
        "never-eof",
        Arc::new(AtomicBool::new(false)),
    )
    .expect("start never-EOF command capture");
    let started = Instant::now();
    reader
        .cancel_and_join_until(Instant::now() + Duration::from_secs(1))
        .expect("cancel never-EOF command capture");

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "never-EOF capture exceeded its cancellation deadline"
    );
    assert!(reader.snapshot().expect("capture snapshot").done);
}

#[test]
fn bounded_capture_waits_for_a_post_exit_reader_probe() {
    let stdout_state = Arc::new(Mutex::new(CapturedCommandStream::default()));
    let stdout_reader_state = stdout_state.clone();
    let stdout_cancel = Arc::new(AtomicBool::new(false));
    let stdout_reader_cancel = stdout_cancel.clone();
    let stdout_post_exit = Arc::new(AtomicBool::new(false));
    let stdout_reader_post_exit = stdout_post_exit.clone();
    let overflowed = Arc::new(AtomicBool::new(false));
    let stdout_overflowed = overflowed.clone();
    let (release, wait_for_release) = std::sync::mpsc::sync_channel(0);
    let stdout_thread = std::thread::Builder::new()
        .name("kin-integration-delayed-stdout-capture".to_string())
        .spawn(move || {
            wait_for_release.recv().expect("release delayed reader");
            drain_command_stream(
                std::io::Cursor::new(b"late direct-child output".to_vec()),
                &stdout_reader_state,
                &stdout_overflowed,
                &stdout_reader_cancel,
                &stdout_reader_post_exit,
            );
        })
        .expect("spawn delayed stdout reader");
    let stdout = CommandCaptureReader {
        name: "stdout",
        state: stdout_state,
        thread: Some(stdout_thread),
        cancel: stdout_cancel,
        post_exit: stdout_post_exit,
    };
    let stderr =
        CommandCaptureReader::spawn(NeverEofCommandCapturePipe, "stderr", overflowed.clone())
            .expect("start never-EOF stderr reader");
    let release_thread = std::thread::spawn(move || {
        std::thread::sleep(PROCESS_QUIESCENCE.saturating_mul(2));
        release.send(()).expect("release delayed stdout reader");
    });

    let captured = BoundedCommandCapture {
        stdout,
        stderr,
        overflowed,
    }
    .finish(false)
    .expect("finish delayed post-exit capture");
    release_thread.join().expect("join delayed-reader release");

    assert_eq!(captured.stdout.bytes, b"late direct-child output");
}

#[test]
fn bounded_capture_requires_post_exit_pipe_quiescence_after_data() {
    let stdout_state = Arc::new(Mutex::new(CapturedCommandStream::default()));
    let stdout_reader_state = stdout_state.clone();
    let stdout_cancel = Arc::new(AtomicBool::new(false));
    let stdout_reader_cancel = stdout_cancel.clone();
    let stdout_post_exit = Arc::new(AtomicBool::new(false));
    let stdout_reader_post_exit = stdout_post_exit.clone();
    let overflowed = Arc::new(AtomicBool::new(false));
    let stdout_overflowed = overflowed.clone();
    let (entered_first_attempt, wait_for_first_attempt) = std::sync::mpsc::sync_channel(0);
    let (release_pre_exit_pending, wait_for_pre_exit_pending) = std::sync::mpsc::sync_channel(0);
    let (release_first_chunk, wait_for_first_chunk) = std::sync::mpsc::sync_channel(0);
    let (release_second_chunk, wait_for_second_chunk) = std::sync::mpsc::sync_channel(0);
    let stdout_thread = std::thread::Builder::new()
        .name("kin-integration-gated-stdout-capture".to_string())
        .spawn(move || {
            drain_command_stream(
                GatedTwoChunkCommandCapturePipe {
                    stage: 0,
                    first_attempt_entered: entered_first_attempt,
                    release_pre_exit_pending: wait_for_pre_exit_pending,
                    release_first_chunk: wait_for_first_chunk,
                    release_second_chunk: wait_for_second_chunk,
                    cancel: stdout_reader_cancel.clone(),
                },
                &stdout_reader_state,
                &stdout_overflowed,
                &stdout_reader_cancel,
                &stdout_reader_post_exit,
            );
        })
        .expect("spawn gated stdout reader");
    let stdout = CommandCaptureReader {
        name: "stdout",
        state: stdout_state,
        thread: Some(stdout_thread),
        cancel: stdout_cancel,
        post_exit: stdout_post_exit,
    };
    wait_for_first_attempt
        .recv()
        .expect("stdout reader entered its pre-exit probe");
    let stderr =
        CommandCaptureReader::spawn(NeverEofCommandCapturePipe, "stderr", overflowed.clone())
            .expect("start never-EOF stderr reader");
    let release_thread = std::thread::spawn(move || {
        std::thread::sleep(PROCESS_QUIESCENCE.saturating_mul(2));
        release_pre_exit_pending
            .send(())
            .expect("release pre-exit pending probe");
        std::thread::sleep(PROCESS_QUIESCENCE.saturating_mul(2));
        release_first_chunk
            .send(())
            .expect("release first stdout chunk");
        std::thread::sleep(PROCESS_QUIESCENCE.saturating_mul(2));
        release_second_chunk
            .send(())
            .expect("release second stdout chunk");
    });

    let captured = BoundedCommandCapture {
        stdout,
        stderr,
        overflowed,
    }
    .finish(false)
    .expect("finish gated post-exit capture");
    release_thread.join().expect("join gated-reader release");

    assert_eq!(captured.stdout.bytes, b"first chunk second chunk");
}

pub(super) fn bounded_capture_deadline_cannot_be_bypassed_by_continuous_output() {
    let stdout_state = Arc::new(Mutex::new(CapturedCommandStream::default()));
    let stdout_reader_state = stdout_state.clone();
    let stdout_cancel = Arc::new(AtomicBool::new(false));
    let stdout_reader_cancel = stdout_cancel.clone();
    let stdout_post_exit = Arc::new(AtomicBool::new(false));
    let stdout_reader_post_exit = stdout_post_exit.clone();
    let stdout_pipe_post_exit = stdout_post_exit.clone();
    let overflowed = Arc::new(AtomicBool::new(false));
    let stdout_overflowed = overflowed.clone();
    let (entered_continuous_data, wait_for_continuous_data) = std::sync::mpsc::sync_channel(0);
    let (release_continuous_data, wait_for_continuous_data_release) =
        std::sync::mpsc::sync_channel(0);
    let (crossed_quiet_threshold, wait_for_quiet_threshold) = std::sync::mpsc::sync_channel(0);
    let stdout_thread = std::thread::Builder::new()
        .name("kin-integration-continuous-stdout-capture".to_string())
        .spawn(move || {
            drain_command_stream(
                ContinuousAfterPostExitQuiescencePipe {
                    post_exit_pending_observations: 0,
                    post_exit: stdout_pipe_post_exit,
                    before_continuous_data: Some((
                        entered_continuous_data,
                        wait_for_continuous_data_release,
                    )),
                },
                &stdout_reader_state,
                &stdout_overflowed,
                &stdout_reader_cancel,
                &stdout_reader_post_exit,
            );
        })
        .expect("spawn continuous stdout reader");
    let stdout = CommandCaptureReader {
        name: "stdout",
        state: stdout_state,
        thread: Some(stdout_thread),
        cancel: stdout_cancel,
        post_exit: stdout_post_exit,
    };
    let stderr =
        CommandCaptureReader::spawn(NeverEofCommandCapturePipe, "stderr", overflowed.clone())
            .expect("start never-EOF stderr reader");
    let watchdog_stdout_cancel = stdout.cancel.clone();
    let watchdog_stderr_cancel = stderr.cancel.clone();
    let watchdog_stdout_thread = stdout
        .thread
        .as_ref()
        .expect("live stdout capture thread")
        .thread()
        .clone();
    let watchdog_stderr_thread = stderr
        .thread
        .as_ref()
        .expect("live stderr capture thread")
        .thread()
        .clone();
    let started = Instant::now();
    let release_thread = std::thread::spawn(move || {
        wait_for_continuous_data
            .recv_timeout(Duration::from_secs(2))
            .expect("reader reached the continuous-data gate within its deadline");
        wait_for_quiet_threshold
            .recv_timeout(Duration::from_secs(2))
            .expect("capture coordinator crossed the quiet threshold");
        release_continuous_data
            .send(())
            .expect("release continuous data");
    });
    let capture = BoundedCommandCapture {
        stdout,
        stderr,
        overflowed,
    };
    let (finish_result_tx, finish_result_rx) = std::sync::mpsc::sync_channel(1);
    let finish_thread = std::thread::spawn(move || {
        let result = capture.finish_with_timeout_and_quiet_threshold_hook(
            false,
            Duration::from_secs(3),
            Some(crossed_quiet_threshold),
        );
        let _ = finish_result_tx.send(result);
    });
    let finish_result = match finish_result_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => {
            finish_thread.join().expect("join bounded capture finish");
            result
        }
        Err(timeout) => {
            watchdog_stdout_cancel.store(true, Ordering::Release);
            watchdog_stderr_cancel.store(true, Ordering::Release);
            watchdog_stdout_thread.unpark();
            watchdog_stderr_thread.unpark();
            let cleanup = finish_result_rx.recv_timeout(Duration::from_secs(1));
            if cleanup.is_ok() {
                finish_thread
                    .join()
                    .expect("join watchdog-released capture finish");
            }
            panic!(
                "continuous output hung the bounded capture finish; \
                 watchdog_result={timeout}; cleanup_result={cleanup:?}"
            );
        }
    };
    release_thread
        .join()
        .expect("join continuous-data gate release");
    let error = finish_result
        .expect_err("continuous descendant output must not bypass the capture deadline");

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "continuous output bypassed the bounded capture deadline"
    );
    assert!(
        error.to_string().contains("post-exit pipe quiescence"),
        "{error}"
    );
}

fn compact_command_capture(stream: &CapturedCommandStream) -> String {
    compact_command_bytes(&stream.bytes, stream.truncated)
}

fn compact_command_bytes(bytes: &[u8], already_truncated: bool) -> String {
    let prefix = &bytes[..bytes.len().min(COMMAND_DIAGNOSTIC_LIMIT)];
    let lossy = String::from_utf8_lossy(prefix);
    let needs_marker = already_truncated
        || bytes.len() > COMMAND_DIAGNOSTIC_LIMIT
        || lossy.len() > COMMAND_DIAGNOSTIC_LIMIT;
    let content_budget = if needs_marker {
        COMMAND_DIAGNOSTIC_LIMIT.saturating_sub(COMMAND_DIAGNOSTIC_MARKER.len())
    } else {
        COMMAND_DIAGNOSTIC_LIMIT
    };
    let mut content_end = lossy.len().min(content_budget);
    while !lossy.is_char_boundary(content_end) {
        content_end -= 1;
    }
    let mut rendered = lossy[..content_end].to_owned();
    if needs_marker {
        rendered.push_str(COMMAND_DIAGNOSTIC_MARKER);
    }
    debug_assert!(rendered.len() <= COMMAND_DIAGNOSTIC_LIMIT);
    rendered
}

fn render_failed_cleanup_output(status: &str, stdout: &[u8], stderr: &[u8]) -> String {
    format!(
        "isolated daemon cleanup failed with {status}: stdout={} stderr={}",
        compact_command_bytes(stdout, false),
        compact_command_bytes(stderr, false)
    )
}

fn command_output_from_capture(
    status: ExitStatus,
    capture: CapturedCommandOutput,
    label: &str,
) -> std::io::Result<Output> {
    if capture.stdout.truncated || capture.stderr.truncated {
        return Err(std::io::Error::other(format!(
            "{label} exceeded the {COMMAND_CAPTURE_LIMIT}-byte per-stream capture limit \
             (stdout={}, stderr={}); stdout={} stderr={}",
            capture.stdout.observed_bytes,
            capture.stderr.observed_bytes,
            compact_command_capture(&capture.stdout),
            compact_command_capture(&capture.stderr)
        )));
    }
    Ok(Output {
        status,
        stdout: capture.stdout.bytes,
        stderr: capture.stderr.bytes,
    })
}

fn render_command_captures(capture: &CapturedCommandOutput) -> String {
    format!(
        "stdout={} stderr={}",
        compact_command_capture(&capture.stdout),
        compact_command_capture(&capture.stderr)
    )
}

fn run_bounded_within(
    mut command: std::process::Command,
    label: &str,
    runtime: Option<&IsolatedDaemonRuntime>,
    readiness: Option<(&Path, Duration)>,
    timeout: Duration,
) -> std::io::Result<Output> {
    BoundedCommandCapture::configure(&mut command);
    let runtime_containment = runtime.map(|runtime| &runtime.containment);

    let (mut child, mut command_containment) = match runtime_containment {
        Some(containment) => (containment.spawn(command, label)?, None),
        None => {
            let (child, containment) = CommandContainment::spawn(command, label)?;
            (child, Some(containment))
        }
    };
    let mut capture = Some(match BoundedCommandCapture::start(&mut child, label) {
        Ok(capture) => capture,
        Err(error) => {
            let cleanup =
                terminate_spawned_process(child, label, command_containment.as_mut(), runtime);
            return Err(std::io::Error::other(format!(
                "initialize bounded capture for {label}: {error}; cleanup={cleanup:?}"
            )));
        }
    });
    if let Some((ready_path, readiness_timeout)) = readiness {
        let readiness_deadline = Instant::now() + readiness_timeout;
        while !ready_path.is_file() {
            if capture
                .as_ref()
                .is_some_and(BoundedCommandCapture::overflowed)
            {
                let cleanup =
                    terminate_spawned_process(child, label, command_containment.as_mut(), runtime);
                let captured = capture
                    .take()
                    .expect("capture remains owned")
                    .finish(cleanup.is_ok())?;
                return Err(std::io::Error::other(format!(
                    "{label} exceeded the {COMMAND_CAPTURE_LIMIT}-byte per-stream capture limit \
                     before readiness (stdout={}, stderr={}); cleanup={cleanup:?}; {}",
                    captured.stdout.observed_bytes,
                    captured.stderr.observed_bytes,
                    render_command_captures(&captured)
                )));
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    let descendants_closed = command_containment.is_some();
                    if let Some(containment) = command_containment.as_mut() {
                        containment.terminate_and_confirm().map_err(|error| {
                            std::io::Error::other(format!(
                                "clean descendants after {label} exited before readiness: {error}"
                            ))
                        })?;
                    }
                    let captured = capture
                        .take()
                        .expect("capture remains owned")
                        .finish(descendants_closed)?;
                    return command_output_from_capture(status, captured, label);
                }
                Ok(None) if Instant::now() < readiness_deadline => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Ok(None) => {
                    let cleanup = terminate_spawned_process(
                        child,
                        label,
                        command_containment.as_mut(),
                        runtime,
                    );
                    let captured = capture
                        .take()
                        .expect("capture remains owned")
                        .finish(cleanup.is_ok())
                        .map(|captured| render_command_captures(&captured))
                        .unwrap_or_else(|error| format!("capture-error={error}"));
                    panic!(
                        "{label} did not publish readiness at {} within {readiness_timeout:?}; cleanup={cleanup:?}; {captured}",
                        ready_path.display(),
                    );
                }
                Err(error) => {
                    let cleanup = terminate_spawned_process(
                        child,
                        label,
                        command_containment.as_mut(),
                        runtime,
                    );
                    let captured = capture
                        .take()
                        .expect("capture remains owned")
                        .finish(cleanup.is_ok())
                        .map(|captured| render_command_captures(&captured))
                        .unwrap_or_else(|capture_error| format!("capture-error={capture_error}"));
                    return Err(std::io::Error::other(format!(
                        "{error}; cleanup={cleanup:?}; {captured}"
                    )));
                }
            }
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        if capture
            .as_ref()
            .is_some_and(BoundedCommandCapture::overflowed)
        {
            let cleanup =
                terminate_spawned_process(child, label, command_containment.as_mut(), runtime);
            let captured = capture
                .take()
                .expect("capture remains owned")
                .finish(cleanup.is_ok())?;
            return Err(std::io::Error::other(format!(
                "{label} exceeded the {COMMAND_CAPTURE_LIMIT}-byte per-stream capture limit \
                 (stdout={}, stderr={}); cleanup={cleanup:?}; {}",
                captured.stdout.observed_bytes,
                captured.stderr.observed_bytes,
                render_command_captures(&captured)
            )));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let descendants_closed = command_containment.is_some();
                if let Some(containment) = command_containment.as_mut() {
                    containment.terminate_and_confirm().map_err(|error| {
                        std::io::Error::other(format!(
                            "clean descendants after {label} exited: {error}"
                        ))
                    })?;
                }
                let captured = capture
                    .take()
                    .expect("capture remains owned")
                    .finish(descendants_closed)?;
                return command_output_from_capture(status, captured, label);
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let cleanup =
                    terminate_spawned_process(child, label, command_containment.as_mut(), runtime);
                let captured = capture
                    .take()
                    .expect("capture remains owned")
                    .finish(cleanup.is_ok())
                    .map(|captured| render_command_captures(&captured))
                    .unwrap_or_else(|error| format!("capture-error={error}"));
                panic!("{label} did not exit within {timeout:?}; cleanup={cleanup:?}; {captured}");
            }
            Err(error) => {
                let cleanup =
                    terminate_spawned_process(child, label, command_containment.as_mut(), runtime);
                let captured = capture
                    .take()
                    .expect("capture remains owned")
                    .finish(cleanup.is_ok())
                    .map(|captured| render_command_captures(&captured))
                    .unwrap_or_else(|capture_error| format!("capture-error={capture_error}"));
                return Err(std::io::Error::other(format!(
                    "{error}; cleanup={cleanup:?}; {captured}"
                )));
            }
        }
    }
}

fn confirm_containment_empty_dyn(
    containment: &dyn ProcessContainment,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        match containment.is_empty() {
            Ok(true) => return Ok(()),
            Ok(false) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(false) => return Err("test process containment remained live".to_string()),
            Err(error) => return Err(format!("inspect test process containment: {error}")),
        }
    }
}

fn poll_child_until(
    child: &mut Child,
    deadline: Instant,
    label: &str,
) -> Result<Option<ExitStatus>, String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => return Ok(None),
            Err(error) => return Err(format!("reap {label}: {error}")),
        }
    }
}

fn terminate_spawned_process(
    mut child: Child,
    label: &str,
    mut command_containment: Option<&mut CommandContainment>,
    runtime: Option<&IsolatedDaemonRuntime>,
) -> Result<(), String> {
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    let runtime_containment = runtime.map(|runtime| &runtime.containment);
    let containment = command_containment
        .as_deref()
        .map(|tree| tree as &dyn ProcessContainment)
        .or_else(|| runtime_containment.map(|tree| tree as &dyn ProcessContainment));
    let containment_termination = containment.and_then(|tree| tree.terminate().err());
    let direct_kill = child.kill().err();
    let direct_reap = poll_child_until(&mut child, deadline, label);
    let direct_reap_succeeded = matches!(&direct_reap, Ok(Some(_)));
    // A command-scoped containment can be finalized as soon as its one direct
    // child is reaped. A shared runtime containment cannot: its owning runtime
    // must first reap every registered direct child before the guardian's
    // irreversible final proof.
    let containment_quiescence = match (command_containment.is_some(), direct_reap_succeeded) {
        (true, true) => containment.map(|tree| confirm_containment_empty_dyn(tree, deadline)),
        (true, false) => Some(Err(
            "command containment final proof skipped because the direct child was not reaped"
                .to_string(),
        )),
        (false, _) => None,
    };
    let failed_reap_retention = if direct_reap_succeeded {
        None
    } else if let Some(command_containment) = command_containment.as_deref_mut() {
        Some(command_containment.retain_unreaped_child(child, label.to_string()))
    } else if let Some(runtime) = runtime {
        Some(runtime.retain_unreaped_direct_child(child, label.to_string()))
    } else {
        std::mem::forget(child);
        Some(Err(
            "unreaped uncontained direct child handle intentionally leaked".to_string(),
        ))
    };
    match (
        containment_termination,
        direct_kill,
        direct_reap,
        containment_quiescence,
        failed_reap_retention,
    ) {
        (None, None, Ok(Some(_)), None | Some(Ok(())), None) => Ok(()),
        (termination, kill, reap, quiescence, retention) => Err(format!(
            "{label} cleanup failed: containment termination={termination:?}; direct kill={kill:?}; direct reap={reap:?}; containment quiescence={quiescence:?}; failed-reap retention={retention:?}"
        )),
    }
}

/// The build identity this test binary carries, joined the way
/// `kin_buildinfo::sha_with_dirty` joins it.
///
/// This is a harness-local identity for pairing a test binary with a daemon
/// built beside it. It is deliberately NOT what the daemon stamps persisted
/// vector sidecars with: keying index reuse on a build SHA is what made every
/// Kin upgrade discard the user's whole index, and the sidecar now carries the
/// embedding runtime's own identity instead.
pub fn expected_build_stamp() -> String {
    kin_buildinfo::sha_with_dirty(kin_buildinfo::get())
}

/// Recompose a `--compat-json` `build.sha` / `build.dirty` pair into the stamp
/// `kin_buildinfo::sha_with_dirty` would produce for the same build.
///
/// The daemon reports the two fields separately, so the harness has to join
/// them the same way rather than comparing the pair directly: when the commit
/// is unknown the dirty flag is not part of the identity, and a raw pair
/// comparison would reject a daemon that actually matches.
fn build_stamp(sha: &str, dirty: bool) -> String {
    if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.to_string()
    }
}

/// Why a candidate `kin-daemon` may not be reused by this test binary, or
/// `None` when it may be.
///
/// Two independent reasons. A daemon whose graph snapshot version differs
/// cannot read the repository at all. A daemon built from a *different commit
/// or working tree* reads it fine, but the CLI/daemon HTTP surface between them
/// is versioned by nothing except being built together, so a mixed pair out of
/// one target directory is not a configuration any release ships and not one a
/// failure should be attributed to.
///
/// It is no longer true that such a pair disagrees about persisted vector
/// sidecars. That WAS this gate's second reason, and it was the product defect
/// showing through the harness: a differently-built daemon rejected a seeded
/// sidecar, `indexed_embedding_count` read 0, and the suite reported a defect
/// the harness then worked around. Index reuse no longer keys on a build SHA,
/// so a mixed pair reuses the index just as a user's upgrade now does.
pub fn daemon_compat_mismatch(
    payload: &Value,
    expected_snapshot_version: u64,
    expected_stamp: &str,
) -> Option<String> {
    match payload["graph_snapshot_version"].as_u64() {
        Some(version) if version == expected_snapshot_version => {}
        Some(version) => {
            return Some(format!(
                "graph snapshot version {version} does not match this test binary's {expected_snapshot_version}"
            ));
        }
        None => return Some("compat payload has no graph_snapshot_version".to_string()),
    }

    let Some(sha) = payload["build"]["sha"].as_str() else {
        return Some("compat payload has no build.sha".to_string());
    };
    let Some(dirty) = payload["build"]["dirty"].as_bool() else {
        return Some("compat payload has no build.dirty".to_string());
    };

    let daemon_stamp = build_stamp(sha, dirty);
    if daemon_stamp != expected_stamp {
        return Some(format!(
            "daemon build identity {daemon_stamp} does not match this test binary's {expected_stamp}"
        ));
    }
    None
}

fn daemon_compat(runtime: &IsolatedDaemonRuntime, path: &Path) -> Result<(), String> {
    daemon_compat_within(runtime, path, COMMAND_TIMEOUT)
}

fn daemon_compat_within(
    runtime: &IsolatedDaemonRuntime,
    path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    let mut command = runtime.command(path);
    let output = command
        .arg("--compat-json")
        .output_within(timeout)
        .map_err(|error| format!("could not run {} --compat-json: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --compat-json exited with {}",
            path.display(),
            output.status
        ));
    }
    let payload = serde_json::from_slice::<Value>(&output.stdout).map_err(|error| {
        format!(
            "{} --compat-json did not emit JSON: {error}",
            path.display()
        )
    })?;
    match daemon_compat_mismatch(
        &payload,
        kin_db::GraphSnapshot::CURRENT_VERSION as u64,
        &expected_build_stamp(),
    ) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// The `--target` a `kin-daemon` rebuild has to carry to land beside `kin`.
///
/// Cargo writes a build to `<target-dir>/<profile>/`, and moves it to
/// `<target-dir>/<triple>/<profile>/` when it is given `--target`. The daemon
/// this harness demands sits beside `CARGO_BIN_EXE_kin`, so a rebuild that
/// drops the triple the test binary was built for writes a directory the
/// compatibility check never reads: the rebuild succeeds and the check still
/// reports the daemon missing, naming a path nothing ever wrote.
///
/// The triple is only in the path when cargo put it there, which is exactly
/// when the rebuild needs it, so the layout answers the question directly.
fn daemon_rebuild_target<'a>(kin_bin: &Path, triple: &'a str) -> Option<&'a str> {
    let profile_parent = kin_bin.parent()?.parent()?;
    (profile_parent.file_name()?.to_str() == Some(triple)).then_some(triple)
}

#[test]
fn daemon_rebuild_follows_the_layout_its_own_binary_was_written_into() {
    let triple = "x86_64-pc-windows-msvc";

    assert_eq!(
        daemon_rebuild_target(Path::new("/w/target/debug/kin"), triple),
        None,
        "a host build already writes the directory the check reads"
    );
    assert_eq!(
        daemon_rebuild_target(
            Path::new("/w/target/x86_64-pc-windows-msvc/debug/kin.exe"),
            triple
        ),
        Some(triple),
        "a cross build is only reachable by repeating its --target"
    );
    // A target directory relocated by CARGO_TARGET_DIR keeps the layout, so the
    // triple component stays the whole signal and no path prefix is assumed.
    assert_eq!(
        daemon_rebuild_target(
            Path::new("/lane/cargo-target/nwinfix/x86_64-pc-windows-msvc/debug/kin.exe"),
            triple
        ),
        Some(triple),
    );
    assert_eq!(
        daemon_rebuild_target(
            Path::new("/w/target/aarch64-apple-darwin/debug/kin"),
            triple
        ),
        None,
        "a triple this binary was not built for must never be passed on"
    );
    assert_eq!(daemon_rebuild_target(Path::new("kin"), triple), None);
}

fn fresh_daemon_bin(runtime: &IsolatedDaemonRuntime) -> PathBuf {
    fresh_daemon_bin_with_deadline(runtime, None)
}

fn fresh_daemon_bin_before(runtime: &IsolatedDaemonRuntime, deadline: Instant) -> PathBuf {
    fresh_daemon_bin_with_deadline(runtime, Some(deadline))
}

fn daemon_preparation_budget(
    deadline: Option<Instant>,
    default: Duration,
    label: &str,
) -> Duration {
    deadline
        .map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .unwrap_or_else(|| panic!("daemon preparation deadline expired before {label}"))
        })
        .unwrap_or(default)
}

fn fresh_daemon_bin_with_deadline(
    runtime: &IsolatedDaemonRuntime,
    deadline: Option<Instant>,
) -> PathBuf {
    let kin_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"));
    let daemon_bin = kin_bin.with_file_name(format!("kin-daemon{}", std::env::consts::EXE_SUFFIX));
    if daemon_compat_within(
        runtime,
        &daemon_bin,
        daemon_preparation_budget(deadline, COMMAND_TIMEOUT, "the compatibility probe"),
    )
    .is_ok()
    {
        return daemon_bin;
    }

    BUILD_DAEMON.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.ancestors().nth(2).expect("kin workspace root");
        let mut args = vec!["build", "-p", "kin-daemon", "--bin", "kin-daemon"];
        if let Some(target) = daemon_rebuild_target(&kin_bin, env!("KIN_CLI_TARGET_TRIPLE")) {
            args.extend_from_slice(&["--target", target]);
        }
        // This shells out to cargo from inside a cargo-driven test run, so it
        // contends for the build-directory lock with whatever else is building
        // this checkout. Cargo waits on that lock forever and prints only to
        // the stderr this call captures, so the wait is bounded here.
        let mut build = Command::new(env!("CARGO"));
        scrub_inherited_kin_authority(build.inner_mut());
        let output = build
            .args(&args)
            .current_dir(workspace_root)
            .output_within(daemon_preparation_budget(
                deadline,
                BUILD_TIMEOUT,
                "the fallback Cargo build",
            ))
            .expect("run cargo build -p kin-daemon");
        assert!(
            output.status.success(),
            "cargo build -p kin-daemon failed: stdout={} stderr={}",
            compact_command_bytes(&output.stdout, false),
            compact_command_bytes(&output.stderr, false)
        );
    });

    if let Err(reason) = daemon_compat_within(
        runtime,
        &daemon_bin,
        daemon_preparation_budget(deadline, COMMAND_TIMEOUT, "the final compatibility probe"),
    ) {
        panic!(
            "kin-daemon at {} is unusable after rebuild: {reason}.\n\
             This test binary carries build identity {}. A daemon built from a \
             different commit or working tree pairs with this binary over an \
             HTTP surface that nothing versions except having been built \
             together, so failures under a mixed pair are not attributable to \
             either side. Build both from one tree: cargo build --all-targets",
            daemon_bin.display(),
            expected_build_stamp()
        );
    }
    daemon_bin
}
