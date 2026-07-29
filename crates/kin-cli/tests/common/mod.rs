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
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
#[cfg(unix)]
use sysinfo::ProcessStatus;
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
const RUNTIME_OWNER_ENV: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";
const RUNTIME_CONTAINMENT_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_GUARDIAN";
const RUNTIME_CONTAINMENT_READY_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_READY";
const RUNTIME_CONTAINMENT_PARENT_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PARENT_PID";
const RUNTIME_CONTAINMENT_GROUP_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP";

#[cfg(unix)]
struct RuntimeContainment {
    process_group: libc::pid_t,
    guardian: Option<Child>,
}

#[cfg(unix)]
impl RuntimeContainment {
    fn new(runtime_root: &Path, owner_token: &str) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt as _;

        std::fs::create_dir_all(runtime_root)?;
        let ready = runtime_root.join(format!("guardian-{owner_token}.ready"));
        let mut command = std::process::Command::new(std::env::current_exe()?);
        scrub_inherited_kin_authority(&mut command);
        command
            .args([
                "--exact",
                "common::runtime_containment_guardian_worker",
                "--nocapture",
            ])
            .env(RUNTIME_CONTAINMENT_ENV, "1")
            .env(RUNTIME_CONTAINMENT_READY_ENV, &ready)
            .env(
                RUNTIME_CONTAINMENT_PARENT_ENV,
                std::process::id().to_string(),
            )
            .env(RUNTIME_OWNER_ENV, owner_token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut guardian = command.spawn()?;
        let process_group = libc::pid_t::try_from(guardian.id())
            .map_err(|_| std::io::Error::other("guardian PID does not fit process-group id"))?;
        let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
        while !ready.is_file() && Instant::now() < deadline {
            match guardian.try_wait() {
                Ok(Some(status)) => {
                    return Err(std::io::Error::other(format!(
                        "runtime containment guardian exited before readiness: {status}"
                    )));
                }
                Ok(None) => {}
                Err(probe_error) => {
                    let group_kill = signal_process_group(process_group, libc::SIGKILL);
                    let direct_kill = guardian.kill();
                    let reap = poll_child_until(
                        &mut guardian,
                        Instant::now() + PROCESS_REAP_TIMEOUT,
                        "uninspectable runtime containment guardian",
                    );
                    return Err(std::io::Error::other(format!(
                        "inspect runtime containment guardian readiness: {probe_error}; \
                         group_kill={group_kill:?}; direct_kill={direct_kill:?}; reap={reap:?}"
                    )));
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        if !ready.is_file() {
            let group_kill = signal_process_group(process_group, libc::SIGKILL);
            let direct_kill = guardian.kill();
            let reap = poll_child_until(
                &mut guardian,
                Instant::now() + PROCESS_REAP_TIMEOUT,
                "unready runtime containment guardian",
            );
            return Err(std::io::Error::other(format!(
                "runtime containment guardian did not become ready; group_kill={group_kill:?}; \
                 direct_kill={direct_kill:?}; reap={reap:?}"
            )));
        }
        let _ = std::fs::remove_file(ready);
        Ok(Self {
            process_group,
            guardian: Some(guardian),
        })
    }

    fn spawn(&self, command: &mut std::process::Command, _label: &str) -> std::io::Result<Child> {
        use std::os::unix::process::CommandExt as _;

        if self.guardian.is_none() {
            return Err(std::io::Error::other(
                "runtime containment was already terminated",
            ));
        }
        command.process_group(self.process_group);
        command.spawn()
    }

    fn terminate(&self) -> std::io::Result<()> {
        if self.guardian.is_none() {
            Ok(())
        } else {
            signal_process_group(self.process_group, libc::SIGKILL)
        }
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        if self.guardian.is_none() {
            Ok(true)
        } else {
            process_group_is_empty(self.process_group)
        }
    }

    fn terminate_and_confirm(&mut self) -> Result<(), String> {
        if self.guardian.is_none() {
            return Ok(());
        }
        let terminate_error = self.terminate().err();
        let tree_result = confirm_containment_empty(self, Instant::now() + PROCESS_REAP_TIMEOUT);
        let reap_result = match poll_child_until(
            self.guardian
                .as_mut()
                .expect("guardian remains present until it is reaped"),
            Instant::now() + PROCESS_REAP_TIMEOUT,
            "runtime containment guardian",
        ) {
            Ok(Some(_)) => {
                self.guardian.take();
                Ok(())
            }
            Ok(None) => Err("runtime containment guardian was not reaped".to_string()),
            Err(error) => Err(error),
        };
        combine_containment_results(terminate_error, tree_result, reap_result)
    }
}

#[cfg(unix)]
impl Drop for RuntimeContainment {
    fn drop(&mut self) {
        let _ = self.terminate_and_confirm();
    }
}

#[cfg(unix)]
#[test]
fn runtime_containment_guardian_worker() {
    if std::env::var_os(RUNTIME_CONTAINMENT_ENV).is_none() {
        return;
    }
    let expected_parent = std::env::var(RUNTIME_CONTAINMENT_PARENT_ENV)
        .expect("runtime guardian parent PID")
        .parse::<libc::pid_t>()
        .expect("valid runtime guardian parent PID");
    let ready = std::env::var_os(RUNTIME_CONTAINMENT_READY_ENV)
        .map(PathBuf::from)
        .expect("runtime guardian readiness path");
    std::fs::write(ready, std::process::id().to_string())
        .expect("write runtime guardian readiness");
    loop {
        if unsafe { libc::getppid() } != expected_parent {
            let group = unsafe { libc::getpgrp() };
            let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
struct CommandContainment {
    runtime: RuntimeContainment,
}

#[cfg(unix)]
impl CommandContainment {
    fn spawn(command: &mut std::process::Command, label: &str) -> std::io::Result<(Child, Self)> {
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
}

#[cfg(unix)]
impl Drop for CommandContainment {
    fn drop(&mut self) {
        let _ = self.terminate_and_confirm();
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH)
        || (error.raw_os_error() == Some(libc::EPERM) && process_group_is_empty(process_group)?)
    {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn process_group_is_empty(process_group: libc::pid_t) -> std::io::Result<bool> {
    let system = System::new_all();
    Ok(system.processes().iter().all(|(pid, process)| {
        let Ok(pid) = libc::pid_t::try_from(pid.as_u32()) else {
            return true;
        };
        let group = unsafe { libc::getpgid(pid) };
        group != process_group
            || matches!(
                process.status(),
                ProcessStatus::Dead | ProcessStatus::Zombie
            )
    }))
}

#[cfg(windows)]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self { handle };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
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

    fn spawn(&self, command: &mut std::process::Command, label: &str) -> std::io::Result<Child> {
        spawn_in_windows_job(command, self.handle, label)
    }

    fn terminate(&self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(self.handle, 1) } == 0 {
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
                self.handle,
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
impl Drop for WindowsJob {
    fn drop(&mut self) {
        let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
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
    command: &mut std::process::Command,
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

    fn spawn(&self, command: &mut std::process::Command, label: &str) -> std::io::Result<Child> {
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
    fn spawn(command: &mut std::process::Command, label: &str) -> std::io::Result<(Child, Self)> {
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
}

#[cfg(not(any(unix, windows)))]
struct RuntimeContainment;

#[cfg(not(any(unix, windows)))]
impl RuntimeContainment {
    fn new(_runtime_root: &Path, _owner_token: &str) -> std::io::Result<Self> {
        Ok(Self)
    }

    fn spawn(&self, command: &mut std::process::Command, _label: &str) -> std::io::Result<Child> {
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
    fn spawn(command: &mut std::process::Command, _label: &str) -> std::io::Result<(Child, Self)> {
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

/// Per-test supervisor and registry state with fail-closed lifecycle cleanup.
///
/// Daemon-backed integration tests must never discover the user's real Kin
/// registry. The runtime lives under the fixture's reserved `.kin` control
/// directory. Its `Drop` path first asks the product CLI to stop every process,
/// then terminates the stable OS containment created before any child was
/// launched. A final owner-token scan is verification only: it never signals a
/// PID, so PID reuse cannot authorize killing an unrelated process.
pub struct IsolatedDaemonRuntime {
    repository: PathBuf,
    registry_path: PathBuf,
    home_path: PathBuf,
    owner_token: String,
    containment: RuntimeContainment,
    cleanup_command: Option<CleanupCommand>,
    cleanup_timeout: Duration,
}

impl IsolatedDaemonRuntime {
    pub fn new(repository: &Path) -> Self {
        let runtime_root = repository.join(".kin/test-runtime");
        let home_path = runtime_root.join("home");
        let owner_token = uuid::Uuid::new_v4().to_string();
        let containment = RuntimeContainment::new(&runtime_root, &owner_token)
            .unwrap_or_else(|error| panic!("create isolated runtime containment: {error}"));
        Self {
            repository: repository.to_path_buf(),
            registry_path: runtime_root.join("registry.toml"),
            home_path,
            owner_token,
            containment,
            cleanup_command: None,
            cleanup_timeout: Duration::from_secs(15),
        }
    }

    #[cfg(unix)]
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

    pub fn kin_command(&self) -> Command<'_> {
        self.command(env!("CARGO_BIN_EXE_kin"))
    }

    pub fn daemon_bin(&self) -> PathBuf {
        fresh_daemon_bin(self)
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
    pub fn mark_owned_process_for_test(&self, command: &mut std::process::Command) {
        command.env(RUNTIME_OWNER_ENV, &self.owner_token).env(
            RUNTIME_CONTAINMENT_GROUP_ENV,
            self.containment.process_group.to_string(),
        );
        use std::os::unix::process::CommandExt as _;
        command.process_group(self.containment.process_group);
    }

    fn command<S: AsRef<OsStr>>(&self, program: S) -> Command<'_> {
        let mut command = std::process::Command::new(program);
        self.apply_isolated_environment(&mut command);
        Command {
            inner: command,
            runtime: Some(self),
            intentional_env: Vec::new(),
        }
    }

    fn apply_isolated_environment(&self, command: &mut std::process::Command) {
        scrub_inherited_kin_authority(command);
        command
            .env("KIN_REGISTRY_PATH", &self.registry_path)
            // The explicit registry is authoritative. HOME/USERPROFILE are a
            // fail-closed fallback for any child boundary that intentionally
            // rebuilds its environment instead of inheriting the override.
            .env("HOME", &self.home_path)
            .env("USERPROFILE", &self.home_path)
            .env("XDG_CONFIG_HOME", self.home_path.join(".config"))
            .env(RUNTIME_OWNER_ENV, &self.owner_token)
            .env("KIN_VFS_DISABLE", "1")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
            .env("KIN_SUPERVISOR_IDLE_TIMEOUT_SECS", "1")
            // `daemon stop --all` can wait once per worker and once for the
            // supervisor. Keep both waits below Drop's independent wall cap.
            .env("KIN_DAEMON_STOP_TIMEOUT_SECS", "5");
        #[cfg(unix)]
        command.env(
            RUNTIME_CONTAINMENT_GROUP_ENV,
            self.containment.process_group.to_string(),
        );
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

impl Drop for IsolatedDaemonRuntime {
    fn drop(&mut self) {
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cleanup_invocation()
                .current_dir(&self.repository)
                .output_within(self.cleanup_timeout)
        }));
        let graceful_failure = match cleanup {
            Ok(Ok(output)) if output.status.success() => None,
            Ok(Ok(output)) => Some(format!(
                "isolated daemon cleanup failed with {}: stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
            Ok(Err(error)) => Some(format!("isolated daemon cleanup could not run: {error}")),
            Err(_) => Some("isolated daemon cleanup exceeded its wall-clock bound".to_string()),
        };
        let containment_failure = self.containment.terminate_and_confirm().err();
        let quiescence_failure = wait_for_owned_process_quiescence(
            RUNTIME_OWNER_ENV,
            &self.owner_token,
            Instant::now() + PROCESS_REAP_TIMEOUT,
        )
        .err();
        self.remove_stale_endpoint_files();

        let failure = [graceful_failure, containment_failure, quiescence_failure]
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
/// - Output is captured into regular files rather than pipes. `kin` detaches a
///   `kin-daemon` that inherits the caller's stdout and stderr, and a pipe stays
///   open for as long as any descendant holds its write end — so
///   `std::process::Command::output()` keeps reading long after the `kin`
///   process it launched has exited, for as long as the daemon lives.
/// - The wait carries a wall-clock deadline. At the deadline the child is
///   killed and the test fails naming the command, instead of leaving a silent,
///   idle process the developer has to notice and kill by hand.
pub struct Command<'runtime> {
    inner: std::process::Command,
    runtime: Option<&'runtime IsolatedDaemonRuntime>,
    intentional_env: Vec<(OsString, Option<OsString>)>,
}

impl Command<'static> {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            inner: std::process::Command::new(program),
            runtime: None,
            intentional_env: Vec::new(),
        }
    }
}

impl<'runtime> Command<'runtime> {
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        let key = key.as_ref();
        let value = value.as_ref();
        self.inner.env(key, value);
        if is_allowed_test_override(self.runtime.is_some(), key) {
            upsert_intentional_env(
                &mut self.intentional_env,
                key.to_os_string(),
                Some(value.to_os_string()),
            );
        }
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
        self.inner.env_remove(key);
        if is_allowed_test_override(self.runtime.is_some(), key) {
            upsert_intentional_env(&mut self.intentional_env, key.to_os_string(), None);
        }
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.inner.current_dir(dir);
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stdin(cfg);
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stdout(cfg);
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.inner.stderr(cfg);
        self
    }

    pub fn configured_env_for_test(&self, key: &OsStr) -> Option<Option<OsString>> {
        self.inner
            .get_envs()
            .find(|(configured, _)| env_os_names_equal(configured, key))
            .map(|(_, value)| value.map(OsStr::to_os_string))
    }

    /// Run to completion under [`COMMAND_TIMEOUT`] with stdin closed.
    pub fn output(&mut self) -> std::io::Result<Output> {
        self.output_within(COMMAND_TIMEOUT)
    }

    pub fn output_within(&mut self, timeout: Duration) -> std::io::Result<Output> {
        self.prepare_for_launch();
        let label = self.inner.get_program().to_string_lossy().into_owned();
        run_bounded_within(
            &mut self.inner,
            &label,
            self.runtime.map(|runtime| &runtime.containment),
            timeout,
        )
    }

    /// Spawn a long-lived child inside this runtime's stable OS containment.
    ///
    /// Direct daemon tests need to probe a live child before stopping it, so
    /// `output()` is the wrong lifecycle. This keeps the same authority scrub,
    /// protected runtime capability, Unix process group, and Windows Job
    /// Object as bounded commands while leaving the direct child handle with
    /// the test.
    pub fn spawn_owned(&mut self) -> std::io::Result<Child> {
        let runtime = self.runtime.ok_or_else(|| {
            std::io::Error::other("spawn_owned requires a command from IsolatedDaemonRuntime")
        })?;
        self.prepare_for_launch();
        let label = self.inner.get_program().to_string_lossy().into_owned();
        runtime.containment.spawn(&mut self.inner, &label)
    }

    fn prepare_for_launch(&mut self) {
        scrub_inherited_kin_authority(&mut self.inner);
        kin_git::test_support::isolate_fixture_git(&mut self.inner);
        if let Some(runtime) = self.runtime {
            runtime.apply_isolated_environment(&mut self.inner);
        }
        for (key, value) in &self.intentional_env {
            match value {
                Some(value) => {
                    self.inner.env(key, value);
                }
                None => {
                    self.inner.env_remove(key);
                }
            }
        }
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
    [
        RUNTIME_OWNER_ENV,
        RUNTIME_CONTAINMENT_ENV,
        RUNTIME_CONTAINMENT_READY_ENV,
        RUNTIME_CONTAINMENT_PARENT_ENV,
        RUNTIME_CONTAINMENT_GROUP_ENV,
    ]
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

fn is_kin_authority(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_eq(&label, "LD_PRELOAD")
        || env_name_eq(&label, "LD_AUDIT")
        || env_name_eq(&label, "LD_LIBRARY_PATH")
}

#[cfg(windows)]
#[test]
fn runtime_authority_names_are_case_insensitive_on_windows() {
    for hostile in [
        "kin_registry_path",
        "_kin_vfs_last_dir",
        "Dyld_Library_Path",
        "ld_preload",
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

fn run_bounded_within(
    command: &mut std::process::Command,
    label: &str,
    runtime_containment: Option<&RuntimeContainment>,
    timeout: Duration,
) -> std::io::Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));

    let (mut child, mut command_containment) = match runtime_containment {
        Some(containment) => (containment.spawn(command, label)?, None),
        None => {
            let (child, containment) = CommandContainment::spawn(command, label)?;
            (child, Some(containment))
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(containment) = command_containment.as_mut() {
                    containment.terminate_and_confirm().map_err(|error| {
                        std::io::Error::other(format!(
                            "clean descendants after {label} exited: {error}"
                        ))
                    })?;
                }
                return Ok(Output {
                    status,
                    stdout: read_capture(stdout)?,
                    stderr: read_capture(stderr)?,
                });
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let cleanup = terminate_spawned_process(
                    &mut child,
                    label,
                    command_containment
                        .as_ref()
                        .map(|containment| containment as &dyn ProcessContainment)
                        .or_else(|| {
                            runtime_containment
                                .map(|containment| containment as &dyn ProcessContainment)
                        }),
                );
                panic!(
                    "{label} did not exit within {timeout:?}; cleanup={cleanup:?}; stdout={} stderr={}",
                    String::from_utf8_lossy(&read_capture(stdout).unwrap_or_default()),
                    String::from_utf8_lossy(&read_capture(stderr).unwrap_or_default())
                );
            }
            Err(error) => {
                return match terminate_spawned_process(
                    &mut child,
                    label,
                    command_containment
                        .as_ref()
                        .map(|containment| containment as &dyn ProcessContainment)
                        .or_else(|| {
                            runtime_containment
                                .map(|containment| containment as &dyn ProcessContainment)
                        }),
                ) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(std::io::Error::other(format!("{error}; {cleanup}"))),
                };
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
    child: &mut Child,
    label: &str,
    containment: Option<&dyn ProcessContainment>,
) -> Result<(), String> {
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    let containment_termination = containment.and_then(|tree| tree.terminate().err());
    let direct_kill = child.kill().err();
    let direct_reap = poll_child_until(child, deadline, label);
    let containment_quiescence =
        containment.map(|tree| confirm_containment_empty_dyn(tree, deadline));
    match (
        containment_termination,
        direct_kill,
        direct_reap,
        containment_quiescence,
    ) {
        (None, None, Ok(Some(_)), None | Some(Ok(()))) => Ok(()),
        (termination, kill, reap, quiescence) => Err(format!(
            "{label} cleanup failed: containment termination={termination:?}; direct kill={kill:?}; direct reap={reap:?}; containment quiescence={quiescence:?}"
        )),
    }
}

fn read_capture(mut file: std::fs::File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The build identity this test binary carries, in the exact form the daemon
/// stamps persisted vector sidecars with.
///
/// A test that seeds prepared state writes this stamp; the daemon that later
/// reopens the repository demands its own. The two only agree when both
/// binaries came out of one build of `kin-buildinfo`.
pub fn expected_build_stamp() -> String {
    kin_buildinfo::sha_with_dirty(kin_buildinfo::get())
}

/// Recompose a `--compat-json` `build.sha` / `build.dirty` pair into the stamp
/// `kin_buildinfo::sha_with_dirty` would produce for the same build.
///
/// The daemon reports the two fields separately, so the harness has to join
/// them the way the authority does rather than comparing the pair directly:
/// when the commit is unknown the dirty flag is not part of the identity, and
/// a raw pair comparison would reject a daemon whose embedder identity
/// actually matches.
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
/// Two independent reasons, and the second is the one that used to be missed.
/// A daemon whose graph snapshot version differs cannot read the repository at
/// all. A daemon that is merely built from a *different commit or working
/// tree* reads it fine, but stamps and demands a different embedder identity —
/// so a sidecar seeded by this test binary is rejected on load,
/// `indexed_embedding_count` reads 0, and the suite reports a product defect
/// that only exists because two binaries in one target directory were built at
/// different times.
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
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    let mut command = runtime.command(path);
    let output = command
        .arg("--compat-json")
        .output()
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

fn fresh_daemon_bin(runtime: &IsolatedDaemonRuntime) -> PathBuf {
    let kin_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"));
    let daemon_bin = kin_bin.with_file_name(format!("kin-daemon{}", std::env::consts::EXE_SUFFIX));
    if daemon_compat(runtime, &daemon_bin).is_ok() {
        return daemon_bin;
    }

    BUILD_DAEMON.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.ancestors().nth(2).expect("kin workspace root");
        // This shells out to cargo from inside a cargo-driven test run, so it
        // contends for the build-directory lock with whatever else is building
        // this checkout. Cargo waits on that lock forever and prints only to
        // the stderr this call captures, so the wait is bounded here.
        let mut build = Command::new(env!("CARGO"));
        scrub_inherited_kin_authority(&mut build.inner);
        let output = build
            .args(["build", "-p", "kin-daemon", "--bin", "kin-daemon"])
            .current_dir(workspace_root)
            .output_within(BUILD_TIMEOUT)
            .expect("run cargo build -p kin-daemon");
        assert!(
            output.status.success(),
            "cargo build -p kin-daemon failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    });

    if let Err(reason) = daemon_compat(runtime, &daemon_bin) {
        panic!(
            "kin-daemon at {} is unusable after rebuild: {reason}.\n\
             This test binary carries build identity {}. A daemon built from a \
             different commit or working tree stamps persisted vector sidecars \
             with a different embedder identity, so state this suite seeds is \
             rejected on reopen and indexed_embedding_count reads 0 — a harness \
             fault that reads as a product defect. Build both from one tree: \
             cargo build --all-targets",
            daemon_bin.display(),
            expected_build_stamp()
        );
    }
    daemon_bin
}
