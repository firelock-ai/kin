// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded subprocess execution for native CLI tests.
//!
//! Dedicated reader sinks continuously drain stdout and stderr while retaining
//! at most a fixed byte ceiling per stream. On Unix, a readiness-gated guardian
//! owns every worker's process group. Its ownership pipe makes parent death kill
//! the group, and the guardian remains unreaped while the group is proven empty
//! so its numeric id cannot be reused before containment is disarmed. Workers
//! must not detach or call `setsid`, because that escapes the bounded
//! process-group contract. On Windows, each worker is assigned to a
//! kill-on-close Job Object that contains descendants.

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Wall-clock cap for a test-driven worker process.
///
/// This is a backstop against a wait that would otherwise never end, not an
/// assertion about how fast the machine is. The workers it bounds re-execute
/// this test binary and normally finish in under a second, but the suite runs
/// them many-at-once and a developer machine may be saturated by other work at
/// the same time, so the cap is set far above any legitimate completion time.
/// Tightening it back toward the observed runtime trades a class of hangs for a
/// class of load-dependent false failures.
pub(crate) const DEFAULT_TEST_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(300);
const TEST_SUBPROCESS_REAP_GRACE: Duration = Duration::from_secs(5);
const TEST_SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TEST_SUBPROCESS_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
/// Maximum rendered UTF-8 bytes, including any truncation marker.
const TEST_SUBPROCESS_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const TEST_SUBPROCESS_DIAGNOSTIC_MARKER: &str = "\n[bounded capture truncated]";

fn env_name_eq(actual: &str, expected: &str) -> bool {
    if cfg!(windows) {
        actual.eq_ignore_ascii_case(expected)
    } else {
        actual == expected
    }
}

fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    if cfg!(windows) {
        actual
            .get(..expected.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
    } else {
        actual.starts_with(expected)
    }
}

fn is_test_subprocess_authority(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "KIN_")
        || env_name_starts_with(&label, "_KIN_")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
}

fn is_allowed_explicit_worker_kin_input(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_eq(&label, "KIN_HOME")
        || env_name_starts_with(&label, "KIN_TEST_RESTRICTIVE_")
        || env_name_starts_with(&label, "KIN_UPDATE_TEST_")
        || env_name_starts_with(&label, "KIN_UPDATE_TEMP_LEASE_CRASH_")
        || env_name_starts_with(&label, "KIN_UPDATE_TEMP_CLEANUP_CRASH_")
}

/// Remove ambient repository, runtime, VFS, and loader authority immediately
/// before a native test worker or its guardian is spawned.
///
/// The setup/update crash workers need a deliberately tiny Kin input surface.
/// Capture those explicit command-local values before the scrub and replay
/// only that allowlist afterward. Arbitrary Kin authority, including daemon,
/// registry, session, and VFS selectors, remains fail-closed.
fn prepare_test_subprocess_command(command: &mut Command, replay_worker_inputs: bool) {
    let worker_inputs = if replay_worker_inputs {
        command
            .get_envs()
            .filter(|(key, _)| is_allowed_explicit_worker_kin_input(key))
            .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_test_subprocess_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_test_subprocess_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }

    // This shared lower boundary installs a fixed host PATH, null Git config,
    // disabled prompts, and a complete Git/VFS/loader scrub.
    kin_git::test_support::isolate_fixture_git(command);
    for (key, value) in worker_inputs {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    command.env("KIN_VFS_DISABLE", "1");
}

#[cfg(unix)]
fn prepare_test_subprocess_guardian_environment(
    environment: &mut kin_daemon_spawn::ProcessGroupGuardianEnvironment,
) {
    let explicit_authority = environment
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_test_subprocess_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_test_subprocess_authority(key))
        .chain(explicit_authority)
    {
        environment.env_remove(key);
    }

    kin_git::test_support::isolate_fixture_guardian_environment(environment);
    environment.env("KIN_VFS_DISABLE", "1");
}

/// Build a Git command through the workspace's single fixture-isolation
/// boundary. Production Git commands intentionally do not use this helper.
pub(crate) fn fixture_git(repository: &Path) -> kin_git::test_support::FixtureGitCommand {
    kin_git::test_support::fixture_git_in(repository)
}

#[cfg(unix)]
struct TestProcessTree {
    process_group: Option<UnixTestProcessGroup>,
    guardian: Option<kin_daemon_spawn::ProcessGroupGuardian>,
    _guardian_root: tempfile::TempDir,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum UnixTestProcessGroup {
    Armed,
    TerminationRequested,
}

#[cfg(unix)]
impl TestProcessTree {
    fn spawn(mut command: Command, label: &str) -> Result<(Child, Self)> {
        let guardian_root = tempfile::Builder::new()
            .prefix("kin-test-subprocess-guardian-")
            .tempdir()
            .context("failed to create bounded test guardian root")?;
        let ready = guardian_root.path().join("ready");
        let executable = std::env::current_exe().context("resolve current test executable")?;
        let mut launcher = kin_daemon_spawn::ProcessGroupGuardianLauncher::exact_test(
            executable,
            "kin_process_group_guardian_worker",
        );
        if command.get_envs().any(|(key, value)| {
            env_name_eq(
                &key.to_string_lossy(),
                kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY_ENV,
            ) && value == Some(OsStr::new("1"))
        }) {
            launcher = launcher.with_env(
                kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY_ENV,
                "1",
            );
        }
        let guardian = launcher
            .spawn_with(
                &ready,
                Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                prepare_test_subprocess_guardian_environment,
            )
            .with_context(|| format!("failed to spawn parent-death guardian for {label}"))?;
        let mut tree = Self {
            process_group: Some(UnixTestProcessGroup::Armed),
            guardian: Some(guardian),
            _guardian_root: guardian_root,
        };

        prepare_test_subprocess_command(&mut command, true);
        match tree
            .guardian
            .as_mut()
            .expect("new bounded test guardian remains owned")
            .spawn(command)
        {
            Ok(child) => Ok((child, tree)),
            Err(error) => {
                let cleanup = terminate_and_confirm_tree(&mut tree).err();
                Err(error).with_context(|| {
                    format!("failed to spawn {label}; guardian cleanup={cleanup:?}")
                })
            }
        }
    }

    fn terminate(&mut self) -> Result<()> {
        let Some(UnixTestProcessGroup::Armed) = self.process_group else {
            return Ok(());
        };
        let guardian = self.guardian.as_mut().ok_or_else(|| {
            anyhow::anyhow!("bounded test containment lost its process-group guardian")
        })?;
        self.process_group = Some(UnixTestProcessGroup::TerminationRequested);
        guardian.request_cleanup();
        Ok(())
    }

    fn is_empty(&mut self) -> Result<bool> {
        if self.process_group.is_none() {
            return Ok(true);
        }
        let Some(guardian) = self.guardian.as_mut() else {
            return Ok(true);
        };
        let reaped = guardian
            .try_reap()
            .context("failed to poll bounded test process-group guardian")?
            .is_some();
        if reaped {
            self.guardian.take();
        }
        Ok(reaped)
    }

    fn reap_auxiliary_until(&mut self, deadline: Instant) -> Result<bool> {
        let Some(guardian) = self.guardian.as_mut() else {
            return Ok(true);
        };
        match guardian.reap_until(deadline) {
            Ok(_) => {
                self.guardian.take();
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(false),
            Err(error) => Err(error).context("failed to reap bounded test guardian"),
        }
    }

    fn disarm_after_confirmed_cleanup(&mut self) {
        self.process_group.take();
    }
}

#[cfg(unix)]
impl Drop for TestProcessTree {
    fn drop(&mut self) {
        let terminate_error = self.terminate().err();
        if confirm_tree_empty_until(
            self,
            Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
            terminate_error,
        )
        .is_err()
        {
            // Dropping the ownership pipe still leaves the external watcher
            // responsible for the pinned-PGID cleanup proof.
            return;
        }
        match self.reap_auxiliary_until(Instant::now() + TEST_SUBPROCESS_REAP_GRACE) {
            Ok(true) => self.disarm_after_confirmed_cleanup(),
            Ok(false) | Err(_) => {
                // Do not disarm the numeric identity if the watcher could not
                // finish its pinned-PGID proof under the independent grace.
            }
        }
    }
}

#[cfg(unix)]
struct RetainedTestProcessCleanup {
    child: Child,
    tree: TestProcessTree,
}

#[cfg(unix)]
impl RetainedTestProcessCleanup {
    fn run(mut self) -> ExitStatus {
        let _ = self.tree.terminate();
        let _ = self.child.kill();
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
                }
            }
        };

        // The exact direct-child status is reaped. Only now may guardian
        // finalization consume the sentinel PGID pin.
        let _ = terminate_and_confirm_tree(&mut self.tree);
        status
    }
}

#[cfg(unix)]
fn retain_unreaped_test_process(child: Child, tree: TestProcessTree, label: &str) -> String {
    let retained = std::mem::ManuallyDrop::new(RetainedTestProcessCleanup { child, tree });
    match std::thread::Builder::new()
        .name("kin-test-retained-subprocess".to_string())
        .spawn(move || {
            let retained = std::mem::ManuallyDrop::into_inner(retained);
            let _ = retained.run();
        }) {
        Ok(_) => format!("retained exact child and guardian for asynchronous cleanup of {label}"),
        Err(error) => format!(
            "failed to spawn retained cleanup owner for {label}: {error}; exact child and \
             guardian intentionally leaked"
        ),
    }
}

#[cfg(windows)]
struct TestProcessTree {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
struct TestOwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for TestOwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
impl TestProcessTree {
    fn spawn(mut command: Command, label: &str) -> Result<(Child, Self)> {
        use std::os::windows::io::AsRawHandle as _;
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
            return Err(std::io::Error::last_os_error())
                .context("failed to create bounded test job object");
        }
        let mut tree = Self { job };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                tree.job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to configure bounded test job object");
        }

        command.creation_flags(CREATE_SUSPENDED);
        prepare_test_subprocess_command(&mut command, true);
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn {label}"))?;
        let assigned = unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle()) };
        if assigned == 0 {
            let assign_error = std::io::Error::last_os_error();
            return Err(Self::failed_spawn_cleanup(
                &mut child,
                None,
                label,
                format!("failed to assign process to bounded job object: {assign_error}"),
            ));
        }

        let thread_id = (|| -> Result<u32> {
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error())
                    .context("failed to snapshot suspended bounded-process threads");
            }
            let snapshot = TestOwnedHandle(snapshot);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_MORE_FILES {
                    anyhow::bail!("suspended bounded process has no enumerable primary thread");
                }
                return Err(std::io::Error::from_raw_os_error(error as i32))
                    .context("failed to begin suspended bounded-process thread enumeration");
            }
            let expected_size = std::mem::size_of::<THREADENTRY32>() as u32;
            let minimum_size = (std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID)
                + std::mem::size_of::<u32>()) as u32;
            let mut matches = Vec::new();
            loop {
                if entry.dwSize < minimum_size {
                    anyhow::bail!(
                        "suspended bounded-process thread entry is too small: {} (minimum {})",
                        entry.dwSize,
                        minimum_size
                    );
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
                    return Err(std::io::Error::from_raw_os_error(error as i32))
                        .context("failed during suspended bounded-process thread enumeration");
                }
            }
            if matches.len() != 1 {
                anyhow::bail!(
                    "suspended bounded process must have exactly one primary thread, found {}",
                    matches.len()
                );
            }
            Ok(matches[0])
        })();
        let thread_id = match thread_id {
            Ok(thread_id) => thread_id,
            Err(error) => {
                return Err(Self::failed_spawn_cleanup(
                    &mut child,
                    Some(&mut tree),
                    label,
                    format!("failed to bind suspended primary thread: {error:#}"),
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
            return Err(Self::failed_spawn_cleanup(
                &mut child,
                Some(&mut tree),
                label,
                format!("failed to open suspended primary thread: {error}"),
            ));
        }
        let thread = TestOwnedHandle(thread);
        let owner = unsafe { GetProcessIdOfThread(thread.0) };
        let child_id = child.id();
        if owner != child_id {
            return Err(Self::failed_spawn_cleanup(
                &mut child,
                Some(&mut tree),
                label,
                format!(
                    "suspended primary thread owner changed: expected {}, observed {owner}",
                    child_id
                ),
            ));
        }
        let previous_suspend_count = unsafe { ResumeThread(thread.0) };
        if previous_suspend_count != 1 {
            return Err(Self::failed_spawn_cleanup(
                &mut child,
                Some(&mut tree),
                label,
                format!(
                    "suspended primary thread resume returned {previous_suspend_count}, expected exactly 1"
                ),
            ));
        }
        Ok((child, tree))
    }

    fn failed_spawn_cleanup(
        child: &mut Child,
        tree: Option<&mut Self>,
        label: &str,
        cause: String,
    ) -> anyhow::Error {
        let mut tree = tree;
        let tree_terminate_error = tree.as_deref_mut().and_then(|tree| tree.terminate().err());
        let direct_kill_error = child.kill().err();
        let (reaped, reap_error) =
            match poll_child_until(child, Instant::now() + TEST_SUBPROCESS_REAP_GRACE, label) {
                Ok(status) => (status.is_some(), None),
                Err(error) => (false, Some(error)),
            };
        let tree_error =
            tree.and_then(|tree| confirm_reap_and_disarm_tree(tree, tree_terminate_error).err());
        anyhow::anyhow!(
            "{cause}; direct-kill error: {direct_kill_error:?}; reap error: {}; containment-cleanup error: {}; direct child reaped: {reaped}",
            reap_error
                .as_ref()
                .map(|error| format!("{error:#}"))
                .unwrap_or_else(|| "none".to_string()),
            tree_error
                .as_ref()
                .map(|error| format!("{error:#}"))
                .unwrap_or_else(|| "none".to_string())
        )
    }

    fn terminate(&mut self) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to terminate bounded test job object");
        }
        Ok(())
    }

    fn is_empty(&self) -> Result<bool> {
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect bounded test job object");
        }
        Ok(accounting.ActiveProcesses == 0)
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant) -> Result<bool> {
        Ok(true)
    }

    fn disarm_after_confirmed_cleanup(&mut self) {}
}

#[cfg(windows)]
impl Drop for TestProcessTree {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        let _ = unsafe { CloseHandle(self.job) };
    }
}

#[cfg(not(any(unix, windows)))]
struct TestProcessTree;

#[cfg(not(any(unix, windows)))]
impl TestProcessTree {
    fn spawn(mut command: Command, label: &str) -> Result<(Child, Self)> {
        prepare_test_subprocess_command(&mut command, true);
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {label}"))?;
        Ok((child, Self))
    }

    fn terminate(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(true)
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant) -> Result<bool> {
        Ok(true)
    }

    fn disarm_after_confirmed_cleanup(&mut self) {}
}

fn poll_child_until(
    child: &mut Child,
    deadline: Instant,
    label: &str,
) -> Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to poll {label}"))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
    }
}

fn confirm_tree_empty_until(
    tree: &mut TestProcessTree,
    deadline: Instant,
    terminate_error: Option<anyhow::Error>,
) -> Result<()> {
    loop {
        if tree.is_empty()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            if let Some(error) = terminate_error {
                anyhow::bail!(
                    "bounded test containment remained live after termination failed: {error:#}"
                );
            }
            anyhow::bail!("bounded test containment remained live after termination deadline");
        }
        std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
    }
}

fn confirm_reap_and_disarm_tree(
    tree: &mut TestProcessTree,
    terminate_error: Option<anyhow::Error>,
) -> Result<()> {
    let deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
    confirm_tree_empty_until(tree, deadline, terminate_error)?;
    if !tree.reap_auxiliary_until(Instant::now() + TEST_SUBPROCESS_REAP_GRACE)? {
        anyhow::bail!("bounded test guardian was not reaped before the cleanup deadline");
    }
    tree.disarm_after_confirmed_cleanup();
    Ok(())
}

fn terminate_and_confirm_tree(tree: &mut TestProcessTree) -> Result<()> {
    let terminate_error = tree.terminate().err();
    confirm_reap_and_disarm_tree(tree, terminate_error)
}

struct FailedTestProcessCleanup {
    detail: String,
    quiescence_proven: bool,
}

fn cleanup_failed_test_process(
    mut child: Child,
    mut tree: TestProcessTree,
    label: &str,
) -> FailedTestProcessCleanup {
    let deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
    let tree_terminate_error = tree.terminate().err();
    let direct_kill_error = child.kill().err();
    let (status, reap_error) = match poll_child_until(&mut child, deadline, label) {
        Ok(status) => (status, None),
        Err(error) => (None, Some(error)),
    };
    let direct_child_reaped = status.is_some();

    #[cfg(unix)]
    let (tree_error, retention) = if direct_child_reaped {
        (
            confirm_reap_and_disarm_tree(&mut tree, tree_terminate_error).err(),
            None,
        )
    } else {
        (None, Some(retain_unreaped_test_process(child, tree, label)))
    };

    #[cfg(not(unix))]
    let (tree_error, retention) = (
        confirm_reap_and_disarm_tree(&mut tree, tree_terminate_error).err(),
        None::<String>,
    );

    let quiescence_proven = direct_child_reaped && tree_error.is_none();
    FailedTestProcessCleanup {
        detail: format!(
            "direct-kill error: {direct_kill_error:?}; reap error: {}; containment-cleanup error: {}; \
             direct child reaped: {direct_child_reaped}; retained cleanup: {}",
            reap_error
                .as_ref()
                .map(|error| format!("{error:#}"))
                .unwrap_or_else(|| "none".to_string()),
            tree_error
                .as_ref()
                .map(|error| format!("{error:#}"))
                .unwrap_or_else(|| {
                    if direct_child_reaped {
                        "none".to_string()
                    } else {
                        "skipped until exact child status is reaped".to_string()
                    }
                }),
            retention.as_deref().unwrap_or("not required"),
        ),
        quiescence_proven,
    }
}

#[derive(Clone, Debug)]
struct CapturedTestStream {
    bytes: Vec<u8>,
    observed_bytes: u64,
    truncated: bool,
    error: Option<String>,
    done: bool,
}

impl Default for CapturedTestStream {
    fn default() -> Self {
        Self {
            bytes: Vec::with_capacity(TEST_SUBPROCESS_CAPTURE_LIMIT.min(64 * 1024)),
            observed_bytes: 0,
            truncated: false,
            error: None,
            done: false,
        }
    }
}

struct BoundedTestCapture {
    stdout: BoundedTestCaptureReader,
    stderr: BoundedTestCaptureReader,
    overflowed: Arc<AtomicBool>,
}

struct BoundedTestCaptureReader {
    stream: &'static str,
    state: Arc<Mutex<CapturedTestStream>>,
    thread: Option<std::thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}

impl BoundedTestCapture {
    fn configure(command: &mut Command) {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    fn start(child: &mut Child, label: &str) -> Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("{label} did not expose captured stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("{label} did not expose captured stderr"))?;
        let overflowed = Arc::new(AtomicBool::new(false));
        Ok(Self {
            stdout: BoundedTestCaptureReader::spawn(stdout, "stdout", overflowed.clone())
                .context("failed to start bounded stdout capture")?,
            stderr: BoundedTestCaptureReader::spawn(stderr, "stderr", overflowed.clone())
                .context("failed to start bounded stderr capture")?,
            overflowed,
        })
    }

    fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    fn finish_until(self, deadline: Instant) -> Result<(CapturedTestStream, CapturedTestStream)> {
        let stdout = self.stdout.finish_until(deadline);
        let stderr = self.stderr.finish_until(deadline);
        if let Some(error) = stdout.error.as_ref().or(stderr.error.as_ref()) {
            anyhow::bail!("bounded test capture did not finish cleanly: {error}");
        }
        Ok((stdout, stderr))
    }
}

impl BoundedTestCaptureReader {
    fn spawn(
        stream: impl TestCapturePipe,
        name: &'static str,
        overflowed: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        stream.prepare_nonblocking()?;
        let state = Arc::new(Mutex::new(CapturedTestStream::default()));
        let reader_state = state.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancel.clone();
        let thread = std::thread::Builder::new()
            .name(format!("kin-test-{name}-capture"))
            .spawn(move || {
                drain_test_stream(stream, &reader_state, &overflowed, &reader_cancel);
            })?;
        Ok(Self {
            stream: name,
            state,
            thread: Some(thread),
            cancel,
        })
    }

    fn finish_until(mut self, deadline: Instant) -> CapturedTestStream {
        if !self.wait_done_until(deadline) {
            self.cancel.store(true, Ordering::Release);
            if let Some(thread) = &self.thread {
                thread.thread().unpark();
            }
            let _ = self
                .wait_done_until(Instant::now() + TEST_SUBPROCESS_POLL_INTERVAL.saturating_mul(4));
        }
        let done = self.snapshot().done;
        if done {
            if self
                .thread
                .take()
                .expect("bounded capture thread remains owned")
                .join()
                .is_err()
            {
                if let Ok(mut state) = self.state.lock() {
                    state.error = Some(format!("{} capture thread panicked", self.stream));
                }
            }
        } else if let Ok(mut state) = self.state.lock() {
            state.error = Some(format!(
                "{} capture reader ignored cancellation past its deadline",
                self.stream
            ));
        }
        self.snapshot()
    }

    fn wait_done_until(&self, deadline: Instant) -> bool {
        loop {
            if self.snapshot().done {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
        }
    }

    fn snapshot(&self) -> CapturedTestStream {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_else(|_| CapturedTestStream {
                error: Some(format!("{} capture state was poisoned", self.stream)),
                done: true,
                ..CapturedTestStream::default()
            })
    }
}

impl Drop for BoundedTestCaptureReader {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        if self.wait_done_until(Instant::now() + TEST_SUBPROCESS_POLL_INTERVAL.saturating_mul(4)) {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

enum TestCaptureRead {
    Data(usize),
    Pending,
    Eof,
}

trait TestCapturePipe: Read + Send + 'static {
    fn prepare_nonblocking(&self) -> std::io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<TestCaptureRead>;
}

macro_rules! impl_test_capture_pipe {
    ($pipe:ty) => {
        impl TestCapturePipe for $pipe {
            fn prepare_nonblocking(&self) -> std::io::Result<()> {
                prepare_test_capture_pipe(self)
            }

            fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<TestCaptureRead> {
                read_test_capture_pipe(self, buffer)
            }
        }
    };
}

impl_test_capture_pipe!(std::process::ChildStdout);
impl_test_capture_pipe!(std::process::ChildStderr);

#[cfg(test)]
impl TestCapturePipe for std::io::Cursor<Vec<u8>> {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<TestCaptureRead> {
        match self.read(buffer)? {
            0 => Ok(TestCaptureRead::Eof),
            read => Ok(TestCaptureRead::Data(read)),
        }
    }
}

#[cfg(unix)]
fn prepare_test_capture_pipe(pipe: &(impl std::os::fd::AsRawFd + ?Sized)) -> std::io::Result<()> {
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
fn read_test_capture_pipe(
    pipe: &mut impl Read,
    buffer: &mut [u8],
) -> std::io::Result<TestCaptureRead> {
    match pipe.read(buffer) {
        Ok(0) => Ok(TestCaptureRead::Eof),
        Ok(read) => Ok(TestCaptureRead::Data(read)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(TestCaptureRead::Pending)
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn prepare_test_capture_pipe(
    _pipe: &(impl std::os::windows::io::AsRawHandle + ?Sized),
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_test_capture_pipe(
    pipe: &mut (impl Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> std::io::Result<TestCaptureRead> {
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
                Ok(TestCaptureRead::Eof)
            }
            _ => Err(error),
        };
    }
    if available == 0 {
        return Ok(TestCaptureRead::Pending);
    }
    let request = buffer
        .len()
        .min(usize::try_from(available).unwrap_or(usize::MAX));
    match pipe.read(&mut buffer[..request]) {
        Ok(0) => Ok(TestCaptureRead::Eof),
        Ok(read) => Ok(TestCaptureRead::Data(read)),
        Err(error)
            if error.kind() == std::io::ErrorKind::BrokenPipe
                || matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) =>
        {
            Ok(TestCaptureRead::Eof)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
fn prepare_test_capture_pipe<T: ?Sized>(_pipe: &T) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_test_capture_pipe(
    pipe: &mut impl Read,
    buffer: &mut [u8],
) -> std::io::Result<TestCaptureRead> {
    match pipe.read(buffer)? {
        0 => Ok(TestCaptureRead::Eof),
        read => Ok(TestCaptureRead::Data(read)),
    }
}

fn drain_test_stream(
    mut stream: impl TestCapturePipe,
    state: &Arc<Mutex<CapturedTestStream>>,
    overflowed: &Arc<AtomicBool>,
    cancel: &Arc<AtomicBool>,
) {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if cancel.load(Ordering::Acquire) {
            if let Ok(mut state) = state.lock() {
                state.error = Some("capture cancelled before EOF".to_string());
            }
            break;
        }
        let read = match stream.read_available(&mut buffer) {
            Ok(TestCaptureRead::Eof) => break,
            Ok(TestCaptureRead::Pending) => {
                std::thread::park_timeout(TEST_SUBPROCESS_POLL_INTERVAL);
                continue;
            }
            Ok(TestCaptureRead::Data(read)) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                if let Ok(mut state) = state.lock() {
                    state.error = Some(error.to_string());
                }
                break;
            }
        };
        let Ok(mut state) = state.lock() else {
            break;
        };
        state.observed_bytes = state.observed_bytes.saturating_add(read as u64);
        let remaining = TEST_SUBPROCESS_CAPTURE_LIMIT.saturating_sub(state.bytes.len());
        state
            .bytes
            .extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining {
            state.truncated = true;
            overflowed.store(true, Ordering::Release);
        }
    }
    if let Ok(mut state) = state.lock() {
        state.done = true;
    }
}

fn compact_test_capture(stream: &CapturedTestStream) -> String {
    let prefix = &stream.bytes[..stream.bytes.len().min(TEST_SUBPROCESS_DIAGNOSTIC_LIMIT)];
    let lossy = String::from_utf8_lossy(prefix);
    let needs_marker = stream.truncated
        || stream.bytes.len() > TEST_SUBPROCESS_DIAGNOSTIC_LIMIT
        || lossy.len() > TEST_SUBPROCESS_DIAGNOSTIC_LIMIT;
    let content_budget = if needs_marker {
        TEST_SUBPROCESS_DIAGNOSTIC_LIMIT.saturating_sub(TEST_SUBPROCESS_DIAGNOSTIC_MARKER.len())
    } else {
        TEST_SUBPROCESS_DIAGNOSTIC_LIMIT
    };
    let mut content_end = lossy.len().min(content_budget);
    while !lossy.is_char_boundary(content_end) {
        content_end -= 1;
    }
    let mut rendered = lossy[..content_end].to_owned();
    if needs_marker {
        rendered.push_str(TEST_SUBPROCESS_DIAGNOSTIC_MARKER);
    }
    debug_assert!(rendered.len() <= TEST_SUBPROCESS_DIAGNOSTIC_LIMIT);
    rendered
}

fn captured_test_output(
    capture: BoundedTestCapture,
    status: ExitStatus,
    label: &str,
) -> Result<Output> {
    let (stdout, stderr) = capture.finish_until(Instant::now() + TEST_SUBPROCESS_REAP_GRACE)?;
    if stdout.truncated || stderr.truncated {
        anyhow::bail!(
            "{label} exceeded the {}-byte per-stream capture limit \
             (stdout={}, stderr={}); stdout={} stderr={}",
            TEST_SUBPROCESS_CAPTURE_LIMIT,
            stdout.observed_bytes,
            stderr.observed_bytes,
            compact_test_capture(&stdout),
            compact_test_capture(&stderr)
        );
    }
    Ok(Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

pub(crate) fn output_with_timeout(
    mut command: Command,
    label: &str,
    timeout: Duration,
) -> Result<Output> {
    BoundedTestCapture::configure(&mut command);

    let (mut child, mut tree) = TestProcessTree::spawn(command, label)?;
    let capture = match BoundedTestCapture::start(&mut child, label) {
        Ok(capture) => capture,
        Err(error) => {
            let cleanup = cleanup_failed_test_process(child, tree, label);
            return Err(error).with_context(|| {
                format!("failed to initialize {label} capture; {}", cleanup.detail)
            });
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        if capture.overflowed() {
            let cleanup = cleanup_failed_test_process(child, tree, label);
            let capture_detail = if cleanup.quiescence_proven {
                match capture.finish_until(Instant::now() + TEST_SUBPROCESS_REAP_GRACE) {
                    Ok((stdout, stderr)) => format!(
                        "stdout-bytes={} stderr-bytes={} stdout={} stderr={}",
                        stdout.observed_bytes,
                        stderr.observed_bytes,
                        compact_test_capture(&stdout),
                        compact_test_capture(&stderr)
                    ),
                    Err(error) => format!("capture-error={error:#}"),
                }
            } else {
                drop(capture);
                "capture unavailable because process-tree quiescence was not proven".to_string()
            };
            anyhow::bail!(
                "{label} exceeded the {}-byte per-stream capture limit; \
                 {}; {capture_detail}",
                TEST_SUBPROCESS_CAPTURE_LIMIT,
                cleanup.detail,
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_and_confirm_tree(&mut tree)
                    .with_context(|| format!("failed to clean descendants after {label} exited"))?;
                return captured_test_output(capture, status, label);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                let cleanup = cleanup_failed_test_process(child, tree, label);
                let capture_detail = if cleanup.quiescence_proven {
                    match capture.finish_until(Instant::now() + TEST_SUBPROCESS_REAP_GRACE) {
                        Ok((stdout, stderr)) => format!(
                            "stdout={} stderr={}",
                            compact_test_capture(&stdout),
                            compact_test_capture(&stderr)
                        ),
                        Err(error) => format!("capture-error={error:#}"),
                    }
                } else {
                    drop(capture);
                    "capture unavailable because process-tree quiescence was not proven".to_string()
                };
                anyhow::bail!(
                    "{label} timed out after {timeout:?}; {}; {capture_detail}",
                    cleanup.detail,
                );
            }
            Err(error) => {
                let cleanup = cleanup_failed_test_process(child, tree, label);
                anyhow::bail!("failed to poll {label}: {error}; {}", cleanup.detail,);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::path::PathBuf;

    const SLEEP_WORKER: &str = "TEST_BOUNDED_SLEEP_MARKER";
    const DESCENDANT_PARENT: &str = "TEST_BOUNDED_DESCENDANT_PARENT";
    const DESCENDANT_MARKER: &str = "TEST_BOUNDED_DESCENDANT_MARKER";
    #[cfg(unix)]
    const PARENT_DEATH_OWNER: &str = "TEST_BOUNDED_PARENT_DEATH_OWNER";
    #[cfg(unix)]
    const PARENT_DEATH_DESCENDANT: &str = "TEST_BOUNDED_PARENT_DEATH_DESCENDANT";
    const AUTHORITY_OUTER: &str = "TEST_BOUNDED_AUTHORITY_OUTER";
    const AUTHORITY_INNER: &str = "TEST_BOUNDED_AUTHORITY_INNER";
    const HOSTILE_AUTHORITY_KEYS: &[&str] = &[
        "GIT_DIR",
        "GIT_TRACE",
        "KIN_REGISTRY_PATH",
        "KIN_DAEMON_SOCKET",
        "KIN_SESSION_DIR",
        "KIN_UPDATE_CHANNEL",
        "KIN_VFS_WORKSPACE",
        "_KIN_VFS_LAST_DIR",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ];
    const ALLOWED_WORKER_INPUTS: &[(&str, &str)] = &[
        ("KIN_HOME", "/explicit/kin-home"),
        ("KIN_TEST_RESTRICTIVE_ALLOWED", "setup-worker"),
        ("KIN_UPDATE_TEST_ALLOWED", "update-worker"),
        ("KIN_UPDATE_TEMP_LEASE_CRASH_ALLOWED", "temp-lease-worker"),
        (
            "KIN_UPDATE_TEMP_CLEANUP_CRASH_ALLOWED",
            "temp-cleanup-worker",
        ),
    ];

    struct NeverEofCapturePipe;

    impl Read for NeverEofCapturePipe {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    impl TestCapturePipe for NeverEofCapturePipe {
        fn prepare_nonblocking(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn read_available(&mut self, _buffer: &mut [u8]) -> std::io::Result<TestCaptureRead> {
            Ok(TestCaptureRead::Pending)
        }
    }

    #[test]
    fn capture_sink_never_retains_past_the_per_stream_ceiling() {
        let overflowed = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(CapturedTestStream::default()));
        let input = vec![b'x'; TEST_SUBPROCESS_CAPTURE_LIMIT + 16 * 1024];
        drain_test_stream(std::io::Cursor::new(input), &state, &overflowed, &cancel);
        let captured = state.lock().expect("capture state").clone();

        assert_eq!(captured.bytes.len(), TEST_SUBPROCESS_CAPTURE_LIMIT);
        assert_eq!(
            captured.observed_bytes,
            (TEST_SUBPROCESS_CAPTURE_LIMIT + 16 * 1024) as u64
        );
        assert!(captured.truncated);
        assert!(overflowed.load(Ordering::Acquire));
        assert!(compact_test_capture(&captured).len() <= TEST_SUBPROCESS_DIAGNOSTIC_LIMIT);
    }

    #[test]
    fn compact_capture_hard_bounds_invalid_utf8_after_lossy_expansion() {
        let captured = CapturedTestStream {
            bytes: vec![0xff; TEST_SUBPROCESS_DIAGNOSTIC_LIMIT],
            observed_bytes: TEST_SUBPROCESS_DIAGNOSTIC_LIMIT as u64,
            ..CapturedTestStream::default()
        };
        let diagnostic = compact_test_capture(&captured);

        assert!(diagnostic.len() <= TEST_SUBPROCESS_DIAGNOSTIC_LIMIT);
        assert!(diagnostic.ends_with(TEST_SUBPROCESS_DIAGNOSTIC_MARKER));
        assert!(diagnostic.contains('\u{FFFD}'));
    }

    #[test]
    fn never_eof_capture_is_cancelled_within_the_join_deadline() {
        let reader = BoundedTestCaptureReader::spawn(
            NeverEofCapturePipe,
            "never-eof",
            Arc::new(AtomicBool::new(false)),
        )
        .expect("start never-EOF capture");
        let started = Instant::now();
        let captured = reader.finish_until(Instant::now() + Duration::from_millis(50));

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "capture cancellation exceeded its bounded join window"
        );
        assert!(captured.done);
        assert!(
            captured
                .error
                .as_deref()
                .is_some_and(|error| error.contains("cancelled before EOF")),
            "{captured:?}"
        );
    }

    #[test]
    fn sleep_worker() {
        let Some(marker) = std::env::var_os(SLEEP_WORKER) else {
            return;
        };
        println!("bounded child stdout");
        std::io::stdout().flush().unwrap();
        eprintln!("bounded child stderr");
        fs_write(PathBuf::from(&marker).with_extension("started"), b"started");
        std::thread::sleep(Duration::from_secs(30));
        fs_write(
            PathBuf::from(marker).with_extension("finished"),
            b"finished",
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_cleanup_reaps_exact_child_before_guardian_finalization() {
        let temp = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::sleep_worker",
                "--nocapture",
            ])
            .env(SLEEP_WORKER, temp.path().join("retained-cleanup"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (child, tree) = TestProcessTree::spawn(command, "retained cleanup fixture").unwrap();

        let status = RetainedTestProcessCleanup { child, tree }.run();
        assert!(
            !status.success(),
            "retained cleanup did not terminate its exact direct child"
        );
    }

    #[test]
    fn timeout_kills_and_reaps_a_stalled_child_with_output() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("bounded-child");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::sleep_worker",
                "--nocapture",
            ])
            .env(SLEEP_WORKER, &marker);

        let started = Instant::now();
        let timeout = Duration::from_secs(5);
        let error = output_with_timeout(command, "bounded sleep-worker fixture", timeout)
            .expect_err("the bounded helper must terminate the sleeping worker");

        let message = format!("{error:#}");
        assert!(message.contains("timed out"), "{message}");
        assert!(
            message.contains("containment-cleanup error: none"),
            "{message}"
        );
        assert!(message.contains("direct child reaped: true"), "{message}");
        assert!(started.elapsed() < timeout + TEST_SUBPROCESS_REAP_GRACE + Duration::from_secs(2));
        assert!(message.contains("bounded child stdout"), "{message}");
        assert!(message.contains("bounded child stderr"), "{message}");
        assert!(marker.with_extension("started").is_file());
        assert!(!marker.with_extension("finished").exists());
    }

    #[test]
    fn descendant_worker() {
        if let Some(marker) = std::env::var_os(DESCENDANT_MARKER) {
            println!("descendant inherited stdout");
            std::io::stdout().flush().unwrap();
            let pid_marker = PathBuf::from(&marker).with_extension("pid");
            let staged_pid_marker = PathBuf::from(&marker).with_extension("pid.staged");
            fs_write(
                staged_pid_marker.clone(),
                std::process::id().to_string().as_bytes(),
            );
            std::fs::rename(staged_pid_marker, pid_marker).unwrap();
            std::thread::sleep(Duration::from_secs(30));
            fs_write(
                PathBuf::from(marker).with_extension("finished"),
                b"finished",
            );
            return;
        }
        let Some(marker) = std::env::var_os(DESCENDANT_PARENT) else {
            return;
        };
        let marker = PathBuf::from(marker);
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::test_subprocess::tests::descendant_worker",
                "--nocapture",
            ])
            .env(DESCENDANT_MARKER, &marker)
            .spawn()
            .unwrap();
        let pid_marker = marker.with_extension("pid");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut descendant_pid = None;
        while descendant_pid.is_none() && Instant::now() < deadline {
            assert!(descendant.try_wait().unwrap().is_none());
            std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
            descendant_pid = std::fs::read_to_string(&pid_marker)
                .ok()
                .and_then(|contents| contents.trim().parse::<u32>().ok());
        }
        assert!(
            descendant_pid.is_some(),
            "descendant never published a parseable PID marker"
        );
        drop(descendant);
    }

    #[test]
    fn inherited_descendant_output_cannot_escape_deadline_or_survive_return() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("bounded-descendant");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::descendant_worker",
                "--nocapture",
            ])
            .env(DESCENDANT_PARENT, &marker);

        let started = Instant::now();
        let output = output_with_timeout(
            command,
            "inherited-output descendant fixture",
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(String::from_utf8_lossy(&output.stdout).contains("descendant inherited stdout"));
        let pid = std::fs::read_to_string(marker.with_extension("pid"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(
            !process_is_live(pid),
            "descendant process {pid} survived helper return"
        );
        assert!(!marker.with_extension("finished").exists());
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_cleanup_disarms_numeric_process_group_before_repeat_cleanup_and_drop() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "commands::test_subprocess::tests::sleep_worker",
            "--nocapture",
        ]);
        let (mut child, mut tree) =
            TestProcessTree::spawn(command, "one-shot process-group worker").unwrap();
        assert!(matches!(
            tree.process_group,
            Some(UnixTestProcessGroup::Armed)
        ));
        assert!(child.wait().unwrap().success());

        tree.terminate().unwrap();
        assert!(matches!(
            tree.process_group,
            Some(UnixTestProcessGroup::TerminationRequested)
        ));
        tree.terminate()
            .expect("a repeated terminate request must not signal the numeric PGID again");
        confirm_reap_and_disarm_tree(&mut tree, None).unwrap();
        terminate_and_confirm_tree(&mut tree)
            .expect("cleanup after disarm must remain a signal-free no-op");

        assert!(
            tree.process_group.is_none(),
            "confirmed cleanup retained a numeric PGID that Drop could signal after reuse"
        );
        assert!(
            tree.guardian.is_none(),
            "confirmed cleanup retained an already-reaped guardian"
        );
        drop(tree);
    }

    #[cfg(unix)]
    #[test]
    fn guardian_exit_before_readiness_is_cleaned_without_reaping_identity_first() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::sleep_worker",
                "--nocapture",
            ])
            .env(
                kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY_ENV,
                "1",
            );
        let error =
            match TestProcessTree::spawn(command, "guardian early-exit process-group worker") {
                Ok((mut child, mut tree)) => {
                    let _ = child.kill();
                    let _ = poll_child_until(
                        &mut child,
                        Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                        "unexpected early-exit worker",
                    );
                    let _ = terminate_and_confirm_tree(&mut tree);
                    panic!("guardian unexpectedly published readiness");
                }
                Err(error) => error,
            };
        let message = format!("{error:#}");
        assert!(
            message.contains("readiness"),
            "unexpected early-guardian-exit error: {message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_death_guardian_descendant_worker() {
        if let Some(marker) = std::env::var_os(PARENT_DEATH_DESCENDANT) {
            let pid_marker = PathBuf::from(&marker).with_extension("pid");
            let staged_pid_marker = PathBuf::from(&marker).with_extension("pid.staged");
            fs_write(
                staged_pid_marker.clone(),
                std::process::id().to_string().as_bytes(),
            );
            std::fs::rename(staged_pid_marker, pid_marker).unwrap();
            std::thread::sleep(Duration::from_secs(30));
            fs_write(
                PathBuf::from(marker).with_extension("finished"),
                b"finished",
            );
            return;
        }
        let Some(marker) = std::env::var_os(PARENT_DEATH_OWNER) else {
            return;
        };
        let marker = PathBuf::from(marker);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::parent_death_guardian_descendant_worker",
                "--nocapture",
            ])
            .env_remove(PARENT_DEATH_OWNER)
            .env(PARENT_DEATH_DESCENDANT, &marker);
        let output = output_with_timeout(
            command,
            "parent-death guarded descendant",
            Duration::from_secs(30),
        );
        panic!("parent-death owner unexpectedly survived its wait: {output:?}");
    }

    #[cfg(unix)]
    struct KillAndReapChild(Option<Child>);

    #[cfg(unix)]
    impl KillAndReapChild {
        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("child has not been reaped")
        }

        fn kill_and_reap(&mut self) {
            let mut child = self.0.take().expect("child has not been reaped");
            child.kill().unwrap();
            assert!(
                poll_child_until(
                    &mut child,
                    Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                    "parent-death owner",
                )
                .unwrap()
                .is_some(),
                "parent-death owner was not reaped"
            );
        }
    }

    #[cfg(unix)]
    impl Drop for KillAndReapChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = poll_child_until(
                    child,
                    Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                    "parent-death owner Drop cleanup",
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_parent_death_closes_ownership_pipe_and_kills_guarded_descendant() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("parent-death");
        let mut owner = Command::new(std::env::current_exe().unwrap());
        owner
            .args([
                "--exact",
                "commands::test_subprocess::tests::parent_death_guardian_descendant_worker",
                "--nocapture",
            ])
            .env(PARENT_DEATH_OWNER, &marker)
            .env_remove(PARENT_DEATH_DESCENDANT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_test_subprocess_command(&mut owner, false);
        let mut owner = KillAndReapChild(Some(owner.spawn().unwrap()));
        let pid_marker = marker.with_extension("pid");
        let ready_deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
        let descendant = loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_marker) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    break pid;
                }
            }
            assert!(
                owner.child_mut().try_wait().unwrap().is_none(),
                "parent-death owner exited before its descendant became ready"
            );
            assert!(
                Instant::now() < ready_deadline,
                "guarded descendant never published a parseable PID marker: {:?}",
                std::fs::read_to_string(&pid_marker)
            );
            std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
        };

        owner.kill_and_reap();
        let death_deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
        while process_is_live(descendant) && Instant::now() < death_deadline {
            std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
        }
        assert!(
            !process_is_live(descendant),
            "guardian ownership-pipe EOF did not kill descendant {descendant}"
        );
        assert!(!marker.with_extension("finished").exists());
    }

    #[test]
    fn worker_and_guardian_scrub_ambient_and_command_local_authority() {
        if let Some(marker) = std::env::var_os(AUTHORITY_INNER) {
            for key in HOSTILE_AUTHORITY_KEYS {
                assert!(
                    std::env::var_os(key).is_none(),
                    "worker inherited hostile authority {key}"
                );
            }
            for (key, expected) in ALLOWED_WORKER_INPUTS {
                assert_eq!(
                    std::env::var(key).as_deref(),
                    Ok(*expected),
                    "worker did not receive explicit allowlisted input {key}"
                );
            }
            assert!(std::env::var_os("KIN_DIR").is_none());
            assert!(std::env::var_os("KIN_MCP_REPO").is_none());
            fs_write(PathBuf::from(marker), b"scrubbed");
            return;
        }

        if let Some(marker) = std::env::var_os(AUTHORITY_OUTER) {
            for key in HOSTILE_AUTHORITY_KEYS {
                std::env::set_var(key, "ambient-hostile");
            }
            for (key, _) in ALLOWED_WORKER_INPUTS {
                std::env::set_var(key, "ambient-hostile");
            }
            std::env::set_var("KIN_DIR", "/ambient/legacy-home");
            std::env::set_var("KIN_MCP_REPO", "/ambient/repository");

            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "commands::test_subprocess::tests::worker_and_guardian_scrub_ambient_and_command_local_authority",
                    "--nocapture",
                ])
                .env(AUTHORITY_INNER, &marker)
                .env_remove(AUTHORITY_OUTER)
                .env_remove("KIN_DIR")
                .env_remove("KIN_MCP_REPO");
            for key in HOSTILE_AUTHORITY_KEYS {
                command.env(key, "command-hostile");
            }
            for (key, value) in ALLOWED_WORKER_INPUTS {
                command.env(key, value);
            }
            let output = output_with_timeout(
                command,
                "authority-isolated nested worker",
                Duration::from_secs(10),
            )
            .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("authority-scrubbed");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::test_subprocess::tests::worker_and_guardian_scrub_ambient_and_command_local_authority",
                "--nocapture",
            ])
            .env(AUTHORITY_OUTER, &marker);
        let output = output_with_timeout(
            command,
            "ambient-authority isolation owner",
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(std::fs::read(&marker).unwrap(), b"scrubbed");
    }

    fn fs_write(path: PathBuf, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    #[cfg(unix)]
    fn process_is_live(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(windows)]
    fn process_is_live(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return false;
        }
        let mut code = 0;
        let queried = unsafe { GetExitCodeProcess(process, &mut code) } != 0;
        let _ = unsafe { CloseHandle(process) };
        queried && code == STILL_ACTIVE as u32
    }

    #[cfg(not(any(unix, windows)))]
    fn process_is_live(_pid: u32) -> bool {
        false
    }
}
