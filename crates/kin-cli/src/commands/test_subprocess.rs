// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded subprocess execution for native CLI tests.
//!
//! Regular files, rather than pipes, capture output so a descendant inheriting
//! stdout or stderr cannot keep the caller blocked after the direct child exits.
//! On Unix, every worker gets its own process group, which is terminated and
//! proven empty before captured output is read or control returns to the test.
//! Workers must not detach or call `setsid`, because that escapes the bounded
//! process-group contract. On Windows, each worker is assigned to a
//! kill-on-close Job Object that contains its descendants.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
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

/// Build a Git command for a temporary test repository without inheriting the
/// developer's Git repository or configuration authority.
///
/// In particular, a global `core.hooksPath` must not make fixture commits run
/// real user hooks. Production Git commands intentionally do not use this
/// helper.
pub(crate) fn fixture_git(repository: &Path) -> Command {
    let mut command = Command::new("git");
    isolate_fixture_git(&mut command, repository);
    command
}

fn isolate_fixture_git(command: &mut Command, repository: &Path) {
    command
        .current_dir(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");
    #[cfg(not(any(unix, windows)))]
    command.env(
        "GIT_CONFIG_GLOBAL",
        repository.join(".kin-test-global-gitconfig"),
    );

    for inherited in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
    ] {
        command.env_remove(inherited);
    }
    let explicit_config = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|_| key.to_os_string()))
        .filter(|key| is_git_command_config(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_git_command_config(key))
        .chain(explicit_config)
    {
        command.env_remove(key);
    }
}

fn is_git_command_config(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    label == "GIT_CONFIG_COUNT"
        || label.starts_with("GIT_CONFIG_KEY_")
        || label.starts_with("GIT_CONFIG_VALUE_")
}

#[cfg(unix)]
struct TestProcessTree {
    process_group: libc::pid_t,
}

#[cfg(unix)]
impl TestProcessTree {
    fn spawn(command: &mut Command, label: &str) -> Result<(Child, Self)> {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {label}"))?;
        let process_group = libc::pid_t::try_from(child.id())
            .context("test subprocess id does not fit a native process-group id")?;
        Ok((child, Self { process_group }))
    }

    fn terminate(&self) -> Result<()> {
        let result = unsafe { libc::kill(-self.process_group, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error).context("failed to terminate bounded test process group")
        }
    }

    fn is_empty(&self) -> Result<bool> {
        let result = unsafe { libc::kill(-self.process_group, 0) };
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(true),
            Some(libc::EPERM) => Ok(false),
            _ => Err(error).context("failed to inspect bounded test process group"),
        }
    }
}

#[cfg(unix)]
impl Drop for TestProcessTree {
    fn drop(&mut self) {
        let _ = self.terminate();
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
    fn spawn(command: &mut Command, label: &str) -> Result<(Child, Self)> {
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
        let tree = Self { job };
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
                    Some(&tree),
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
                Some(&tree),
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
                Some(&tree),
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
                Some(&tree),
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
        tree: Option<&Self>,
        label: &str,
        cause: String,
    ) -> anyhow::Error {
        let deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
        let tree_terminate_error = tree.and_then(|tree| tree.terminate().err());
        let direct_kill_error = child.kill().err();
        let (reaped, reap_error) = match poll_child_until(child, deadline, label) {
            Ok(status) => (status.is_some(), None),
            Err(error) => (false, Some(error)),
        };
        let tree_error = tree
            .and_then(|tree| confirm_tree_empty_until(tree, deadline, tree_terminate_error).err());
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

    fn terminate(&self) -> Result<()> {
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
    fn spawn(command: &mut Command, label: &str) -> Result<(Child, Self)> {
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {label}"))?;
        Ok((child, Self))
    }

    fn terminate(&self) -> Result<()> {
        Ok(())
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(true)
    }
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
    tree: &TestProcessTree,
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

fn terminate_and_confirm_tree(tree: &TestProcessTree) -> Result<()> {
    let terminate_error = tree.terminate().err();
    confirm_tree_empty_until(
        tree,
        Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
        terminate_error,
    )
}

fn read_captured_file(mut file: File, label: &str) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to rewind captured {label}"))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read captured {label}"))?;
    Ok(bytes)
}

fn read_captured_output(stdout: File, stderr: File, status: ExitStatus) -> Result<Output> {
    Ok(Output {
        status,
        stdout: read_captured_file(stdout, "stdout")?,
        stderr: read_captured_file(stderr, "stderr")?,
    })
}

pub(crate) fn output_with_timeout(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<Output> {
    let stdout = tempfile::tempfile().context("failed to create bounded stdout capture")?;
    let stderr = tempfile::tempfile().context("failed to create bounded stderr capture")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout
                .try_clone()
                .context("failed to clone bounded stdout capture")?,
        ))
        .stderr(Stdio::from(
            stderr
                .try_clone()
                .context("failed to clone bounded stderr capture")?,
        ));

    let (mut child, tree) = TestProcessTree::spawn(command, label)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_and_confirm_tree(&tree)
                    .with_context(|| format!("failed to clean descendants after {label} exited"))?;
                return read_captured_output(stdout, stderr, status);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
            }
            Ok(None) => {
                let cleanup_deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
                let tree_terminate_error = tree.terminate().err();
                let direct_kill_error = child.kill().err();
                let (status, reap_error) =
                    match poll_child_until(&mut child, cleanup_deadline, label) {
                        Ok(status) => (status, None),
                        Err(error) => (None, Some(error)),
                    };
                let tree_error =
                    confirm_tree_empty_until(&tree, cleanup_deadline, tree_terminate_error).err();
                let direct_child_reaped = status.is_some();
                let captured_stdout = read_captured_file(stdout, "stdout")?;
                let captured_stderr = read_captured_file(stderr, "stderr")?;
                anyhow::bail!(
                    "{label} timed out after {timeout:?}; direct-kill error: {direct_kill_error:?}; reap error: {}; containment-cleanup error: {}; direct child reaped: {}; stdout={} stderr={}",
                    reap_error
                        .as_ref()
                        .map(|error| format!("{error:#}"))
                        .unwrap_or_else(|| "none".to_string()),
                    tree_error
                        .as_ref()
                        .map(|error| format!("{error:#}"))
                        .unwrap_or_else(|| "none".to_string()),
                    direct_child_reaped,
                    String::from_utf8_lossy(&captured_stdout),
                    String::from_utf8_lossy(&captured_stderr)
                );
            }
            Err(error) => {
                let cleanup_deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
                let tree_terminate_error = tree.terminate().err();
                let direct_kill_error = child.kill().err();
                let (reaped, reap_error) =
                    match poll_child_until(&mut child, cleanup_deadline, label) {
                        Ok(status) => (status, None),
                        Err(error) => (None, Some(error)),
                    };
                let tree_error =
                    confirm_tree_empty_until(&tree, cleanup_deadline, tree_terminate_error).err();
                anyhow::bail!(
                    "failed to poll {label}: {error}; direct-kill error: {direct_kill_error:?}; reap error: {}; containment-cleanup error: {}; direct child reaped: {}",
                    reap_error
                        .as_ref()
                        .map(|cleanup| format!("{cleanup:#}"))
                        .unwrap_or_else(|| "none".to_string()),
                    tree_error
                        .as_ref()
                        .map(|cleanup| format!("{cleanup:#}"))
                        .unwrap_or_else(|| "none".to_string()),
                    reaped.is_some()
                );
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
    #[test]
    fn fixture_git_ignores_global_hooks() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let hooks = temp.path().join("hooks");
        let repository = temp.path().join("repository");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            format!("[core]\n\thooksPath = {}\n", hooks.display()),
        )
        .unwrap();
        let pre_commit = hooks.join("pre-commit");
        std::fs::write(&pre_commit, b"#!/bin/sh\nexit 91\n").unwrap();
        let mut permissions = std::fs::metadata(&pre_commit).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&pre_commit, permissions).unwrap();

        let run = |args: &[&str]| {
            let mut command = Command::new("git");
            command
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", home.join(".config"))
                .env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "core.hooksPath")
                .env("GIT_CONFIG_VALUE_0", &hooks)
                .env("GIT_CONFIG_PARAMETERS", "malformed hostile fixture config");
            isolate_fixture_git(&mut command, &repository);
            let output = command.args(args).output().unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["init", "--initial-branch=main"]);
        run(&["config", "user.email", "kin@example.invalid"]);
        run(&["config", "user.name", "Kin Test"]);
        std::fs::write(repository.join("README.md"), b"fixture\n").unwrap();
        run(&["add", "README.md"]);
        run(&["commit", "-m", "fixture"]);
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
        let error = output_with_timeout(&mut command, "bounded sleep-worker fixture", timeout)
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
            fs_write(
                PathBuf::from(&marker).with_extension("pid"),
                std::process::id().to_string().as_bytes(),
            );
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
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.with_extension("pid").is_file() && Instant::now() < deadline {
            assert!(descendant.try_wait().unwrap().is_none());
            std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
        }
        assert!(marker.with_extension("pid").is_file());
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
            &mut command,
            "inherited-output descendant fixture",
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(String::from_utf8_lossy(&output.stdout).contains("descendant inherited stdout"));
        let pid = std::fs::read_to_string(marker.with_extension("pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(
            !process_is_live(pid),
            "descendant process {pid} survived helper return"
        );
        assert!(!marker.with_extension("finished").exists());
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
