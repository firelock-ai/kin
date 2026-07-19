// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded subprocess execution for native CLI tests.
//!
//! Regular files, rather than pipes, capture output so a descendant inheriting
//! stdout or stderr cannot keep the caller blocked after the direct child exits.
//! Every worker gets its own process tree, which is terminated and proven empty
//! before captured output is read or control returns to the test.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_TEST_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const TEST_SUBPROCESS_REAP_GRACE: Duration = Duration::from_secs(5);
const TEST_SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
impl TestProcessTree {
    fn spawn(command: &mut Command, label: &str) -> Result<(Child, Self)> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
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

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn {label}"))?;
        let assigned = unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle()) };
        if assigned == 0 {
            let assign_error = std::io::Error::last_os_error();
            let kill_error = child.kill().err();
            let reaped = poll_child_until(
                &mut child,
                Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                label,
            )?;
            anyhow::bail!(
                "failed to assign {label} to its bounded job object: {assign_error}; direct-kill error: {kill_error:?}; reaped: {}",
                reaped.is_some()
            );
        }
        Ok((child, tree))
    }

    fn terminate(&self) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if self.is_empty()? {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            let error = std::io::Error::last_os_error();
            if self.is_empty()? {
                return Ok(());
            }
            return Err(error).context("failed to terminate bounded test job object");
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

fn terminate_and_confirm_tree(tree: &TestProcessTree) -> Result<()> {
    let terminate_error = tree.terminate().err();
    let deadline = Instant::now() + TEST_SUBPROCESS_REAP_GRACE;
    loop {
        if tree.is_empty()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            if let Some(error) = terminate_error {
                anyhow::bail!(
                    "bounded test process tree remained live after termination failed: {error:#}"
                );
            }
            anyhow::bail!("bounded test process tree remained live after termination deadline");
        }
        std::thread::sleep(TEST_SUBPROCESS_POLL_INTERVAL);
    }
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
                let direct_kill_error = child.kill().err();
                let tree_error = terminate_and_confirm_tree(&tree).err();
                let status = poll_child_until(
                    &mut child,
                    Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                    label,
                )?;
                let direct_child_reaped = status.is_some();
                let captured_stdout = read_captured_file(stdout, "stdout")?;
                let captured_stderr = read_captured_file(stderr, "stderr")?;
                anyhow::bail!(
                    "{label} timed out after {timeout:?}; direct-kill error: {direct_kill_error:?}; tree-cleanup error: {}; direct child reaped: {}; stdout={} stderr={}",
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
                let direct_kill_error = child.kill().err();
                let tree_error = terminate_and_confirm_tree(&tree).err();
                let reaped = poll_child_until(
                    &mut child,
                    Instant::now() + TEST_SUBPROCESS_REAP_GRACE,
                    label,
                )?;
                anyhow::bail!(
                    "failed to poll {label}: {error}; direct-kill error: {direct_kill_error:?}; tree-cleanup error: {}; direct child reaped: {}",
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

        let error = output_with_timeout(
            &mut command,
            "bounded sleep-worker fixture",
            Duration::from_secs(5),
        )
        .expect_err("the bounded helper must terminate the sleeping worker");

        let message = format!("{error:#}");
        assert!(message.contains("timed out"), "{message}");
        assert!(message.contains("direct child reaped: true"), "{message}");
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
