// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Test-only subprocess isolation for temporary Git repositories.
//!
//! The fixture boundary owns both authority isolation and process lifetime.
//! Callers cannot obtain the inner [`std::process::Command`], launch it
//! directly, or attach a pipe that a detached descendant could keep open.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

/// Wall-clock backstop for a Git fixture.
///
/// Fixture commands normally finish in well under a second. The generous cap
/// avoids converting machine saturation into a false failure while still
/// ensuring that every launch is bounded.
pub const DEFAULT_FIXTURE_GIT_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-stream byte ceiling for fixture stdout and stderr.
pub const DEFAULT_FIXTURE_GIT_CAPTURE_LIMIT: u64 = 16 * 1024 * 1024;
const FIXTURE_GIT_REAP_GRACE: Duration = Duration::from_secs(5);
const FIXTURE_GIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CAPTURE_TRUNCATION_MARKER: &[u8] = b"\n[output truncated at capture limit]\n";

/// A test-only Git command whose authority and lifetime are enforced at launch.
///
/// There is deliberately no `Deref<Target = Command>`, `spawn`, or stdio
/// customization API. That keeps final scrubbing, bounded active capture, the
/// hard deadline, and whole-tree cleanup impossible to bypass accidentally.
pub struct FixtureGitCommand {
    inner: Command,
    sandbox: tempfile::TempDir,
    host_path: OsString,
    safe_git_environment: BTreeMap<&'static str, OsString>,
    label: &'static str,
}

impl std::fmt::Debug for FixtureGitCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixtureGitCommand")
            .field("inner", &self.inner)
            .field("sandbox", &self.sandbox.path())
            .field("host_path", &self.host_path)
            .field("safe_git_environment", &self.safe_git_environment)
            .finish()
    }
}

impl FixtureGitCommand {
    fn git() -> Self {
        let resolution_root = std::env::current_dir()
            .unwrap_or_else(|error| panic!("locate current directory for host Git: {error}"));
        let host_path = absolute_fixture_host_path(raw_fixture_host_path(), &resolution_root)
            .unwrap_or_else(|error| {
                panic!(
                    "normalize KIN_ORIGINAL_PATH/PATH against {} for host Git: {error}",
                    resolution_root.display()
                )
            });
        let git =
            which::which_in("git", Some(&host_path), &resolution_root).unwrap_or_else(|error| {
                panic!(
                    "locate host Git executable from KIN_ORIGINAL_PATH/PATH at {}: {error}",
                    resolution_root.display()
                )
            });
        let git = if git.is_absolute() {
            git
        } else {
            resolution_root.join(git)
        };
        let mut command = Self::for_program_with_host_path(git, "Git fixture", host_path);
        let hooks = command.sandbox.path().join("hooks");
        std::fs::create_dir_all(&hooks).expect("create isolated Git fixture hooks directory");
        let mut hooks_config = OsString::from("core.hooksPath=");
        hooks_config.push(hooks.as_os_str());
        command.inner.args([
            OsStr::new("-c"),
            hooks_config.as_os_str(),
            OsStr::new("-c"),
            OsStr::new("maintenance.auto=false"),
            OsStr::new("-c"),
            OsStr::new("gc.auto=0"),
            OsStr::new("-c"),
            OsStr::new("protocol.file.allow=always"),
        ]);
        command
    }

    #[cfg(test)]
    fn for_program(program: impl AsRef<OsStr>, label: &'static str) -> Self {
        Self::for_program_with_host_path(program, label, fixture_host_path())
    }

    fn for_program_with_host_path(
        program: impl AsRef<OsStr>,
        label: &'static str,
        host_path: OsString,
    ) -> Self {
        let sandbox = tempfile::Builder::new()
            .prefix("kin-git-fixture-")
            .tempdir()
            .expect("create isolated Git fixture sandbox");
        std::fs::create_dir_all(sandbox.path().join("home"))
            .expect("create isolated Git fixture home");
        std::fs::create_dir_all(sandbox.path().join("xdg"))
            .expect("create isolated Git fixture XDG home");
        Self {
            inner: Command::new(program),
            sandbox,
            host_path,
            safe_git_environment: BTreeMap::new(),
            label,
        }
    }

    pub fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.inner.arg(argument);
        self
    }

    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(arguments);
        self
    }

    pub fn current_dir(&mut self, directory: impl AsRef<Path>) -> &mut Self {
        self.inner.current_dir(directory);
        self
    }

    /// Add a command-local environment value.
    ///
    /// Git, loader, VFS, and external-program authority is scrubbed again at
    /// launch, so this method cannot be used to bypass isolation. Intentional
    /// fixture identities and dates must use the explicit methods below.
    pub fn env<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner.env(key, value);
        self
    }

    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env_remove(key);
        self
    }

    pub fn author_name(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_AUTHOR_NAME", value.as_ref().to_os_string());
        self
    }

    pub fn author_email(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_AUTHOR_EMAIL", value.as_ref().to_os_string());
        self
    }

    pub fn author_date(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_AUTHOR_DATE", value.as_ref().to_os_string());
        self
    }

    pub fn committer_name(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_COMMITTER_NAME", value.as_ref().to_os_string());
        self
    }

    pub fn committer_email(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_COMMITTER_EMAIL", value.as_ref().to_os_string());
        self
    }

    pub fn committer_date(&mut self, value: impl AsRef<OsStr>) -> &mut Self {
        self.safe_git_environment
            .insert("GIT_COMMITTER_DATE", value.as_ref().to_os_string());
        self
    }

    pub fn output(&mut self) -> io::Result<Output> {
        self.output_with_optional_input(
            None,
            DEFAULT_FIXTURE_GIT_TIMEOUT,
            DEFAULT_FIXTURE_GIT_CAPTURE_LIMIT,
        )
    }

    pub fn output_with_timeout(&mut self, timeout: Duration) -> io::Result<Output> {
        self.output_with_optional_input(None, timeout, DEFAULT_FIXTURE_GIT_CAPTURE_LIMIT)
    }

    pub fn output_with_input(&mut self, input: &[u8]) -> io::Result<Output> {
        self.output_with_optional_input(
            Some(input),
            DEFAULT_FIXTURE_GIT_TIMEOUT,
            DEFAULT_FIXTURE_GIT_CAPTURE_LIMIT,
        )
    }

    #[cfg(test)]
    fn output_with_timeout_and_capture_limit(
        &mut self,
        timeout: Duration,
        max_capture_bytes_per_stream: u64,
    ) -> io::Result<Output> {
        self.output_with_optional_input(None, timeout, max_capture_bytes_per_stream)
    }

    fn output_with_optional_input(
        &mut self,
        input: Option<&[u8]>,
        timeout: Duration,
        max_capture_bytes_per_stream: u64,
    ) -> io::Result<Output> {
        self.prepare_for_launch();

        self.inner.stdout(Stdio::piped()).stderr(Stdio::piped());
        let _input = if let Some(bytes) = input {
            let mut file = tempfile::tempfile()?;
            file.write_all(bytes)?;
            file.seek(SeekFrom::Start(0))?;
            self.inner.stdin(Stdio::from(file.try_clone()?));
            Some(file)
        } else {
            self.inner.stdin(Stdio::null());
            None
        };

        let (mut child, mut tree) = FixtureProcessTree::spawn(&mut self.inner, self.label)?;
        let capture =
            match BoundedCapturePair::start(&mut child, max_capture_bytes_per_stream, self.label) {
                Ok(capture) => capture,
                Err(error) => {
                    let cleanup = cleanup_live_tree(&mut child, &mut tree, self.label);
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "failed to start {} bounded capture: {error}; {cleanup}",
                            self.label
                        ),
                    ));
                }
            };
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = capture.try_event() {
                match event {
                    CaptureEvent::LimitExceeded { stream } => {
                        let cleanup = cleanup_live_tree(&mut child, &mut tree, self.label);
                        let captured =
                            capture.finish_until(Instant::now() + FIXTURE_GIT_REAP_GRACE);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{stream} capture crossed its bounded sink; {}",
                                capture_limit_message(
                                    self.label,
                                    max_capture_bytes_per_stream,
                                    &cleanup,
                                    &captured,
                                )
                            ),
                        ));
                    }
                    CaptureEvent::ReadFailed { stream, error } => {
                        let cleanup = cleanup_live_tree(&mut child, &mut tree, self.label);
                        let captured =
                            capture.finish_until(Instant::now() + FIXTURE_GIT_REAP_GRACE);
                        return Err(io_other(format!(
                            "failed to read {} {stream} capture: {error}; {cleanup}; capture={}",
                            self.label,
                            captured.render_errors(),
                        )));
                    }
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    let cleanup = cleanup_reaped_tree(&mut tree);
                    let captured = capture.finish_until(Instant::now() + FIXTURE_GIT_REAP_GRACE);
                    cleanup.map_err(|error| {
                        io_other(format!(
                            "failed to clean descendants after {} exited: {error}",
                            self.label,
                        ))
                    })?;
                    if captured.any_truncated() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            capture_limit_message(
                                self.label,
                                max_capture_bytes_per_stream,
                                "cleanup=ok",
                                &captured,
                            ),
                        ));
                    }
                    if let Some(error) = captured.first_error() {
                        return Err(io_other(format!(
                            "failed to read {} bounded capture: {error}",
                            self.label
                        )));
                    }
                    return Ok(captured.into_output(status));
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
                }
                Ok(None) => {
                    let cleanup = cleanup_live_tree(&mut child, &mut tree, self.label);
                    let captured = capture.finish_until(Instant::now() + FIXTURE_GIT_REAP_GRACE);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{} timed out after {timeout:?}; {cleanup}; capture={}; stdout={} \
                             stderr={}",
                            self.label,
                            captured.render_errors(),
                            compact_capture(&captured.stdout),
                            compact_capture(&captured.stderr),
                        ),
                    ));
                }
                Err(error) => {
                    let cleanup = cleanup_live_tree(&mut child, &mut tree, self.label);
                    let captured = capture.finish_until(Instant::now() + FIXTURE_GIT_REAP_GRACE);
                    return Err(io_other(format!(
                        "failed to poll {}: {error}; {cleanup}; capture={}",
                        self.label,
                        captured.render_errors(),
                    )));
                }
            }
        }
    }

    fn prepare_for_launch(&mut self) {
        isolate_fixture_git(&mut self.inner);
        self.inner
            .env("PATH", &self.host_path)
            .env("HOME", self.sandbox.path().join("home"))
            .env("USERPROFILE", self.sandbox.path().join("home"))
            .env("XDG_CONFIG_HOME", self.sandbox.path().join("xdg"));
        for (key, value) in &self.safe_git_environment {
            self.inner.env(key, value);
        }
    }
}

/// Build a Git command without inheriting the developer's repository,
/// configuration, executable, or process-lifetime authority.
pub fn fixture_git() -> FixtureGitCommand {
    FixtureGitCommand::git()
}

/// Build an isolated Git command already bound to `repository`.
pub fn fixture_git_in(repository: &Path) -> FixtureGitCommand {
    let mut command = fixture_git();
    command.current_dir(repository);
    command
}

/// Remove Git, Kin VFS, dynamic-loader, and external-program authority from a
/// fixture command.
///
/// This lower-level function exists for test harnesses that wrap non-Git
/// commands too. [`FixtureGitCommand`] reapplies it immediately before every
/// launch so a later `.env(...)` cannot regain authority.
pub fn isolate_fixture_git(command: &mut Command) {
    let host_path = fixture_host_path();
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_fixture_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_fixture_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }

    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("PATH", host_path)
        .env("KIN_VFS_DISABLE", "1");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");
    #[cfg(not(any(unix, windows)))]
    command.env(
        "GIT_CONFIG_GLOBAL",
        command
            .get_current_dir()
            .unwrap_or_else(|| Path::new("."))
            .join(".kin-test-global-gitconfig"),
    );
}

fn fixture_host_path() -> OsString {
    let resolution_root = std::env::current_dir()
        .unwrap_or_else(|error| panic!("locate current directory for fixture host PATH: {error}"));
    absolute_fixture_host_path(raw_fixture_host_path(), &resolution_root).unwrap_or_else(|error| {
        panic!(
            "normalize fixture host PATH against {}: {error}",
            resolution_root.display()
        )
    })
}

fn raw_fixture_host_path() -> OsString {
    std::env::var_os("KIN_ORIGINAL_PATH")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default()
}

fn absolute_fixture_host_path(
    host_path: impl AsRef<OsStr>,
    resolution_root: &Path,
) -> io::Result<OsString> {
    let entries = std::env::split_paths(host_path.as_ref())
        .map(|entry| {
            if entry.is_absolute() {
                entry
            } else {
                resolution_root.join(entry)
            }
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).map_err(|error| {
        io_other(format!(
            "failed to make fixture host PATH absolute against {}: {error}",
            resolution_root.display()
        ))
    })
}

fn is_fixture_authority(key: &OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "KIN_VFS_")
        || env_name_eq(&label, "KIN_ORIGINAL_PATH")
        || env_name_eq(&label, "KIN_NO_VFS")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
        || env_name_eq(&label, "EMAIL")
        || env_name_eq(&label, "SSH_ASKPASS")
        || env_name_eq(&label, "SSH_ASKPASS_REQUIRE")
        || env_name_eq(&label, "SSH_AUTH_SOCK")
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

#[cfg(unix)]
struct FixtureProcessTree {
    process_group: Option<UnixFixtureProcessGroup>,
    guardian: Option<Child>,
    guardian_stdin: Option<std::process::ChildStdin>,
}

#[cfg(unix)]
fn isolate_fixture_guardian(command: &mut Command, host_path: &OsStr) {
    isolate_fixture_git(command);
    command.env("PATH", host_path);
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum UnixFixtureProcessGroup {
    Armed(libc::pid_t),
    TerminationRequested(libc::pid_t),
}

#[cfg(unix)]
impl UnixFixtureProcessGroup {
    fn id(self) -> libc::pid_t {
        match self {
            Self::Armed(process_group) | Self::TerminationRequested(process_group) => process_group,
        }
    }
}

#[cfg(unix)]
impl FixtureProcessTree {
    fn spawn(command: &mut Command, label: &str) -> io::Result<(Child, Self)> {
        use std::os::unix::process::CommandExt as _;

        let host_path = command
            .get_envs()
            .find(|(key, _)| env_name_eq(&key.to_string_lossy(), "PATH"))
            .and_then(|(_, value)| value.map(OsStr::to_os_string))
            .unwrap_or_else(fixture_host_path);
        // The guardian is the stable group leader and parent-death watchdog.
        // Its stdin stays open only while this test process is alive. If the
        // parent disappears, EOF makes the guardian kill its entire group.
        let mut guardian_command = Command::new("/bin/sh");
        guardian_command
            .args(["-c", "IFS= read -r _; kill -KILL 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        isolate_fixture_guardian(&mut guardian_command, &host_path);
        let mut guardian = guardian_command.spawn().map_err(|error| {
            io_other(format!(
                "failed to spawn parent-death guardian for {label}: {error}"
            ))
        })?;
        let process_group = libc::pid_t::try_from(guardian.id())
            .map_err(|_| io_other("fixture guardian id does not fit a native process-group id"))?;
        let guardian_stdin = match guardian.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = guardian.kill();
                let _ = guardian.wait();
                return Err(io_other(
                    "fixture guardian did not expose its watchdog stdin",
                ));
            }
        };
        let mut tree = Self {
            process_group: Some(UnixFixtureProcessGroup::Armed(process_group)),
            guardian: Some(guardian),
            guardian_stdin: Some(guardian_stdin),
        };

        command.process_group(process_group);
        match command.spawn() {
            Ok(child) => Ok((child, tree)),
            Err(error) => {
                let cleanup = cleanup_reaped_tree(&mut tree)
                    .err()
                    .map(|cleanup| format!("; guardian cleanup failed: {cleanup}"))
                    .unwrap_or_default();
                Err(io_other(format!(
                    "failed to spawn {label}: {error}{cleanup}"
                )))
            }
        }
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.guardian_stdin.take();
        let Some(UnixFixtureProcessGroup::Armed(process_group)) = self.process_group else {
            return Ok(());
        };
        // Mark the numeric group as already signaled before making the syscall.
        // Cleanup may continue to inspect this exact group, but neither a
        // second terminate call nor Drop may signal the number again.
        self.process_group = Some(UnixFixtureProcessGroup::TerminationRequested(process_group));
        let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(io_other(format!(
                "failed to terminate bounded Git fixture process group: {error}"
            )))
        }
    }

    fn reap_auxiliary_until(&mut self, deadline: Instant) -> io::Result<bool> {
        loop {
            let reaped = match self.guardian.as_mut() {
                Some(guardian) => guardian.try_wait()?.is_some(),
                None => true,
            };
            if reaped {
                self.guardian.take();
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
    }

    fn is_empty(&self) -> io::Result<bool> {
        let Some(process_group) = self.process_group else {
            return Ok(true);
        };
        if self.guardian.is_none() {
            return Err(io_other(
                "cannot inspect Git fixture process group after releasing its stable guardian",
            ));
        }
        let system = sysinfo::System::new_all();
        for (pid, process) in system.processes() {
            let Ok(pid) = libc::pid_t::try_from(pid.as_u32()) else {
                continue;
            };
            if unsafe { libc::getpgid(pid) } == process_group.id()
                && !matches!(
                    process.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn disarm_after_confirmed_cleanup(&mut self) {
        self.process_group.take();
    }
}

#[cfg(unix)]
impl Drop for FixtureProcessTree {
    fn drop(&mut self) {
        // Closing the ownership pipe is the guardian's parent-death signal.
        // Let the stable group leader consume EOF and execute its group kill;
        // killing/reaping it here could win that race after quiescence failed
        // and discard the last trustworthy owner of the numeric PGID.
        self.guardian_stdin.take();
        // Only an authority that was never asked to terminate can signal here.
        // A termination-requested numeric PGID is discarded without reuse.
        if let Some(UnixFixtureProcessGroup::Armed(process_group)) = self.process_group.take() {
            let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        }
        // Deliberately drop, rather than kill or wait on, an unreaped guardian.
        // Successful cleanup already reaps it and sets this field to None.
        // On a failed empty-group proof, retaining the child process lets the
        // EOF watchdog finish before the OS releases its group-leader identity.
    }
}

#[cfg(windows)]
struct FixtureProcessTree {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
struct FixtureOwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for FixtureOwnedHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
impl FixtureProcessTree {
    fn spawn(command: &mut Command, label: &str) -> io::Result<(Child, Self)> {
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
            return Err(io_other(format!(
                "failed to create bounded Git fixture job: {}",
                io::Error::last_os_error()
            )));
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
            return Err(io_other(format!(
                "failed to configure bounded Git fixture job: {}",
                io::Error::last_os_error()
            )));
        }

        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command
            .spawn()
            .map_err(|error| io_other(format!("failed to spawn {label}: {error}")))?;
        if unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle()) } == 0 {
            let cause = format!(
                "failed to assign {label} to bounded job: {}",
                io::Error::last_os_error()
            );
            return Err(failed_windows_spawn_cleanup(
                &mut child, &mut tree, label, cause,
            ));
        }

        let thread_id = (|| -> io::Result<u32> {
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(io_other(format!(
                    "failed to snapshot suspended fixture threads: {}",
                    io::Error::last_os_error()
                )));
            }
            let snapshot = FixtureOwnedHandle(snapshot);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_MORE_FILES {
                    return Err(io_other(
                        "suspended Git fixture has no enumerable primary thread",
                    ));
                }
                return Err(io_other(format!(
                    "failed to begin fixture thread enumeration: {}",
                    io::Error::from_raw_os_error(error as i32)
                )));
            }
            let expected_size = std::mem::size_of::<THREADENTRY32>() as u32;
            let minimum_size = (std::mem::offset_of!(THREADENTRY32, th32OwnerProcessID)
                + std::mem::size_of::<u32>()) as u32;
            let mut matches = Vec::new();
            loop {
                if entry.dwSize < minimum_size {
                    return Err(io_other(format!(
                        "suspended fixture thread entry is too small: {} (minimum {minimum_size})",
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
                    return Err(io_other(format!(
                        "failed during fixture thread enumeration: {}",
                        io::Error::from_raw_os_error(error as i32)
                    )));
                }
            }
            if matches.len() != 1 {
                return Err(io_other(format!(
                    "suspended Git fixture must have exactly one primary thread, found {}",
                    matches.len()
                )));
            }
            Ok(matches[0])
        })();
        let thread_id = match thread_id {
            Ok(thread_id) => thread_id,
            Err(error) => {
                return Err(failed_windows_spawn_cleanup(
                    &mut child,
                    &mut tree,
                    label,
                    format!("failed to bind suspended fixture primary thread: {error}"),
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
            let error = io::Error::last_os_error();
            return Err(failed_windows_spawn_cleanup(
                &mut child,
                &mut tree,
                label,
                format!("failed to open suspended fixture primary thread: {error}"),
            ));
        }
        let thread = FixtureOwnedHandle(thread);
        let owner = unsafe { GetProcessIdOfThread(thread.0) };
        let expected_owner = child.id();
        if owner != expected_owner {
            return Err(failed_windows_spawn_cleanup(
                &mut child,
                &mut tree,
                label,
                format!(
                    "suspended fixture primary thread owner changed: expected {}, observed {owner}",
                    expected_owner
                ),
            ));
        }
        let previous_suspend_count = unsafe { ResumeThread(thread.0) };
        if previous_suspend_count != 1 {
            return Err(failed_windows_spawn_cleanup(
                &mut child,
                &mut tree,
                label,
                format!(
                    "suspended fixture primary thread resume returned {previous_suspend_count}, expected 1"
                ),
            ));
        }
        Ok((child, tree))
    }

    fn terminate(&mut self) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if unsafe { TerminateJobObject(self.job, 1) } == 0 {
            return Err(io_other(format!(
                "failed to terminate bounded Git fixture job: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant) -> io::Result<bool> {
        Ok(true)
    }

    fn is_empty(&self) -> io::Result<bool> {
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
            return Err(io_other(format!(
                "failed to inspect bounded Git fixture job: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(accounting.ActiveProcesses == 0)
    }

    fn disarm_after_confirmed_cleanup(&mut self) {}
}

#[cfg(windows)]
impl Drop for FixtureProcessTree {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        let _ = self.terminate();
        let _ = unsafe { CloseHandle(self.job) };
    }
}

#[cfg(windows)]
fn failed_windows_spawn_cleanup(
    child: &mut Child,
    tree: &mut FixtureProcessTree,
    label: &str,
    cause: String,
) -> io::Error {
    let cleanup = cleanup_live_tree(child, tree, label);
    io_other(format!("{cause}; {cleanup}"))
}

#[cfg(not(any(unix, windows)))]
struct FixtureProcessTree;

#[cfg(not(any(unix, windows)))]
impl FixtureProcessTree {
    fn spawn(command: &mut Command, label: &str) -> io::Result<(Child, Self)> {
        command
            .spawn()
            .map(|child| (child, Self))
            .map_err(|error| io_other(format!("failed to spawn {label}: {error}")))
    }

    fn terminate(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn reap_auxiliary_until(&mut self, _deadline: Instant) -> io::Result<bool> {
        Ok(true)
    }

    fn is_empty(&self) -> io::Result<bool> {
        Ok(true)
    }

    fn disarm_after_confirmed_cleanup(&mut self) {}
}

fn cleanup_reaped_tree(tree: &mut FixtureProcessTree) -> io::Result<()> {
    let terminate_error = tree.terminate().err();
    confirm_tree_empty_until(
        tree,
        Instant::now() + FIXTURE_GIT_REAP_GRACE,
        terminate_error,
    )?;
    let auxiliary_reaped = tree.reap_auxiliary_until(Instant::now() + FIXTURE_GIT_REAP_GRACE)?;
    if !auxiliary_reaped {
        return Err(io_other(
            "bounded Git fixture guardian was not reaped before the cleanup deadline",
        ));
    }
    tree.disarm_after_confirmed_cleanup();
    Ok(())
}

fn cleanup_live_tree(child: &mut Child, tree: &mut FixtureProcessTree, label: &str) -> String {
    let deadline = Instant::now() + FIXTURE_GIT_REAP_GRACE;
    let terminate_error = tree.terminate().err();
    let direct_kill_error = child.kill().err();
    let (direct_reaped, reap_error) = match poll_child_until(child, deadline, label) {
        Ok(status) => (status.is_some(), None),
        Err(error) => (false, Some(error)),
    };
    let containment_error = confirm_tree_empty_until(
        tree,
        Instant::now() + FIXTURE_GIT_REAP_GRACE,
        terminate_error,
    )
    .err();
    let auxiliary_error = if containment_error.is_none() {
        match tree.reap_auxiliary_until(Instant::now() + FIXTURE_GIT_REAP_GRACE) {
            Ok(true) => None,
            Ok(false) => Some(io_other(
                "bounded Git fixture guardian was not reaped before the cleanup deadline",
            )),
            Err(error) => Some(error),
        }
    } else {
        Some(io_other(
            "guardian reap skipped because live containment was not disproven",
        ))
    };
    if containment_error.is_none() && auxiliary_error.is_none() {
        tree.disarm_after_confirmed_cleanup();
    };
    format!(
        "direct-kill error: {}; reap error: {}; auxiliary-reap error: {}; containment-cleanup error: {}; direct child reaped: {direct_reaped}",
        display_optional_error(direct_kill_error.as_ref()),
        display_optional_error(reap_error.as_ref()),
        display_optional_error(auxiliary_error.as_ref()),
        display_optional_error(containment_error.as_ref()),
    )
}

fn poll_child_until(
    child: &mut Child,
    deadline: Instant,
    label: &str,
) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| io_other(format!("failed to poll {label}: {error}")))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
    }
}

fn confirm_tree_empty_until(
    tree: &FixtureProcessTree,
    deadline: Instant,
    terminate_error: Option<io::Error>,
) -> io::Result<()> {
    loop {
        if tree.is_empty()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let suffix = terminate_error
                .map(|error| format!(" after termination failed: {error}"))
                .unwrap_or_default();
            return Err(io_other(format!(
                "bounded Git fixture containment remained live after the cleanup deadline{suffix}"
            )));
        }
        std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
    }
}

#[derive(Debug)]
enum CaptureEvent {
    LimitExceeded { stream: &'static str },
    ReadFailed { stream: &'static str, error: String },
}

struct BoundedCapturePair {
    events: mpsc::Receiver<CaptureEvent>,
    stdout: BoundedCaptureReader,
    stderr: BoundedCaptureReader,
}

impl BoundedCapturePair {
    fn start(
        child: &mut Child,
        max_capture_bytes_per_stream: u64,
        label: &str,
    ) -> io::Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io_other(format!("{label} stdout was not piped")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io_other(format!("{label} stderr was not piped")))?;
        let (events_tx, events) = mpsc::channel();
        let stdout = BoundedCaptureReader::spawn(
            stdout,
            "stdout",
            max_capture_bytes_per_stream,
            events_tx.clone(),
        )?;
        let stderr =
            BoundedCaptureReader::spawn(stderr, "stderr", max_capture_bytes_per_stream, events_tx)?;
        Ok(Self {
            events,
            stdout,
            stderr,
        })
    }

    fn try_event(&self) -> Option<CaptureEvent> {
        self.events.try_recv().ok()
    }

    fn finish_until(self, deadline: Instant) -> CapturedStreams {
        CapturedStreams {
            stdout: self.stdout.finish_until(deadline),
            stderr: self.stderr.finish_until(deadline),
        }
    }
}

struct BoundedCaptureReader {
    stream: &'static str,
    result: Option<mpsc::Receiver<CapturedBytes>>,
    thread: Option<std::thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}

impl BoundedCaptureReader {
    fn spawn<R>(
        reader: R,
        stream: &'static str,
        max_capture_bytes: u64,
        events: mpsc::Sender<CaptureEvent>,
    ) -> io::Result<Self>
    where
        R: CapturePipe,
    {
        reader.prepare_nonblocking()?;
        let (result_tx, result) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = Arc::clone(&cancel);
        let thread = std::thread::Builder::new()
            .name(format!("kin-git-capture-{stream}"))
            .spawn(move || {
                let captured = drain_bounded_stream(
                    reader,
                    stream,
                    max_capture_bytes,
                    &events,
                    &reader_cancel,
                );
                let _ = result_tx.send(captured);
            })?;
        Ok(Self {
            stream,
            result: Some(result),
            thread: Some(thread),
            cancel,
        })
    }

    fn finish_until(mut self, deadline: Instant) -> CapturedBytes {
        let result = self
            .result
            .as_ref()
            .expect("bounded capture result receiver remains owned");
        let wait = deadline.saturating_duration_since(Instant::now());
        let (capture, acknowledged) = match result.recv_timeout(wait) {
            Ok(captured) => (Some(captured), true),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.cancel.store(true, Ordering::Release);
                if let Some(thread) = &self.thread {
                    thread.thread().unpark();
                }
                match result.recv_timeout(FIXTURE_GIT_POLL_INTERVAL.saturating_mul(2)) {
                    Ok(captured) => (Some(captured), true),
                    Err(mpsc::RecvTimeoutError::Disconnected) => (None, true),
                    Err(mpsc::RecvTimeoutError::Timeout) => (None, false),
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => (None, true),
        };
        self.result.take();
        let joined = acknowledged
            && self
                .thread
                .take()
                .expect("bounded capture reader thread remains owned")
                .join()
                .is_ok();
        match (capture, joined) {
            (Some(captured), true) => captured,
            (Some(mut captured), false) => {
                captured.error = Some(format!("{} capture reader panicked", self.stream));
                captured
            }
            (None, _) => CapturedBytes::failed(format!(
                "{} capture reader did not return a result before its cancellation deadline",
                self.stream
            )),
        }
    }
}

impl Drop for BoundedCaptureReader {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        let acknowledged = self.result.as_ref().is_some_and(|result| {
            !matches!(
                result.recv_timeout(FIXTURE_GIT_POLL_INTERVAL.saturating_mul(2)),
                Err(mpsc::RecvTimeoutError::Timeout)
            )
        });
        self.result.take();
        if acknowledged {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

enum PipeRead {
    Data(usize),
    Pending,
    Eof,
}

trait CapturePipe: io::Read + Send + 'static {
    fn prepare_nonblocking(&self) -> io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<PipeRead>;
}

macro_rules! impl_capture_pipe {
    ($pipe:ty) => {
        impl CapturePipe for $pipe {
            fn prepare_nonblocking(&self) -> io::Result<()> {
                prepare_capture_pipe(self)
            }

            fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<PipeRead> {
                read_capture_pipe(self, buffer)
            }
        }
    };
}

impl_capture_pipe!(std::process::ChildStdout);
impl_capture_pipe!(std::process::ChildStderr);

#[cfg(unix)]
fn prepare_capture_pipe(pipe: &(impl std::os::fd::AsRawFd + ?Sized)) -> io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("failed to inspect bounded Git fixture capture pipe flags: {error}"),
        ));
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("failed to make bounded Git fixture capture pipe nonblocking: {error}"),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_capture_pipe(pipe: &mut impl io::Read, buffer: &mut [u8]) -> io::Result<PipeRead> {
    match pipe.read(buffer) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(read) => Ok(PipeRead::Data(read)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::Pending),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn prepare_capture_pipe(
    _pipe: &(impl std::os::windows::io::AsRawHandle + ?Sized),
) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_capture_pipe(
    pipe: &mut (impl io::Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> io::Result<PipeRead> {
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
        let error = io::Error::last_os_error();
        return match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => Ok(PipeRead::Eof),
            _ => Err(error),
        };
    }
    if available == 0 {
        return Ok(PipeRead::Pending);
    }
    let available = usize::try_from(available).unwrap_or(usize::MAX);
    let request = buffer.len().min(available);
    match pipe.read(&mut buffer[..request]) {
        Ok(0) => Ok(PipeRead::Eof),
        Ok(read) => Ok(PipeRead::Data(read)),
        Err(error)
            if error.kind() == io::ErrorKind::BrokenPipe
                || matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) =>
        {
            Ok(PipeRead::Eof)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
fn prepare_capture_pipe<T: ?Sized>(_pipe: &T) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_capture_pipe(pipe: &mut impl io::Read, buffer: &mut [u8]) -> io::Result<PipeRead> {
    match pipe.read(buffer)? {
        0 => Ok(PipeRead::Eof),
        read => Ok(PipeRead::Data(read)),
    }
}

#[derive(Default)]
struct CapturedBytes {
    bytes: Vec<u8>,
    truncated: bool,
    observed_bytes: u64,
    peak_buffered_bytes: usize,
    error: Option<String>,
}

impl CapturedBytes {
    fn failed(error: String) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

struct CapturedStreams {
    stdout: CapturedBytes,
    stderr: CapturedBytes,
}

impl CapturedStreams {
    fn any_truncated(&self) -> bool {
        self.stdout.truncated || self.stderr.truncated
    }

    fn first_error(&self) -> Option<&str> {
        self.stdout
            .error
            .as_deref()
            .or(self.stderr.error.as_deref())
    }

    fn render_errors(&self) -> String {
        match (self.stdout.error.as_deref(), self.stderr.error.as_deref()) {
            (None, None) => "ok".to_string(),
            (stdout, stderr) => format!(
                "stdout={}; stderr={}",
                stdout.unwrap_or("ok"),
                stderr.unwrap_or("ok")
            ),
        }
    }

    fn into_output(self, status: ExitStatus) -> Output {
        Output {
            status,
            stdout: self.stdout.bytes,
            stderr: self.stderr.bytes,
        }
    }
}

fn drain_bounded_stream<R: CapturePipe>(
    mut reader: R,
    stream: &'static str,
    max_capture_bytes: u64,
    events: &mpsc::Sender<CaptureEvent>,
    cancel: &AtomicBool,
) -> CapturedBytes {
    let max_buffered = usize::try_from(max_capture_bytes).unwrap_or(usize::MAX);
    let mut captured = CapturedBytes {
        bytes: Vec::with_capacity(max_buffered.min(64 * 1024)),
        ..CapturedBytes::default()
    };
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        if cancel.load(Ordering::Acquire) {
            captured.error = Some(format!("{stream} capture cancelled before EOF"));
            break;
        }
        let read = match reader.read_available(&mut chunk) {
            Ok(PipeRead::Eof) => break,
            Ok(PipeRead::Pending) => {
                std::thread::park_timeout(FIXTURE_GIT_POLL_INTERVAL);
                continue;
            }
            Ok(PipeRead::Data(read)) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let error = error.to_string();
                captured.error = Some(error.clone());
                let _ = events.send(CaptureEvent::ReadFailed { stream, error });
                break;
            }
        };
        retain_bounded_chunk(&mut captured, &chunk[..read], max_buffered, stream, events);
        if cancel.load(Ordering::Acquire) {
            captured.error = Some(format!("{stream} capture cancelled before EOF"));
            break;
        }
    }
    if captured.truncated {
        if max_buffered >= CAPTURE_TRUNCATION_MARKER.len() {
            captured
                .bytes
                .truncate(max_buffered - CAPTURE_TRUNCATION_MARKER.len());
            captured.bytes.extend_from_slice(CAPTURE_TRUNCATION_MARKER);
        } else {
            captured.bytes.truncate(max_buffered);
        }
    }
    captured
}

fn retain_bounded_chunk(
    captured: &mut CapturedBytes,
    chunk: &[u8],
    max_buffered: usize,
    stream: &'static str,
    events: &mpsc::Sender<CaptureEvent>,
) {
    captured.observed_bytes = captured
        .observed_bytes
        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    let remaining = max_buffered.saturating_sub(captured.bytes.len());
    let retained = remaining.min(chunk.len());
    captured.bytes.extend_from_slice(&chunk[..retained]);
    captured.peak_buffered_bytes = captured.peak_buffered_bytes.max(captured.bytes.len());
    if retained < chunk.len() && !captured.truncated {
        captured.truncated = true;
        let _ = events.send(CaptureEvent::LimitExceeded { stream });
    }
}

fn compact_capture(capture: &CapturedBytes) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 400;
    let prefix = &capture.bytes[..capture.bytes.len().min(MAX_DIAGNOSTIC_BYTES)];
    let mut rendered = String::from_utf8_lossy(prefix).trim().to_string();
    if capture.bytes.len() > MAX_DIAGNOSTIC_BYTES || capture.truncated {
        rendered.push_str("...");
    }
    if let Some(error) = &capture.error {
        if !rendered.is_empty() {
            rendered.push(' ');
        }
        rendered.push_str("[capture error: ");
        rendered.push_str(error);
        rendered.push(']');
    }
    if rendered.is_empty() {
        "<empty>".to_string()
    } else {
        rendered
    }
}

fn capture_limit_message(
    label: &str,
    max_capture_bytes_per_stream: u64,
    cleanup: &str,
    captured: &CapturedStreams,
) -> String {
    format!(
        "{label} exceeded the {max_capture_bytes_per_stream}-byte per-stream capture limit \
         (stdout={}, stderr={}; peak-buffered stdout={}, stderr={}); {cleanup}; capture={}; \
         stdout={} stderr={}",
        captured.stdout.observed_bytes,
        captured.stderr.observed_bytes,
        captured.stdout.peak_buffered_bytes,
        captured.stderr.peak_buffered_bytes,
        captured.render_errors(),
        compact_capture(&captured.stdout),
        compact_capture(&captured.stderr),
    )
}

fn display_optional_error(error: Option<&io::Error>) -> String {
    error
        .map(ToString::to_string)
        .unwrap_or_else(|| "none".to_string())
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const STALLED_WORKER: &str = "TEST_FIXTURE_GIT_STALLED_WORKER";
    const RUNAWAY_OUTPUT_WORKER: &str = "TEST_FIXTURE_GIT_RUNAWAY_OUTPUT_WORKER";
    const DESCENDANT_PARENT: &str = "TEST_FIXTURE_GIT_DESCENDANT_PARENT";
    const DESCENDANT_MARKER: &str = "TEST_FIXTURE_GIT_DESCENDANT_MARKER";
    #[cfg(unix)]
    const PARENT_DEATH_OWNER: &str = "TEST_FIXTURE_GIT_PARENT_DEATH_OWNER";
    #[cfg(unix)]
    const PARENT_DEATH_DESCENDANT: &str = "TEST_FIXTURE_GIT_PARENT_DEATH_DESCENDANT";
    #[cfg(unix)]
    const HOSTILE_GIT_MARKER: &str = "TEST_FIXTURE_GIT_HOSTILE_EXECUTABLE_MARKER";

    struct NeverEofCapturePipe;

    impl io::Read for NeverEofCapturePipe {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl CapturePipe for NeverEofCapturePipe {
        fn prepare_nonblocking(&self) -> io::Result<()> {
            Ok(())
        }

        fn read_available(&mut self, _buffer: &mut [u8]) -> io::Result<PipeRead> {
            Ok(PipeRead::Pending)
        }
    }

    #[test]
    fn active_capture_sink_never_buffers_past_the_byte_ceiling() {
        let (events, received) = mpsc::channel();
        let mut captured = CapturedBytes::default();
        retain_bounded_chunk(&mut captured, &[b'a'; 3_000], 4_096, "stdout", &events);
        retain_bounded_chunk(&mut captured, &[b'b'; 3_000], 4_096, "stdout", &events);

        assert_eq!(captured.observed_bytes, 6_000);
        assert_eq!(captured.bytes.len(), 4_096);
        assert_eq!(captured.peak_buffered_bytes, 4_096);
        assert!(captured.truncated);
        assert!(matches!(
            received.try_recv(),
            Ok(CaptureEvent::LimitExceeded { stream: "stdout" })
        ));
    }

    #[test]
    fn capture_deadline_cannot_be_misreported_as_eof() {
        let (events, _received) = mpsc::channel();
        let reader =
            BoundedCaptureReader::spawn(NeverEofCapturePipe, "stdout", 4_096, events).unwrap();
        let captured = reader.finish_until(Instant::now());
        assert_eq!(
            captured.error.as_deref(),
            Some("stdout capture cancelled before EOF")
        );
    }

    fn assert_success(args: &[&str], output: &Output) {
        assert!(
            output.status.success(),
            "git {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn fixture_git_reapplies_isolation_after_command_scope_overrides() {
        let temp = tempfile::tempdir().unwrap();
        let output = fixture_git_in(temp.path())
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "test.hostile")
            .env("GIT_CONFIG_VALUE_0", "present")
            .env("GIT_CONFIG_PARAMETERS", "malformed hostile fixture config")
            .args(["config", "--get", "test.hostile"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn fixture_git_removes_full_git_vfs_loader_and_external_authority() {
        let mut command = Command::new("git");
        command
            .env("GIT_DEFAULT_HASH", "sha256")
            .env("GIT_DEFAULT_REF_FORMAT", "reftable")
            .env("GIT_INDEX_VERSION", "4")
            .env("GIT_AUTHOR_NAME", "Hostile Author")
            .env("GIT_TRACE", "/hostile/trace")
            .env("GIT_REDIRECT_STDOUT", "/hostile/stdout")
            .env("GIT_EXEC_PATH", "/hostile/exec")
            .env("GIT_SSH_COMMAND", "hostile-ssh")
            .env("DYLD_INSERT_LIBRARIES", "/hostile/libkin_vfs.dylib")
            .env("LD_DEBUG", "all")
            .env("LD_DEBUG_OUTPUT", "/hostile/loader-trace")
            .env("LD_PROFILE", "git")
            .env("KIN_VFS_WORKSPACE", "/hostile/workspace")
            .env("KIN_VFS_DISABLE", "0")
            .env("KIN_ORIGINAL_PATH", "/hostile/shims")
            .env("PATH", "/hostile/shims")
            .env("EMAIL", "hostile@example.com")
            .env("SSH_ASKPASS", "/hostile/askpass")
            .env("_KIN_VFS_LAST_DIR", "/hostile/workspace/src");

        isolate_fixture_git(&mut command);

        let configured = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for removed in [
            "GIT_DEFAULT_HASH",
            "GIT_DEFAULT_REF_FORMAT",
            "GIT_INDEX_VERSION",
            "GIT_AUTHOR_NAME",
            "GIT_TRACE",
            "GIT_REDIRECT_STDOUT",
            "GIT_EXEC_PATH",
            "GIT_SSH_COMMAND",
            "DYLD_INSERT_LIBRARIES",
            "LD_DEBUG",
            "LD_DEBUG_OUTPUT",
            "LD_PROFILE",
            "KIN_VFS_WORKSPACE",
            "KIN_ORIGINAL_PATH",
            "EMAIL",
            "SSH_ASKPASS",
            "_KIN_VFS_LAST_DIR",
        ] {
            assert_eq!(
                configured.get(removed),
                Some(&None),
                "{removed} remained in the fixture environment"
            );
        }
        assert_eq!(
            configured.get("KIN_VFS_DISABLE"),
            Some(&Some("1".to_string()))
        );
        assert_eq!(
            configured.get("GIT_CONFIG_NOSYSTEM"),
            Some(&Some("1".to_string()))
        );
        assert_eq!(
            configured.get("GIT_ALLOW_PROTOCOL"),
            Some(&Some("file".to_string()))
        );
        assert_eq!(
            configured.get("PATH"),
            Some(&Some(fixture_host_path().to_string_lossy().into_owned()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn guardian_uses_the_same_final_authority_scrub_and_host_path() {
        let host_path = fixture_host_path();
        let mut guardian = Command::new("/bin/sh");
        guardian
            .env("GIT_DIR", "/hostile/repository")
            .env("KIN_VFS_WORKSPACE", "/hostile/workspace")
            .env("KIN_ORIGINAL_PATH", "/hostile/shims")
            .env("DYLD_INSERT_LIBRARIES", "/hostile/inject.dylib")
            .env("LD_PRELOAD", "/hostile/inject.so")
            .env("PATH", "/hostile/shims");

        isolate_fixture_guardian(&mut guardian, &host_path);

        let configured = guardian
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for removed in [
            "GIT_DIR",
            "KIN_VFS_WORKSPACE",
            "KIN_ORIGINAL_PATH",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert_eq!(configured.get(removed), Some(&None), "{removed}");
        }
        assert_eq!(
            configured.get("PATH"),
            Some(&Some(host_path.to_string_lossy().into_owned()))
        );
        assert_eq!(
            configured.get("KIN_VFS_DISABLE"),
            Some(&Some("1".to_string()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn hostile_command_path_cannot_replace_resolved_host_git() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let shim = temp.path().join("git");
        let marker = temp.path().join("hostile-git-ran");
        std::fs::write(
            &shim,
            b"#!/bin/sh\nprintf hostile > \"$TEST_FIXTURE_GIT_HOSTILE_EXECUTABLE_MARKER\"\nexit 91\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&shim).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&shim, permissions).unwrap();

        let mut command = fixture_git();
        assert!(
            Path::new(command.inner.get_program()).is_absolute(),
            "fixture Git executable was not resolved absolutely: {:?}",
            command.inner.get_program()
        );
        let output = command
            .env("PATH", temp.path())
            .env("KIN_ORIGINAL_PATH", temp.path())
            .env(HOSTILE_GIT_MARKER, &marker)
            .arg("--version")
            .output()
            .unwrap();

        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).starts_with("git version "),
            "{output:?}"
        );
        assert!(!marker.exists(), "hostile PATH shim replaced host Git");
    }

    #[cfg(unix)]
    #[test]
    fn relative_host_path_stays_bound_after_fixture_child_cwd_changes() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let resolution_root = root.path().join("resolution");
        let child_root = root.path().join("child");
        let trusted_bin = resolution_root.join("bin");
        let hostile_bin = child_root.join("bin");
        std::fs::create_dir_all(&trusted_bin).unwrap();
        std::fs::create_dir_all(&hostile_bin).unwrap();
        let trusted = trusted_bin.join("kin-fixture-helper");
        let hostile = hostile_bin.join("kin-fixture-helper");
        std::fs::write(&trusted, "#!/bin/sh\nprintf trusted\n").unwrap();
        std::fs::write(&hostile, "#!/bin/sh\nprintf hostile\n").unwrap();
        for executable in [&trusted, &hostile] {
            let mut permissions = std::fs::metadata(executable).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(executable, permissions).unwrap();
        }

        let host_path = absolute_fixture_host_path("bin", &resolution_root).unwrap();
        assert!(
            std::env::split_paths(&host_path).all(|entry| entry.is_absolute()),
            "fixture host PATH retained a child-cwd-relative entry"
        );
        let output = Command::new("kin-fixture-helper")
            .current_dir(&child_root)
            .env("PATH", host_path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"trusted");
    }

    #[cfg(windows)]
    #[test]
    fn fixture_git_treats_windows_environment_names_case_insensitively() {
        for hostile in [
            "git_default_hash",
            "Git_Config_Count",
            "git_author_name",
            "git_trace",
            "kin_vfs_workspace",
            "Dyld_Library_Path",
            "ld_debug_output",
            "ssh_askpass",
        ] {
            assert!(
                is_fixture_authority(OsStr::new(hostile)),
                "{hostile} bypassed Windows environment-name isolation"
            );
        }
    }

    #[test]
    fn fixture_git_ignores_global_config_attributes_trace_and_format_authority() {
        let temp = tempfile::tempdir().unwrap();
        let hostile_home = temp.path().join("hostile-home");
        let hostile_xdg = temp.path().join("hostile-xdg");
        let repository = temp.path().join("repository");
        let trace = temp.path().join("trace.log");
        std::fs::create_dir_all(hostile_home.join(".config/git")).unwrap();
        std::fs::create_dir_all(hostile_xdg.join("git")).unwrap();
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::write(
            hostile_home.join(".gitconfig"),
            "[user]\n\tname = Hostile Global\n\temail = hostile@example.com\n",
        )
        .unwrap();
        std::fs::write(hostile_home.join(".config/git/attributes"), "*.txt text\n").unwrap();
        std::fs::write(hostile_xdg.join("git/attributes"), "*.txt text\n").unwrap();

        let init_args = ["init", "--initial-branch=main"];
        let init = fixture_git_in(&repository)
            .env("HOME", &hostile_home)
            .env("USERPROFILE", &hostile_home)
            .env("XDG_CONFIG_HOME", &hostile_xdg)
            .env("GIT_DEFAULT_HASH", "sha256")
            .env("GIT_DEFAULT_REF_FORMAT", "reftable")
            .env("GIT_TRACE", &trace)
            .args(init_args)
            .output()
            .unwrap();
        assert_success(&init_args, &init);
        assert!(!trace.exists(), "hostile Git trace escaped fixture sandbox");

        for args in [
            ["config", "user.name", "Fixture Local"],
            ["config", "user.email", "fixture@example.invalid"],
        ] {
            let output = fixture_git_in(&repository).args(args).output().unwrap();
            assert_success(&args, &output);
        }
        std::fs::write(repository.join("sample.txt"), b"fixture\r\n").unwrap();
        let add_args = ["add", "sample.txt"];
        let add = fixture_git_in(&repository).args(add_args).output().unwrap();
        assert_success(&add_args, &add);

        let commit_args = ["commit", "-m", "fixture"];
        let commit = fixture_git_in(&repository)
            .env("GIT_AUTHOR_NAME", "Hostile Command Author")
            .env("GIT_AUTHOR_EMAIL", "hostile-command@example.com")
            .env("GIT_AUTHOR_DATE", "2030-01-01T00:00:00 +0000")
            .author_name("Explicit Fixture Author")
            .author_email("fixture-author@example.invalid")
            .author_date("2001-01-01T00:00:00 +0000")
            .committer_name("Explicit Fixture Committer")
            .committer_email("fixture-committer@example.invalid")
            .committer_date("2001-01-02T00:00:00 +0000")
            .args(commit_args)
            .output()
            .unwrap();
        assert_success(&commit_args, &commit);

        let format = fixture_git_in(&repository)
            .args(["rev-parse", "--show-object-format"])
            .output()
            .unwrap();
        assert_success(&["rev-parse", "--show-object-format"], &format);
        assert_eq!(String::from_utf8_lossy(&format.stdout).trim(), "sha1");
        assert!(repository.join(".git/refs").is_dir());

        let identity = fixture_git_in(&repository)
            .args(["show", "-s", "--format=%an|%ae|%aI|%cn|%ce|%cI", "HEAD"])
            .output()
            .unwrap();
        assert_success(&["show"], &identity);
        let identity = String::from_utf8_lossy(&identity.stdout);
        assert!(identity.contains("Explicit Fixture Author"), "{identity}");
        assert!(
            identity.contains("fixture-author@example.invalid"),
            "{identity}"
        );
        assert!(identity.contains("2001-01-01"), "{identity}");
        assert!(
            identity.contains("Explicit Fixture Committer"),
            "{identity}"
        );
        assert!(
            identity.contains("fixture-committer@example.invalid"),
            "{identity}"
        );
        assert!(identity.contains("2001-01-02"), "{identity}");

        let attribute = fixture_git_in(&repository)
            .args(["check-attr", "text", "--", "sample.txt"])
            .output()
            .unwrap();
        assert_success(&["check-attr"], &attribute);
        assert_eq!(
            String::from_utf8_lossy(&attribute.stdout).trim(),
            "sample.txt: text: unspecified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_cleanup_disarms_numeric_process_group_before_drop() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, mut tree) =
            FixtureProcessTree::spawn(&mut command, "one-shot process-group fixture").unwrap();
        assert!(matches!(
            tree.process_group,
            Some(UnixFixtureProcessGroup::Armed(_))
        ));
        assert!(child.wait().unwrap().success());

        tree.terminate().unwrap();
        assert!(matches!(
            tree.process_group,
            Some(UnixFixtureProcessGroup::TerminationRequested(_))
        ));
        tree.terminate()
            .expect("a repeated terminate request must not signal the PGID again");
        cleanup_reaped_tree(&mut tree).unwrap();

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
    fn failed_quiescence_drop_allows_guardian_eof_group_kill_to_finish() {
        use std::os::unix::process::CommandExt as _;

        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("guardian-eof.marker");
        let mut guardian = Command::new("/bin/sh");
        guardian
            .args([
                OsStr::new("-c"),
                OsStr::new("IFS= read -r _; sleep 0.2; printf watchdog > \"$1\"; kill -KILL 0"),
                OsStr::new("fixture-guardian"),
                marker.as_os_str(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut guardian = guardian.spawn().unwrap();
        let process_group = libc::pid_t::try_from(guardian.id()).unwrap();
        let guardian_stdin = guardian.stdin.take().unwrap();
        let tree = FixtureProcessTree {
            process_group: Some(UnixFixtureProcessGroup::TerminationRequested(process_group)),
            guardian: Some(guardian),
            guardian_stdin: Some(guardian_stdin),
        };

        // This is the state left after termination was requested but the
        // empty-group proof failed. Drop must close the ownership pipe without
        // killing/reaping the guardian before it consumes EOF.
        drop(tree);

        let deadline = Instant::now() + Duration::from_secs(3);
        while !marker.is_file() && Instant::now() < deadline {
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
        let marker_written = marker.is_file();
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(process_group, &mut status, 0) };
        assert!(
            marker_written,
            "failed-quiescence Drop killed the guardian before its EOF watchdog ran"
        );
        assert_eq!(
            reaped, process_group,
            "test could not reap the completed EOF guardian"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_death_guardian_worker() {
        if let Some(marker) = std::env::var_os(PARENT_DEATH_DESCENDANT) {
            std::fs::write(
                PathBuf::from(&marker).with_extension("pid"),
                std::process::id().to_string(),
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::fs::write(
                PathBuf::from(marker).with_extension("finished"),
                b"finished",
            )
            .unwrap();
            return;
        }
        let Some(marker) = std::env::var_os(PARENT_DEATH_OWNER) else {
            return;
        };
        let marker = PathBuf::from(marker);
        let mut descendant = Command::new(std::env::current_exe().unwrap());
        descendant
            .args([
                "--exact",
                "test_support::tests::parent_death_guardian_worker",
                "--nocapture",
            ])
            .env_remove(PARENT_DEATH_OWNER)
            .env(PARENT_DEATH_DESCENDANT, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut descendant, tree) =
            FixtureProcessTree::spawn(&mut descendant, "parent-death descendant").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.with_extension("pid").is_file() && Instant::now() < deadline {
            assert!(descendant.try_wait().unwrap().is_none());
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
        assert!(marker.with_extension("pid").is_file());
        std::fs::write(marker.with_extension("owner-ready"), b"ready").unwrap();
        let _descendant = descendant;
        let _tree = tree;
        std::thread::sleep(Duration::from_secs(30));
    }

    #[cfg(unix)]
    #[test]
    fn owner_sigkill_triggers_guardian_eof_and_kills_descendant() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("parent-death");
        let mut owner = Command::new(std::env::current_exe().unwrap());
        owner
            .args([
                "--exact",
                "test_support::tests::parent_death_guardian_worker",
                "--nocapture",
            ])
            .env(PARENT_DEATH_OWNER, &marker)
            .env_remove(PARENT_DEATH_DESCENDANT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner = owner.spawn().unwrap();
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !marker.with_extension("owner-ready").is_file() && Instant::now() < ready_deadline {
            assert!(
                owner.try_wait().unwrap().is_none(),
                "parent-death owner exited before its descendant became ready"
            );
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
        assert!(marker.with_extension("owner-ready").is_file());
        let descendant = std::fs::read_to_string(marker.with_extension("pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();

        let owner_pid = libc::pid_t::try_from(owner.id()).unwrap();
        assert_eq!(unsafe { libc::kill(owner_pid, libc::SIGKILL) }, 0);
        owner.wait().unwrap();

        let death_deadline = Instant::now() + FIXTURE_GIT_REAP_GRACE;
        while process_is_live(descendant) && Instant::now() < death_deadline {
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
        assert!(
            !process_is_live(descendant),
            "guardian EOF did not kill descendant {descendant} after owner SIGKILL"
        );
        assert!(!marker.with_extension("finished").exists());
    }

    #[test]
    fn stalled_worker() {
        let Some(marker) = std::env::var_os(STALLED_WORKER) else {
            return;
        };
        std::fs::write(PathBuf::from(&marker).with_extension("started"), b"started").unwrap();
        println!("stalled fixture stdout");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(30));
        std::fs::write(
            PathBuf::from(marker).with_extension("finished"),
            b"finished",
        )
        .unwrap();
    }

    #[test]
    fn bounded_launch_times_out_and_reaps_stalled_worker() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("stalled");
        let mut command =
            FixtureGitCommand::for_program(std::env::current_exe().unwrap(), "stalled fixture");
        command
            .args([
                "--exact",
                "test_support::tests::stalled_worker",
                "--nocapture",
            ])
            .env(STALLED_WORKER, &marker);
        let timeout = Duration::from_secs(2);
        let started = Instant::now();
        let error = command
            .output_with_timeout(timeout)
            .expect_err("stalled fixture must hit its hard deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(error.to_string().contains("direct child reaped: true"));
        assert!(started.elapsed() < timeout + FIXTURE_GIT_REAP_GRACE + Duration::from_secs(2));
        assert!(marker.with_extension("started").is_file());
        assert!(!marker.with_extension("finished").exists());
    }

    #[test]
    fn runaway_output_worker() {
        if std::env::var_os(RUNAWAY_OUTPUT_WORKER).is_none() {
            return;
        }
        let chunk = vec![b'x'; 64 * 1024];
        loop {
            std::io::stdout().write_all(&chunk).unwrap();
            std::io::stdout().flush().unwrap();
        }
    }

    #[test]
    fn bounded_launch_rejects_runaway_output_and_reaps_the_tree() {
        let mut command =
            FixtureGitCommand::for_program(std::env::current_exe().unwrap(), "runaway fixture");
        command
            .args([
                "--exact",
                "test_support::tests::runaway_output_worker",
                "--nocapture",
            ])
            .env(RUNAWAY_OUTPUT_WORKER, "1");
        let error = command
            .output_with_timeout_and_capture_limit(Duration::from_secs(5), 4 * 1024)
            .expect_err("runaway output must hit the per-stream capture ceiling");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        let message = error.to_string();
        assert!(message.contains("exceeded the 4096-byte"), "{message}");
        assert!(message.contains("direct child reaped: true"), "{message}");
    }

    #[test]
    fn descendant_worker() {
        if let Some(marker) = std::env::var_os(DESCENDANT_MARKER) {
            std::fs::write(
                PathBuf::from(&marker).with_extension("pid"),
                std::process::id().to_string(),
            )
            .unwrap();
            println!("descendant inherited capture");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::fs::write(
                PathBuf::from(marker).with_extension("finished"),
                b"finished",
            )
            .unwrap();
            return;
        }
        let Some(marker) = std::env::var_os(DESCENDANT_PARENT) else {
            return;
        };
        let marker = PathBuf::from(marker);
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "test_support::tests::descendant_worker",
                "--nocapture",
            ])
            .env(DESCENDANT_MARKER, &marker)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.with_extension("pid").is_file() && Instant::now() < deadline {
            assert!(descendant.try_wait().unwrap().is_none());
            std::thread::sleep(FIXTURE_GIT_POLL_INTERVAL);
        }
        assert!(marker.with_extension("pid").is_file());
        drop(descendant);
    }

    #[test]
    fn bounded_launch_kills_inherited_descendant_before_return() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("descendant");
        let mut command =
            FixtureGitCommand::for_program(std::env::current_exe().unwrap(), "descendant fixture");
        command
            .args([
                "--exact",
                "test_support::tests::descendant_worker",
                "--nocapture",
            ])
            .env(DESCENDANT_PARENT, &marker);
        let output = command
            .output_with_timeout(Duration::from_secs(10))
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("descendant inherited capture"));
        let pid = std::fs::read_to_string(marker.with_extension("pid"))
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(
            !process_is_live(pid),
            "descendant process {pid} survived fixture return"
        );
        assert!(!marker.with_extension("finished").exists());
    }

    #[cfg(unix)]
    fn process_is_live(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
