// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one definition of how a repo daemon is started and how its port is
//! learned.
//!
//! Two callers start a daemon and wait for it: the CLI autostart path and the
//! MCP revival path. They cannot share code through either of their own crates,
//! because `kin-cli` depends on `kin-mcp` and `kin-mcp` cannot depend on
//! `kin-daemon`, which already depends on `kin-mcp`. So each grew its own copy
//! of the contract, and the MCP copy twice regressed to a weaker version of a
//! rule the CLI copy already enforced.
//!
//! A third surface starts a daemon without waiting for it: the macOS LaunchAgent
//! plist, which hands its argument vector to launchd rather than to a child this
//! process supervises. It is not a caller of the startup helpers here, but it
//! does have to agree about port selection, so it passes
//! [`DAEMON_PORT_ARGUMENT`] like everything else. `kin-daemon` also once
//! re-exported a fourth entry point of its own; it is gone, so counting the
//! spawn contracts in the tree now yields the one below.
//!
//! This crate is the shared floor beneath them. It deliberately holds the
//! decisions that diverged rather than everything a spawn touches:
//!
//! - the daemon owns port selection ([`DAEMON_PORT_ARGUMENT`]), and the port is
//!   read back from the port file rather than reserved by the parent
//! - a spawn that never learns a port fails closed; there is no fallback port
//! - a startup child is killed only against positive evidence that it is dead
//! - a stale port record is cleared only when no PID owner remains
//!
//! HTTP readiness probing stays with the callers: they already own health
//! response types and repo-identity validation, and keeping `reqwest` out of
//! here keeps this crate cheap enough that neither caller has a reason to
//! reimplement it.

use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The port argument every daemon spawn passes.
///
/// Zero means "bind an ephemeral port and report it", which is what makes the
/// port file the handshake. A parent that instead probes for a free port and
/// passes that number opens a reserve-release-rebind race: between the probe
/// closing its listener and the daemon binding, any other process on the
/// machine can take the port, and the daemon then dies on a bind conflict the
/// parent will misread as a slow start.
pub const DAEMON_PORT_ARGUMENT: &str = "0";

/// Idle timeout injected into daemons started to serve an MCP session.
///
/// Interactive agent sessions go quiet for long stretches between tool calls,
/// so the CLI default (60s) expires a daemon mid-session and the MCP shim does
/// not reconnect. Both spawn paths and the daemon's own default read this.
pub const MCP_IDLE_TIMEOUT_SECS: &str = "1800";

/// Operator opt-out for the background embedding pass the daemon starts on its
/// own after its first reconciliation cycle.
///
/// The daemon reads this from its own process environment at start, so the
/// value that decides the pass is the one the *spawning* command held. Every
/// spawn built here pins the caller's value onto the child explicitly rather
/// than leaving it to inheritance, so the delivery is a stated property of the
/// spawn (and assertable without starting a process) instead of an accident of
/// what the authority scrub happens not to remove.
pub const DAEMON_AUTO_EMBED_ENV: &str = "KIN_DAEMON_AUTO_EMBED";

/// File the daemon writes its bound port into once it is listening.
pub const PORT_FILE_NAME: &str = "daemon.port";

/// File the daemon writes its PID into as part of endpoint publication.
pub const PID_FILE_NAME: &str = "daemon.pid";

/// File whoever ends a daemon from outside writes its reason into.
pub const DEATH_FILE_NAME: &str = "daemon.death";

/// Why a daemon stopped, recorded by the process that stopped it.
///
/// A daemon killed from outside cannot log its own cause: the reaper's SIGTERM
/// grace is shorter than the daemon's own shutdown, so the SIGKILL that follows
/// lands while the tokio arm that would print a shutdown line is still unpolled.
/// Everything the killer knew therefore went to the killer's log, and the log an
/// operator actually opens — `.kin/daemon.log` — simply stopped mid-line. This
/// carries that reason back to the repository the daemon served, so both the CLI
/// reporting a failed request and `kin doctor` can say what happened instead of
/// quoting a transport error.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonDeathNote {
    /// The daemon that was ended.
    pub pid: u32,
    /// What ended it, e.g. `kin-supervisor-reaper`.
    pub killed_by: String,
    /// The deciding condition, in the killer's own words.
    pub reason: String,
    /// What the daemon was doing, when the killer could tell.
    pub in_flight: Option<String>,
    /// RFC 3339 timestamp of the decision.
    pub at: String,
}

impl DaemonDeathNote {
    /// One line an operator can read without parsing anything.
    pub fn summary(&self) -> String {
        match &self.in_flight {
            Some(work) => format!(
                "{} ended pid {} at {}: {} (in flight: {})",
                self.killed_by, self.pid, self.at, self.reason, work
            ),
            None => format!(
                "{} ended pid {} at {}: {}",
                self.killed_by, self.pid, self.at, self.reason
            ),
        }
    }
}

/// Record why a daemon was ended, in the repository it served.
///
/// Best effort by construction: the caller is about to signal a process, and a
/// note it could not write must never stop that from happening.
pub fn write_daemon_death_note(kin_root: &Path, note: &DaemonDeathNote) {
    let Ok(body) = serde_json::to_string(note) else {
        return;
    };
    let tmp = kin_root.join(format!("{DEATH_FILE_NAME}.tmp"));
    if fs::write(&tmp, body).is_ok() && fs::rename(&tmp, kin_root.join(DEATH_FILE_NAME)).is_err() {
        let _ = fs::remove_file(&tmp);
    }
}

/// Read the death note left for `kin_root`, if one is there.
pub fn read_daemon_death_note(kin_root: &Path) -> Option<DaemonDeathNote> {
    let raw = fs::read_to_string(kin_root.join(DEATH_FILE_NAME)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Clear a death note. A daemon that comes up successfully calls this, so a note
/// never outlives the outage it describes and gets blamed for the next one.
pub fn clear_daemon_death_note(kin_root: &Path) {
    let _ = fs::remove_file(kin_root.join(DEATH_FILE_NAME));
}

/// Append a line to the repo daemon's own log.
///
/// The one place a killer can put its reason where the operator will look. The
/// daemon holds this file open in append mode and is about to stop writing to
/// it, so an extra append races nothing.
pub fn append_to_daemon_log(kin_root: &Path, line: &str) {
    use std::io::Write as _;
    let Ok(mut log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(kin_root.join("daemon.log"))
    else {
        return;
    };
    let _ = writeln!(log, "{line}");
}

/// Shared install-mutation lease for spawn paths that cannot depend on
/// `kin-cli` (most importantly MCP daemon revival). Full uninstall takes the
/// same `<KIN_HOME>/update.lock` exclusively before stopping processes and
/// retiring the executable root. Holding this lease until readiness makes a
/// managed spawn land wholly before that sweep or fail after retirement.
pub struct ManagedInstallSpawnFence {
    _file: File,
    #[cfg(windows)]
    _root: File,
}

impl ManagedInstallSpawnFence {
    /// Take spawn admission only when `binary` is the real `bin/kin-daemon`
    /// beneath `configured_root`. Development and explicitly external daemon
    /// binaries return `Ok(None)` and are not attributed to the managed install.
    pub fn acquire(binary: &Path, configured_root: &Path) -> std::io::Result<Option<Self>> {
        let Some(bin_dir) = binary.parent() else {
            return Ok(None);
        };
        if bin_dir.file_name().and_then(|name| name.to_str()) != Some("bin") {
            return Ok(None);
        }
        let Some(candidate_root) = bin_dir.parent() else {
            return Ok(None);
        };
        let candidate_root = candidate_root.canonicalize()?;
        let candidate_name = candidate_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if candidate_name.starts_with(".kin-uninstall-retired-")
            || candidate_name.starts_with(".kin-uninstall-delete-")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to spawn a managed daemon from retired uninstall state: {}",
                    binary.display()
                ),
            ));
        }
        let configured_root = match configured_root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if candidate_root != configured_root {
            return Ok(None);
        }

        let root_before = fs::symlink_metadata(&configured_root)?;
        if root_before.file_type().is_symlink() || !root_before.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed install root is not a real non-symlink directory",
            ));
        }
        let binary_before = fs::symlink_metadata(binary)?;
        if binary_before.file_type().is_symlink() || !binary_before.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed daemon binary is not a real non-symlink file",
            ));
        }
        let resolved_binary = binary.canonicalize()?;
        let expected_binary = configured_root
            .join("bin")
            .join(binary.file_name().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "managed daemon binary has no file name",
                )
            })?);
        if resolved_binary != expected_binary.canonicalize()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed daemon binary changed before spawn admission",
            ));
        }

        let lock_path = configured_root.join("update.lock");
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed install update lock is not a real non-symlink file",
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Opened before the lock, because the root's post-admission identity has
        // to be judged against a handle bound to the directory that was admitted.
        // Windows identity lives in GetFileInformationByHandle, so a path-derived
        // Metadata cannot carry it, and a handle opened after the lock would be
        // bound to whatever the path resolves to by then.
        #[cfg(windows)]
        let root_guard = open_windows_root_guard(&configured_root)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options.open(&lock_path)?;
        FileExt::lock_shared(&file)?;

        if configured_root.canonicalize()? != candidate_root
            || binary.canonicalize()? != resolved_binary
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed install changed after spawn admission",
            ));
        }
        // Unix compares dev+ino, which is the object's identity and does not move
        // when the directory's contents do. Windows has no path-derived identity,
        // so it asks the same question the way the lock binding below does: the
        // handle held since admission against a fresh open of the same path. The
        // metadata heuristic cannot stand in here, because it answers "does this
        // look unchanged" rather than "is this the same object", and creating the
        // lock inside the root is a legitimate change to how the root looks.
        #[cfg(unix)]
        {
            let root_after = fs::symlink_metadata(&configured_root)?;
            if !same_file_object(&root_before, &root_after) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed install root identity changed after spawn admission",
                ));
            }
        }
        #[cfg(windows)]
        {
            let current_root = open_windows_root_guard(&configured_root)?;
            if windows_file_identity(&root_guard)?.0 != windows_file_identity(&current_root)?.0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed install root identity changed after spawn admission",
                ));
            }
        }
        let lock_path_metadata = fs::symlink_metadata(&lock_path)?;
        if lock_path_metadata.file_type().is_symlink()
            || !same_file_object(&file.metadata()?, &lock_path_metadata)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed install update lock binding changed after spawn admission",
            ));
        }
        #[cfg(windows)]
        {
            let current_lock = open_windows_regular_nofollow(&lock_path)?;
            if windows_file_identity(&file)?.0 != windows_file_identity(&current_lock)?.0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed install update lock object changed after spawn admission",
                ));
            }
        }
        Ok(Some(Self {
            _file: file,
            #[cfg(windows)]
            _root: root_guard,
        }))
    }
}

#[cfg(unix)]
fn same_file_object(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_object(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> std::io::Result<((u32, u64), u32)> {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        (
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ),
        info.dwFileAttributes,
    ))
}

#[cfg(windows)]
fn open_windows_root_guard(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let (_, attributes) = windows_file_identity(&file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed install root is not a real non-reparse directory",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_windows_regular_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let (_, attributes) = windows_file_identity(&file)?;
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed install update lock is not a real non-reparse file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
const TEST_RUNTIME_OWNER_ENV: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";

#[cfg(unix)]
const TEST_RUNTIME_PROCESS_GROUP_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP";

/// Private executable mode used by the process-group guardian.
///
/// Product binaries call [`run_process_group_guardian_if_requested`] before
/// parsing their normal arguments. Test binaries expose one exact test that
/// calls the same dispatcher. A launcher adds this variable only after its
/// caller has scrubbed ambient authority, so a scrub cannot silently remove
/// the dispatch capability.
#[doc(hidden)]
pub const PROCESS_GROUP_GUARDIAN_MODE_ENV: &str = "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_MODE";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_READY_ENV: &str = "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_READY";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_WATCHER_MODE: &str = "watcher-v1";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_SENTINEL_MODE: &str = "sentinel-v1";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_CLEANUP_TIMEOUT_MS_ENV: &str =
    "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_CLEANUP_TIMEOUT_MS";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_LAUNCHER_PID_ENV: &str =
    "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_LAUNCHER_PID";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_TARGET_PGID_ENV: &str =
    "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_TARGET_PGID";

/// Test-only fault injection that makes the watcher exit before publishing
/// readiness for the already launcher-owned sentinel.
#[cfg(unix)]
#[doc(hidden)]
pub const PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY_ENV: &str =
    "KIN_INTERNAL_PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY";

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_DEFAULT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN: Duration = Duration::from_secs(1);

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_REAPER_TERMINAL_MARGIN: Duration = Duration::from_secs(1);

#[cfg(unix)]
const PROCESS_GROUP_GUARDIAN_KILL_PASSES: usize = 3;

#[cfg(unix)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessGroupCleanupTrigger {
    ParentBarrierComplete = 1,
    WatcherBarrierRequired = 2,
}

#[cfg(unix)]
impl ProcessGroupCleanupTrigger {
    fn parse(byte: u8) -> std::io::Result<Self> {
        match byte {
            value if value == Self::ParentBarrierComplete as u8 => Ok(Self::ParentBarrierComplete),
            value if value == Self::WatcherBarrierRequired as u8 => {
                Ok(Self::WatcherBarrierRequired)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid process-group cleanup trigger byte: {byte}"),
            )),
        }
    }
}

/// How long to wait between polls of the port file.
const PORT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Repository, session, projection, and runtime authority that must not cross
/// the host boundary into a daemon process.
///
/// Daemon configuration that is intentionally inherited (for example registry
/// location, bearer token, and feature controls) is deliberately absent. The
/// test-runtime owner capability is also absent: it is what keeps a daemon
/// inside the harness's verified process group instead of detaching.
const DAEMON_AMBIENT_AUTHORITY_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "KIN_VFS_WORKSPACE",
    "KIN_VFS_WORKSPACE_ALIASES",
    "KIN_VFS_SOCK",
    "KIN_VFS_PIPE",
    "KIN_VFS_CANARY",
    "KIN_VFS_INTERPOSE_ACTIVE",
    "KIN_VFS_LAST_DIR",
    "_KIN_VFS_LAST_DIR",
    "KIN_NO_VFS",
    "KIN_SESSION",
    "KIN_SESSION_ID",
    "KIN_SESSION_DIR",
    "KIN_DAEMON_URL",
    "KIN_DAEMON_WATCH_PID",
    "KIN_SUPERVISOR_STARTUP_GENERATION",
    "KIN_REPO_ID",
    "KIN_REPO_IDS",
    "KIN_PRIMARY_REPO_ID",
    "KIN_MCP_REPO",
    "KIN_SOURCE_ROOT",
    "KIN_ORIGINAL_PATH",
    "KIN_DISCOVERY_MODE",
    "KIN_CONTENT_MODE",
    "KIN_VFS_DISABLE",
];

/// Strip ambient repository/session/projection and loader authority from a
/// daemon command, then bind it to the caller's host toolchain.
///
/// This is public for the few daemon processes that are not assembled through
/// [`DaemonSpawnPlan`] (notably the supervisor and compatibility probes). New
/// repo-daemon launchers should use the plan so this final scrub cannot be
/// forgotten.
pub fn scrub_daemon_process_authority(command: &mut Command) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .collect::<Vec<_>>();
    for key in daemon_ambient_authority_keys(explicit_authority) {
        command.env_remove(key);
    }

    command
        .env("PATH", daemon_host_path())
        .env("KIN_VFS_DISABLE", "1");
}

fn daemon_ambient_authority_keys(
    explicit: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .map(|(key, _)| key)
        .chain(explicit)
        .filter(|key| is_daemon_ambient_authority(key))
        .collect()
}

fn daemon_host_path() -> std::ffi::OsString {
    std::env::var_os("KIN_ORIGINAL_PATH")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default()
}

fn is_daemon_ambient_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    DAEMON_AMBIENT_AUTHORITY_ENV
        .iter()
        .any(|expected| env_name_eq(&label, expected))
        || env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
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

// ── Stable process-group guardian ──────────────────────────────────────

/// Environment-only configuration for guardian-owned internal processes.
///
/// This deliberately exposes no executable, argument, stdio, working-directory,
/// process-group, or `pre_exec` surface. The launcher applies the completed
/// environment independently to the sentinel and watcher before adding its
/// private dispatch values, so caller configuration can never enter either
/// internal child's fork-to-exec path.
#[cfg(unix)]
#[derive(Debug, Default)]
pub struct ProcessGroupGuardianEnvironment {
    clear: bool,
    values: std::collections::BTreeMap<std::ffi::OsString, Option<std::ffi::OsString>>,
}

#[cfg(unix)]
impl ProcessGroupGuardianEnvironment {
    /// Set one environment value.
    pub fn env(
        &mut self,
        key: impl Into<std::ffi::OsString>,
        value: impl Into<std::ffi::OsString>,
    ) -> &mut Self {
        self.values.insert(key.into(), Some(value.into()));
        self
    }

    /// Set a sequence of environment values.
    pub fn envs<K, V, I>(&mut self, values: I) -> &mut Self
    where
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
        I: IntoIterator<Item = (K, V)>,
    {
        for (key, value) in values {
            self.env(key, value);
        }
        self
    }

    /// Remove one inherited or explicitly configured environment value.
    pub fn env_remove(&mut self, key: impl Into<std::ffi::OsString>) -> &mut Self {
        let key = key.into();
        if self.clear {
            self.values.remove(&key);
        } else {
            self.values.insert(key, None);
        }
        self
    }

    /// Prevent the internal processes from inheriting the launcher environment.
    pub fn env_clear(&mut self) -> &mut Self {
        self.clear = true;
        self.values.clear();
        self
    }

    /// Inspect the explicit environment overlay.
    ///
    /// As with [`Command::get_envs`], removed values are represented by `None`;
    /// after [`Self::env_clear`] only subsequently added values are present.
    pub fn get_envs(
        &self,
    ) -> impl ExactSizeIterator<Item = (&std::ffi::OsStr, Option<&std::ffi::OsStr>)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_os_str(), value.as_deref()))
    }

    fn apply_to(&self, command: &mut Command) {
        if self.clear {
            command.env_clear();
        }
        for (key, value) in &self.values {
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
}

/// Guardian-environment equivalent of [`scrub_daemon_process_authority`].
///
/// Both boundaries share the same authority classification and host PATH
/// selection. This variant cannot configure anything except environment state,
/// so it is safe to pass directly to [`ProcessGroupGuardianLauncher::spawn_with`].
#[cfg(unix)]
pub fn scrub_daemon_guardian_environment(environment: &mut ProcessGroupGuardianEnvironment) {
    let explicit_authority = environment
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .collect::<Vec<_>>();
    for key in daemon_ambient_authority_keys(explicit_authority) {
        environment.env_remove(key);
    }
    environment
        .env("PATH", daemon_host_path())
        .env("KIN_VFS_DISABLE", "1");
}

/// Describe the executable entrypoint used by a Unix process-group guardian.
///
/// Production binaries use [`Self::product`]. A Rust test binary uses
/// [`Self::exact_test`] to route the re-executed process to one exact worker
/// without running the rest of the test suite.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ProcessGroupGuardianLauncher {
    executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    cleanup_timeout: Duration,
}

#[cfg(unix)]
impl ProcessGroupGuardianLauncher {
    /// Launch through a product executable whose `main` calls
    /// [`run_process_group_guardian_if_requested`] before normal argument
    /// parsing or runtime construction.
    pub fn product(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            arguments: Vec::new(),
            environment: Vec::new(),
            cleanup_timeout: PROCESS_GROUP_GUARDIAN_DEFAULT_CLEANUP_TIMEOUT,
        }
    }

    /// Launch through one exact Rust test worker.
    ///
    /// The named test should do nothing except assert that
    /// [`run_process_group_guardian_if_requested`] returned `Ok(true)`.
    pub fn exact_test(
        executable: impl Into<PathBuf>,
        exact_test_name: impl Into<std::ffi::OsString>,
    ) -> Self {
        Self {
            executable: executable.into(),
            arguments: vec![
                "--exact".into(),
                exact_test_name.into(),
                "--nocapture".into(),
            ],
            environment: Vec::new(),
            cleanup_timeout: PROCESS_GROUP_GUARDIAN_DEFAULT_CLEANUP_TIMEOUT,
        }
    }

    /// Add an environment value after the caller's authority scrub.
    ///
    /// This is primarily for deterministic fault injection in containment
    /// tests. Product configuration should stay on the target command rather
    /// than the guardian.
    #[must_use]
    pub fn with_env(
        mut self,
        key: impl Into<std::ffi::OsString>,
        value: impl Into<std::ffi::OsString>,
    ) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    /// Bound process-group cleanup and watcher handoff.
    ///
    /// Production callers normally keep the default. A shorter value is useful
    /// for adversarial tests of stopped or killed cleanup authorities.
    #[must_use]
    pub fn with_cleanup_timeout(mut self, cleanup_timeout: Duration) -> Self {
        self.cleanup_timeout = cleanup_timeout.max(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        self
    }

    /// Spawn a launcher-owned sentinel and its separate watcher.
    ///
    /// `configure_environment` receives an environment-only builder. It runs
    /// once before either internal command is built; the resulting overlay is
    /// copied to both commands before private dispatch capability is installed.
    /// This ordering is load-bearing: adding the internal mode before an
    /// authority scrub can leave a normal product process waiting for input
    /// instead of starting a watcher.
    ///
    /// The readiness path must be unique to this launch and its parent
    /// directory must already exist.
    pub fn spawn_with(
        &self,
        readiness_path: &Path,
        deadline: std::time::Instant,
        configure_environment: impl FnOnce(&mut ProcessGroupGuardianEnvironment),
    ) -> std::io::Result<ProcessGroupGuardian> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;

        let _ = std::fs::remove_file(readiness_path);
        let watcher_reaper = process_group_watcher_reaper()?;
        let launcher_pid = unsafe { libc::getpid() };
        if launcher_pid <= 0 {
            return Err(std::io::Error::other(
                "process-group guardian launcher has no valid PID",
            ));
        }
        let mut environment = ProcessGroupGuardianEnvironment::default();
        configure_environment(&mut environment);

        let mut sentinel_command = Command::new(&self.executable);
        sentinel_command.args(&self.arguments);
        environment.apply_to(&mut sentinel_command);
        for (key, value) in &self.environment {
            sentinel_command.env(key, value);
        }
        sentinel_command
            .env(
                PROCESS_GROUP_GUARDIAN_MODE_ENV,
                PROCESS_GROUP_GUARDIAN_SENTINEL_MODE,
            )
            .env(PROCESS_GROUP_GUARDIAN_READY_ENV, readiness_path)
            .env(
                PROCESS_GROUP_GUARDIAN_LAUNCHER_PID_ENV,
                launcher_pid.to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut sentinel = sentinel_command
            .spawn()
            .map_err(|error| contextual_guardian_io(error, "spawn process-group sentinel"))?;
        let process_group = match child_id_to_pid(&sentinel, "process-group sentinel") {
            Ok(process_group) => process_group,
            Err(error) => {
                reap_unarmed_process_group_sentinel(&watcher_reaper, sentinel);
                return Err(error);
            }
        };
        if unsafe { libc::getpgid(process_group) } != process_group {
            let observed_group = unsafe { libc::getpgid(process_group) };
            reap_unarmed_process_group_sentinel(&watcher_reaper, sentinel);
            return Err(std::io::Error::other(format!(
                "process-group sentinel did not lead its group: pid={process_group}, pgid={observed_group}"
            )));
        }
        let mut sentinel_arm = match sentinel.stdin.take() {
            Some(arm) => {
                if let Err(error) = set_nonblocking(arm.as_raw_fd()) {
                    reap_unarmed_process_group_sentinel(&watcher_reaper, sentinel);
                    return Err(contextual_guardian_io(
                        error,
                        "make process-group sentinel arm nonblocking",
                    ));
                }
                Some(arm)
            }
            None => {
                reap_unarmed_process_group_sentinel(&watcher_reaper, sentinel);
                return Err(std::io::Error::other(
                    "process-group sentinel did not expose its arm pipe",
                ));
            }
        };

        let mut watcher_command = Command::new(&self.executable);
        watcher_command.args(&self.arguments);
        environment.apply_to(&mut watcher_command);
        for (key, value) in &self.environment {
            watcher_command.env(key, value);
        }
        watcher_command
            .env(
                PROCESS_GROUP_GUARDIAN_MODE_ENV,
                PROCESS_GROUP_GUARDIAN_WATCHER_MODE,
            )
            .env(PROCESS_GROUP_GUARDIAN_READY_ENV, readiness_path)
            .env(
                PROCESS_GROUP_GUARDIAN_CLEANUP_TIMEOUT_MS_ENV,
                self.cleanup_timeout.as_millis().to_string(),
            )
            .env(
                PROCESS_GROUP_GUARDIAN_LAUNCHER_PID_ENV,
                launcher_pid.to_string(),
            )
            .env(
                PROCESS_GROUP_GUARDIAN_TARGET_PGID_ENV,
                process_group.to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut watcher = match watcher_command.spawn() {
            Ok(watcher) => watcher,
            Err(error) => {
                sentinel_arm.take();
                reap_unarmed_process_group_sentinel(&watcher_reaper, sentinel);
                return Err(contextual_guardian_io(error, "spawn process-group watcher"));
            }
        };
        let watcher_id = watcher.id();
        let mut ownership = match watcher.stdin.take() {
            Some(ownership) => {
                if let Err(error) = set_nonblocking(ownership.as_raw_fd()) {
                    let mut ownership = Some(ownership);
                    return Err(reap_failed_process_group_watcher(
                        watcher,
                        sentinel,
                        &mut sentinel_arm,
                        &mut ownership,
                        process_group,
                        self.cleanup_timeout,
                        &watcher_reaper,
                        contextual_guardian_io(
                            error,
                            "make process-group cleanup request nonblocking",
                        ),
                    ));
                }
                Some(ownership)
            }
            None => {
                let mut ownership = None;
                let error = std::io::Error::other(
                    "process-group watcher did not expose its ownership pipe",
                );
                return Err(reap_failed_process_group_watcher(
                    watcher,
                    sentinel,
                    &mut sentinel_arm,
                    &mut ownership,
                    process_group,
                    self.cleanup_timeout,
                    &watcher_reaper,
                    error,
                ));
            }
        };

        loop {
            if let Ok(readiness) = std::fs::read_to_string(readiness_path) {
                if let Ok(readiness) = parse_process_group_guardian_readiness(&readiness) {
                    let validation = validate_process_group_guardian_readiness(
                        watcher_id,
                        process_group,
                        readiness,
                    );
                    if let Err(error) = validation {
                        let _ = std::fs::remove_file(readiness_path);
                        return Err(reap_failed_process_group_watcher(
                            watcher,
                            sentinel,
                            &mut sentinel_arm,
                            &mut ownership,
                            process_group,
                            self.cleanup_timeout,
                            &watcher_reaper,
                            error,
                        ));
                    }
                    if let Err(error) = arm_process_group_sentinel(&mut sentinel_arm, &mut sentinel)
                    {
                        let _ = std::fs::remove_file(readiness_path);
                        return Err(reap_failed_process_group_watcher(
                            watcher,
                            sentinel,
                            &mut sentinel_arm,
                            &mut ownership,
                            process_group,
                            self.cleanup_timeout,
                            &watcher_reaper,
                            error,
                        ));
                    }
                    let _ = std::fs::remove_file(readiness_path);
                    return Ok(ProcessGroupGuardian {
                        process_group: readiness.process_group,
                        watcher: Some(watcher),
                        sentinel: Some(sentinel),
                        ownership,
                        watcher_status: None,
                        watcher_failure: None,
                        group_barrier_completed: false,
                        finalized: false,
                        cleanup_timeout: self.cleanup_timeout,
                        watcher_reaper,
                    });
                }
                // The watcher publishes by atomic rename, but tolerate a
                // non-atomic test fixture and keep observing until the
                // deadline or watcher exit establishes the real outcome.
            }

            match watcher.try_wait() {
                Ok(Some(status)) => {
                    let _ = std::fs::remove_file(readiness_path);
                    return Err(reap_failed_process_group_watcher(
                        watcher,
                        sentinel,
                        &mut sentinel_arm,
                        &mut ownership,
                        process_group,
                        self.cleanup_timeout,
                        &watcher_reaper,
                        std::io::Error::other(format!(
                            "process-group watcher exited before readiness: {status}"
                        )),
                    ));
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
                }
                Ok(None) => {
                    let _ = std::fs::remove_file(readiness_path);
                    let error = std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "process-group watcher did not publish readiness before the deadline",
                    );
                    return Err(reap_failed_process_group_watcher(
                        watcher,
                        sentinel,
                        &mut sentinel_arm,
                        &mut ownership,
                        process_group,
                        self.cleanup_timeout,
                        &watcher_reaper,
                        error,
                    ));
                }
                Err(error) => {
                    let _ = std::fs::remove_file(readiness_path);
                    let error =
                        contextual_guardian_io(error, "inspect process-group watcher readiness");
                    return Err(reap_failed_process_group_watcher(
                        watcher,
                        sentinel,
                        &mut sentinel_arm,
                        &mut ownership,
                        process_group,
                        self.cleanup_timeout,
                        &watcher_reaper,
                        error,
                    ));
                }
            }
        }
    }
}

/// Readiness published after the watcher validates the launcher-owned sentinel.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGroupGuardianReadiness {
    /// PID of the external watcher. It must lead a group distinct from the
    /// target so group cleanup cannot kill its own cleanup authority.
    pub watcher_pid: libc::pid_t,
    /// PID and PGID of the sentinel owned and ultimately reaped by the launcher.
    pub process_group: libc::pid_t,
}

/// Parse the versioned watcher readiness record.
#[cfg(unix)]
pub fn parse_process_group_guardian_readiness(
    value: &str,
) -> std::io::Result<ProcessGroupGuardianReadiness> {
    let mut fields = value.split_whitespace();
    let version = fields.next();
    let watcher_pid = fields
        .next()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|value| *value > 0);
    let process_group = fields
        .next()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|value| *value > 0);
    if version != Some("kin-pg-guardian-v1")
        || fields.next().is_some()
        || watcher_pid.is_none()
        || process_group.is_none()
        || watcher_pid == process_group
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid process-group guardian readiness: {value:?}"),
        ));
    }
    Ok(ProcessGroupGuardianReadiness {
        watcher_pid: watcher_pid.expect("validated watcher pid"),
        process_group: process_group.expect("validated process group"),
    })
}

#[cfg(unix)]
fn validate_process_group_guardian_readiness(
    expected_watcher_id: u32,
    expected_process_group: libc::pid_t,
    readiness: ProcessGroupGuardianReadiness,
) -> std::io::Result<()> {
    let expected_watcher = libc::pid_t::try_from(expected_watcher_id).map_err(|_| {
        std::io::Error::other("process-group watcher PID does not fit a native pid")
    })?;
    if readiness.watcher_pid != expected_watcher {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "process-group watcher readiness named PID {}, expected {expected_watcher}",
                readiness.watcher_pid
            ),
        ));
    }
    if readiness.process_group != expected_process_group {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "process-group watcher readiness named target {}, expected {expected_process_group}",
                readiness.process_group
            ),
        ));
    }
    let watcher_group = unsafe { libc::getpgid(readiness.watcher_pid) };
    if watcher_group != readiness.watcher_pid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "process-group watcher does not lead its group: pid={}, pgid={watcher_group}",
                readiness.watcher_pid
            ),
        ));
    }
    let observed_target_group = unsafe { libc::getpgid(readiness.process_group) };
    if observed_target_group != readiness.process_group {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "process-group sentinel does not pin its target group: pid={}, pgid={observed_target_group}",
                readiness.process_group
            ),
        ));
    }
    Ok(())
}

/// Owned parent side of a Unix process-group guardian.
///
/// The ownership pipe tells the watcher when cleanup must start, while the
/// launcher-owned sentinel pins the target process-group identity. Configured
/// children and their ordinary fork/exec descendants inherit that group. At
/// explicit cleanup the launcher stops the whole group as a kernel-enforced
/// fork barrier, kills it repeatedly, then hands completion to the watcher. The
/// watcher performs that barrier only for owner death or failed parent cleanup.
/// The launcher reaps its sentinel and then establishes that nothing left in
/// the group can still execute, which an already-exited member satisfies whether
/// or not its process-table slot has been collected yet.
///
/// This is intentionally a same-credential, group-preserving cooperative
/// contract, not a security sandbox. A child that changes credentials or
/// deliberately detaches with `setsid`, `setpgid`, double-fork daemonization,
/// or an equivalent escape is outside the guarantee. Callers must not describe
/// such hostile descendants as contained.
#[cfg(unix)]
#[derive(Debug)]
pub struct ProcessGroupGuardian {
    process_group: libc::pid_t,
    watcher: Option<std::process::Child>,
    sentinel: Option<std::process::Child>,
    ownership: Option<std::process::ChildStdin>,
    watcher_status: Option<std::process::ExitStatus>,
    watcher_failure: Option<String>,
    group_barrier_completed: bool,
    /// Whether launcher-side finalization has already consumed the terminal
    /// watcher status, so no later call can do anything but report that.
    ///
    /// Finalization happens exactly once. Reporting the already-finalized
    /// sentinel to an explicit caller is right, and reporting it from `Drop` is
    /// pure noise: an owner that reaped its guardian and then dropped the handle
    /// is the ordinary end of a bounded probe, not a cleanup failure. Every
    /// bounded daemon probe took that shape, so a single failed daemon start
    /// printed one "failed cleanup during Drop" warning per probe and buried the
    /// real cause under them.
    finalized: bool,
    cleanup_timeout: Duration,
    watcher_reaper: std::sync::mpsc::Sender<WatcherReaperJob>,
}

#[cfg(unix)]
impl ProcessGroupGuardian {
    /// Stable target group to assign to contained children.
    pub fn process_group(&self) -> libc::pid_t {
        self.process_group
    }

    /// PID of the external watcher while it remains owned.
    pub fn watcher_id(&self) -> Option<u32> {
        self.watcher.as_ref().map(std::process::Child::id)
    }

    /// Atomically admit and spawn a child inside this guardian.
    ///
    /// The command is consumed so the guardian's `pre_exec` callback can never
    /// remain attached to a caller-reused command after a failed spawn. Rust
    /// applies the requested process group before caller callbacks, which means
    /// an earlier callback that stalls is already inside the pinned group.
    /// Taking `&mut self` makes the watcher-liveness check and spawn admission
    /// indivisible from [`Self::request_cleanup`].
    ///
    /// Callers must finish their environment/authority scrub before calling
    /// this method.
    pub fn spawn(&mut self, mut command: Command) -> std::io::Result<std::process::Child> {
        self.prepare_spawn_admission(&mut command)?;
        command.spawn()
    }

    /// Tokio equivalent of [`Self::spawn`] with the same atomic admission
    /// guarantee.
    pub fn spawn_tokio(
        &mut self,
        mut command: tokio::process::Command,
    ) -> std::io::Result<tokio::process::Child> {
        self.prepare_spawn_admission(command.as_std_mut())?;
        command.spawn()
    }

    fn prepare_spawn_admission(&mut self, command: &mut Command) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;

        self.ensure_watcher_live_for_admission()?;
        let ownership = self.ownership.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "process-group guardian admission is already sealed",
            )
        })?;
        let ownership_fd = ownership.as_raw_fd();
        command.process_group(self.process_group);
        unsafe {
            command.pre_exec(move || close_fd_allow_already_closed(ownership_fd));
        }
        Ok(())
    }

    fn ensure_watcher_live_for_admission(&mut self) -> std::io::Result<()> {
        self.observe_watcher_exit()?;
        if self.watcher.is_some() {
            return Ok(());
        }
        if self.watcher_failure.is_none() {
            let status = self
                .watcher_status
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_else(|| "unknown status".to_string());
            let fallback = self.complete_parent_barrier();
            self.record_watcher_failure(match fallback {
                Ok(()) => format!("process-group watcher exited before admission: {status}"),
                Err(error) => format!(
                    "process-group watcher exited before admission: {status}; \
                     parent fallback barrier failed: {error}"
                ),
            });
        }

        let detail = self
            .watcher_failure
            .as_deref()
            .unwrap_or("process-group watcher is no longer available");
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            format!("process-group guardian rejected child admission: {detail}"),
        ))
    }

    /// Transfer cleanup authority to the watcher.
    ///
    /// Repeated calls are harmless. On the first explicit request, the launcher
    /// keeps the ownership writer open while it runs its bounded
    /// STOP/repeated-KILL barrier. It then tells the watcher either that the
    /// parent barrier completed or that watcher fallback is required. EOF
    /// remains the fail-closed watcher trigger for launcher death or a failed
    /// handoff. Exactly one healthy authority signals the group, and neither
    /// trigger consumes the sentinel or performs final proof.
    pub fn request_cleanup(&mut self) {
        if let Some(mut ownership) = self.ownership.take() {
            let trigger = match self.complete_parent_barrier() {
                Ok(()) => ProcessGroupCleanupTrigger::ParentBarrierComplete,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "launcher-side process-group cleanup barrier failed; requiring watcher fallback"
                    );
                    ProcessGroupCleanupTrigger::WatcherBarrierRequired
                }
            };
            if let Err(error) = send_process_group_cleanup_trigger(&mut ownership, trigger) {
                tracing::warn!(
                    ?trigger,
                    %error,
                    "could not hand process-group cleanup result to watcher; EOF requires watcher fallback"
                );
            }
        }
        if let Err(error) = self.observe_watcher_exit() {
            self.record_watcher_failure(error.to_string());
        }
    }

    /// Poll and reap a completed watcher.
    ///
    /// A successful result combines the completed launcher-or-watcher
    /// STOP/repeated-KILL barrier with launcher-side sentinel reap and one final
    /// containment check, which requires every process still in the group to
    /// have exited and is satisfied trivially when the group is empty.
    pub fn try_reap(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.observe_watcher_exit()?;
        if self.watcher.is_some() {
            return Ok(None);
        }
        let Some(status) = self.watcher_status.take() else {
            return Err(std::io::Error::other(
                "process-group watcher was already finalized",
            ));
        };
        self.finalized = true;

        self.ownership.take();
        let finalization = finalize_owned_process_group(
            &mut self.sentinel,
            self.process_group,
            std::time::Instant::now() + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN,
        );
        match finalization {
            Ok(()) => {
                if let Some(failure) = self.watcher_failure.take() {
                    return Err(guardian_watcher_failure(failure, None));
                }
            }
            Err(finalization_error) => {
                if let Some(sentinel) = self.sentinel.take() {
                    transfer_owned_process_group_children_to_reaper(
                        &self.watcher_reaper,
                        None,
                        Some(sentinel),
                        self.process_group,
                        self.group_barrier_completed,
                    );
                }
                if let Some(failure) = self.watcher_failure.take() {
                    return Err(guardian_watcher_failure(failure, Some(finalization_error)));
                }
                return Err(finalization_error);
            }
        }
        Ok(Some(status))
    }

    /// Wait through watcher quiescence and launcher-side exact finalization.
    pub fn reap_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.try_reap()? {
                return Ok(status);
            }
            if self.watcher.is_none() {
                return Err(std::io::Error::other(
                    "process-group watcher was already reaped",
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "process-group watcher did not complete cleanup before the deadline",
                ));
            }
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    fn observe_watcher_exit(&mut self) -> std::io::Result<()> {
        let Some(watcher) = self.watcher.as_mut() else {
            return Ok(());
        };
        let Some(status) = watcher
            .try_wait()
            .map_err(|error| contextual_guardian_io(error, "poll process-group watcher"))?
        else {
            return Ok(());
        };
        self.watcher.take();
        self.watcher_status = Some(status);
        if status.success() {
            self.group_barrier_completed = true;
            return Ok(());
        }

        let failure = format!("process-group watcher cleanup failed with status {status}");
        let fallback = self.complete_parent_barrier();
        self.record_watcher_failure(match fallback {
            Ok(()) => failure,
            Err(error) => format!("{failure}; parent fallback barrier failed: {error}"),
        });
        Ok(())
    }

    fn quiesce_from_parent(&mut self) -> std::io::Result<()> {
        if self.sentinel.is_none() {
            return Err(std::io::Error::other(
                "process-group sentinel is no longer available for a safe fallback",
            ));
        }
        quiesce_pinned_process_group(
            self.process_group,
            std::time::Instant::now() + self.cleanup_timeout,
        )
    }

    fn complete_parent_barrier(&mut self) -> std::io::Result<()> {
        if self.group_barrier_completed {
            return Ok(());
        }
        self.quiesce_from_parent()?;
        self.group_barrier_completed = true;
        Ok(())
    }

    fn record_watcher_failure(&mut self, failure: String) {
        if self.watcher_failure.is_none() {
            self.watcher_failure = Some(failure);
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuardian {
    fn drop(&mut self) {
        // A guardian its owner already reaped owns nothing and can only report
        // the already-finalized sentinel. That is the ordinary end of a bounded
        // probe, so it is recorded and not warned about. Warning here printed
        // one "failed cleanup during Drop" line per daemon binary probe and
        // pushed the real reason a start failed out of the reader's view.
        if self.finalized {
            tracing::debug!(
                process_group = self.process_group,
                "process-group guardian dropped after its owner finalized it"
            );
            return;
        }
        self.request_cleanup();
        let deadline = std::time::Instant::now()
            + self.cleanup_timeout
            + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN;
        loop {
            match self.try_reap() {
                Ok(Some(_)) => return,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
                }
                Ok(None) => {
                    let watcher = self.watcher.take();
                    let sentinel = self.sentinel.take();
                    tracing::warn!(
                        watcher_pid = ?watcher.as_ref().map(std::process::Child::id),
                        sentinel_pid = ?sentinel.as_ref().map(std::process::Child::id),
                        "process-group guardian exceeded its cleanup bound; transferring every remaining owned child to durable reaper"
                    );
                    transfer_owned_process_group_children_to_reaper(
                        &self.watcher_reaper,
                        watcher,
                        sentinel,
                        self.process_group,
                        self.group_barrier_completed,
                    );
                    return;
                }
                Err(error) => {
                    let watcher = self.watcher.take();
                    let sentinel = self.sentinel.take();
                    if watcher.is_some() || sentinel.is_some() {
                        tracing::warn!(
                            watcher_pid = ?watcher.as_ref().map(std::process::Child::id),
                            sentinel_pid = ?sentinel.as_ref().map(std::process::Child::id),
                            %error,
                            "guardian finalization failed with children still owned; transferring every remaining handle to durable reaper"
                        );
                        transfer_owned_process_group_children_to_reaper(
                            &self.watcher_reaper,
                            watcher,
                            sentinel,
                            self.process_group,
                            self.group_barrier_completed,
                        );
                    } else {
                        tracing::warn!(
                            %error,
                            "process-group guardian reported failed cleanup during Drop"
                        );
                    }
                    return;
                }
            }
        }
    }
}

#[cfg(unix)]
fn child_id_to_pid(child: &std::process::Child, label: &str) -> std::io::Result<libc::pid_t> {
    libc::pid_t::try_from(child.id())
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| std::io::Error::other(format!("{label} PID does not fit a native pid")))
}

#[cfg(unix)]
fn set_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn close_fd_allow_already_closed(fd: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::close(fd) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn write_one_byte_nonblocking(
    writer: &mut std::process::ChildStdin,
    byte: u8,
    context: &str,
) -> std::io::Result<()> {
    use std::io::Write as _;

    let deadline = std::time::Instant::now() + PROCESS_GROUP_GUARDIAN_POLL_INTERVAL;
    loop {
        match writer.write(&[byte]) {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("{context}: one-byte write made no progress"),
                ));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted
                    && std::time::Instant::now() < deadline => {}
            Err(error) => return Err(contextual_guardian_io(error, context)),
        }
    }
}

#[cfg(unix)]
fn send_process_group_cleanup_trigger(
    ownership: &mut std::process::ChildStdin,
    trigger: ProcessGroupCleanupTrigger,
) -> std::io::Result<()> {
    write_one_byte_nonblocking(
        ownership,
        trigger as u8,
        "hand process-group cleanup result to watcher",
    )
}

#[cfg(unix)]
fn arm_process_group_sentinel(
    sentinel_arm: &mut Option<std::process::ChildStdin>,
    _sentinel: &mut std::process::Child,
) -> std::io::Result<()> {
    let mut sentinel_arm = sentinel_arm.take().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "process-group sentinel arm is no longer available",
        )
    })?;
    write_one_byte_nonblocking(&mut sentinel_arm, 1, "arm process-group sentinel")
}

#[cfg(unix)]
fn reap_unarmed_process_group_sentinel(
    reaper: &std::sync::mpsc::Sender<WatcherReaperJob>,
    mut sentinel: std::process::Child,
) {
    let sentinel_pid = sentinel.id();
    if let Err(error) = sentinel.kill() {
        tracing::warn!(
            sentinel_pid,
            %error,
            "could not terminate unarmed process-group sentinel immediately"
        );
    }
    let deadline = std::time::Instant::now() + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN;
    match reap_child_until(&mut sentinel, deadline) {
        Ok(Some(_)) => {}
        Ok(None) => {
            tracing::warn!(
                sentinel_pid,
                "unarmed process-group sentinel exceeded its direct reap bound; transferring its exact child handle to durable reaper"
            );
            transfer_owned_process_group_children_to_reaper(reaper, Some(sentinel), None, 0, false);
        }
        Err(error) => {
            tracing::warn!(
                sentinel_pid,
                %error,
                "unarmed process-group sentinel reap failed; transferring its exact child handle to durable reaper"
            );
            transfer_owned_process_group_children_to_reaper(reaper, Some(sentinel), None, 0, false);
        }
    }
}

#[cfg(unix)]
fn reap_child_until(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct WatcherReaperJob {
    watcher: Option<std::process::Child>,
    sentinel: Option<std::process::Child>,
    process_group: libc::pid_t,
    group_barrier_completed: bool,
    force_deadline: std::time::Instant,
    terminal_deadline: std::time::Instant,
    forced: bool,
    terminal_action_issued: bool,
    watcher_terminal_warning_emitted: bool,
    sentinel_terminal_warning_emitted: bool,
}

#[cfg(unix)]
static PROCESS_GROUP_WATCHER_REAPER: OnceLock<std::sync::mpsc::Sender<WatcherReaperJob>> =
    OnceLock::new();

#[cfg(unix)]
fn process_group_watcher_reaper() -> std::io::Result<std::sync::mpsc::Sender<WatcherReaperJob>> {
    if let Some(reaper) = PROCESS_GROUP_WATCHER_REAPER.get() {
        return Ok(reaper.clone());
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("kin-process-group-watcher-reaper".to_string())
        .spawn(move || process_group_watcher_reaper_loop(receiver))
        .map_err(|error| {
            contextual_guardian_io(error, "start durable process-group watcher reaper")
        })?;
    match PROCESS_GROUP_WATCHER_REAPER.set(sender.clone()) {
        Ok(()) => Ok(sender),
        Err(_) => Ok(PROCESS_GROUP_WATCHER_REAPER
            .get()
            .expect("another thread initialized the watcher reaper")
            .clone()),
    }
}

#[cfg(unix)]
fn process_group_watcher_reaper_loop(receiver: std::sync::mpsc::Receiver<WatcherReaperJob>) {
    let mut jobs = Vec::new();
    loop {
        match receiver.recv_timeout(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL) {
            Ok(job) => jobs.push(job),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if jobs.is_empty() => return,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        }
        while let Ok(job) = receiver.try_recv() {
            jobs.push(job);
        }
        let mut index = 0;
        while index < jobs.len() {
            if poll_watcher_reaper_job(&mut jobs[index]) {
                jobs.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }
}

#[cfg(unix)]
fn poll_watcher_reaper_job(job: &mut WatcherReaperJob) -> bool {
    let now = std::time::Instant::now();

    let watcher_poll = job.watcher.as_mut().map(std::process::Child::try_wait);
    if let Some(watcher_poll) = watcher_poll {
        match watcher_poll {
            Ok(Some(status)) => {
                job.watcher.take();
                if status.success() {
                    job.group_barrier_completed = true;
                } else if !job.forced {
                    issue_reaper_group_barrier(job, now);
                    job.forced = true;
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    watcher_pid = ?job.watcher.as_ref().map(std::process::Child::id),
                    %error,
                    "durable reaper could not poll watcher; retaining owned handle"
                );
            }
        }
    }

    if job.watcher.is_some() && now >= job.force_deadline && !job.forced {
        issue_reaper_group_barrier(job, now);
        if let Some(watcher) = job.watcher.as_mut() {
            let _ = watcher.kill();
        }
        job.forced = true;
    }

    if job.watcher.is_some() && now >= job.terminal_deadline && !job.terminal_action_issued {
        issue_reaper_group_barrier(job, now);
        if let Some(watcher) = job.watcher.as_mut() {
            let _ = watcher.kill();
        }
        job.terminal_action_issued = true;
    }

    if job.watcher.is_some()
        && job.terminal_action_issued
        && now >= job.terminal_deadline + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN
        && !job.watcher_terminal_warning_emitted
    {
        tracing::error!(
            watcher_pid = ?job.watcher.as_ref().map(std::process::Child::id),
            "watcher exceeded its hard terminal reap bound; retaining and polling its owned handle"
        );
        job.watcher_terminal_warning_emitted = true;
    }

    // The watcher may still send group signals until its status is collected.
    // Never consume the sentinel (and release the numeric PGID pin) first.
    if job.watcher.is_some() {
        return false;
    }

    let Some(sentinel_poll) = job.sentinel.as_mut().map(std::process::Child::try_wait) else {
        return true;
    };
    match sentinel_poll {
        Ok(Some(status)) => {
            job.sentinel.take();
            log_reaper_group_finalization(status, job.process_group);
            true
        }
        Ok(None) => {
            if now >= job.terminal_deadline && !job.terminal_action_issued {
                issue_reaper_group_barrier(job, now);
                job.terminal_action_issued = true;
            }
            if job.terminal_action_issued
                && now >= job.terminal_deadline + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN
                && !job.sentinel_terminal_warning_emitted
            {
                tracing::error!(
                    sentinel_pid = ?job.sentinel.as_ref().map(std::process::Child::id),
                    "sentinel exceeded its hard terminal reap bound; retaining and polling its owned handle"
                );
                job.sentinel_terminal_warning_emitted = true;
            }
            false
        }
        Err(error) => {
            tracing::warn!(
                sentinel_pid = ?job.sentinel.as_ref().map(std::process::Child::id),
                %error,
                "durable reaper could not poll sentinel; retaining owned handle"
            );
            false
        }
    }
}

#[cfg(unix)]
fn issue_reaper_group_barrier(job: &mut WatcherReaperJob, now: std::time::Instant) {
    if job.sentinel.is_none() || job.group_barrier_completed {
        return;
    }
    match quiesce_pinned_process_group(
        job.process_group,
        now + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN,
    ) {
        Ok(()) => job.group_barrier_completed = true,
        Err(error) => {
            tracing::warn!(
                watcher_pid = ?job.watcher.as_ref().map(std::process::Child::id),
                sentinel_pid = ?job.sentinel.as_ref().map(std::process::Child::id),
                %error,
                "durable reaper could not complete the pinned-group barrier"
            );
        }
    }
}

#[cfg(unix)]
fn log_reaper_group_finalization(
    sentinel_status: std::process::ExitStatus,
    process_group: libc::pid_t,
) {
    let sentinel_was_killed = sentinel_exit_was_signalled(sentinel_status);
    // The sentinel handle was just reaped and consumed. This is the one final
    // group probe; no reaper path may signal the numeric PGID after this call.
    // It asks the same containment question the launcher path asks, because an
    // observable group holding nothing but uncollected corpses is contained, and
    // logging that benign state as an error trained operators to ignore the log
    // line that reports a real escape.
    let containment = process_group_containment(process_group);
    if !sentinel_was_killed {
        tracing::error!(
            %sentinel_status,
            process_group,
            "durable reaper observed unexpected sentinel exit"
        );
    }
    match containment {
        ProcessGroupContainment::Empty | ProcessGroupContainment::OnlyExited => {}
        ProcessGroupContainment::LiveMember { pid } => tracing::error!(
            process_group,
            live_pid = pid,
            "durable reaper final probe found a live process in the process group"
        ),
        ProcessGroupContainment::Indeterminate { detail } => tracing::warn!(
            process_group,
            %detail,
            "durable reaper could not establish process-group containment"
        ),
    }
}

#[cfg(unix)]
fn transfer_process_group_watcher_to_reaper(
    reaper: &std::sync::mpsc::Sender<WatcherReaperJob>,
    watcher: std::process::Child,
    sentinel: std::process::Child,
    process_group: libc::pid_t,
) {
    transfer_owned_process_group_children_to_reaper(
        reaper,
        Some(watcher),
        Some(sentinel),
        process_group,
        false,
    );
}

#[cfg(unix)]
fn transfer_owned_process_group_children_to_reaper(
    reaper: &std::sync::mpsc::Sender<WatcherReaperJob>,
    watcher: Option<std::process::Child>,
    sentinel: Option<std::process::Child>,
    process_group: libc::pid_t,
    group_barrier_completed: bool,
) {
    debug_assert!(watcher.is_some() || sentinel.is_some());
    let force_deadline = std::time::Instant::now();
    let job = WatcherReaperJob {
        watcher,
        sentinel,
        process_group,
        group_barrier_completed,
        force_deadline,
        terminal_deadline: force_deadline + PROCESS_GROUP_GUARDIAN_REAPER_TERMINAL_MARGIN,
        forced: false,
        terminal_action_issued: false,
        watcher_terminal_warning_emitted: false,
        sentinel_terminal_warning_emitted: false,
    };
    if let Err(error) = reaper.send(job) {
        let job = error.0;
        tracing::error!(
            watcher_pid = ?job.watcher.as_ref().map(std::process::Child::id),
            sentinel_pid = ?job.sentinel.as_ref().map(std::process::Child::id),
            "durable process-group watcher reaper disconnected; starting retained fallback reaper"
        );
        start_retained_fallback_reaper(job);
    }
}

#[cfg(unix)]
fn reap_failed_process_group_watcher(
    mut watcher: std::process::Child,
    mut sentinel: std::process::Child,
    sentinel_arm: &mut Option<std::process::ChildStdin>,
    ownership: &mut Option<std::process::ChildStdin>,
    process_group: libc::pid_t,
    cleanup_timeout: Duration,
    watcher_reaper: &std::sync::mpsc::Sender<WatcherReaperJob>,
    primary_error: std::io::Error,
) -> std::io::Error {
    let arm_error = arm_process_group_sentinel(sentinel_arm, &mut sentinel).err();
    if let Some(mut ownership) = ownership.take() {
        if let Err(error) = send_process_group_cleanup_trigger(
            &mut ownership,
            ProcessGroupCleanupTrigger::WatcherBarrierRequired,
        ) {
            tracing::warn!(
                %error,
                "could not require watcher cleanup after guardian startup failure; EOF remains fail-closed"
            );
        }
    }
    let deadline =
        std::time::Instant::now() + cleanup_timeout + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN;
    match reap_child_until(&mut watcher, deadline) {
        Ok(Some(status)) => {
            let fallback = if status.success() {
                Ok(())
            } else {
                quiesce_pinned_process_group(process_group, deadline)
            };
            let group_barrier_completed = fallback.is_ok();
            let mut sentinel = Some(sentinel);
            let finalization = finalize_owned_process_group(&mut sentinel, process_group, deadline);
            let finalization_error = finalization.err();
            if let Some(sentinel) = sentinel.take() {
                transfer_owned_process_group_children_to_reaper(
                    watcher_reaper,
                    None,
                    Some(sentinel),
                    process_group,
                    group_barrier_completed,
                );
            }
            guardian_startup_failure(primary_error, arm_error, fallback.err(), finalization_error)
        }
        Ok(None) => {
            let watcher_pid = watcher.id();
            transfer_process_group_watcher_to_reaper(
                watcher_reaper,
                watcher,
                sentinel,
                process_group,
            );
            std::io::Error::new(
                primary_error.kind(),
                format!(
                    "{primary_error}; process-group watcher exceeded cleanup bound \
                     and was transferred to the durable reaper (pid={watcher_pid})"
                ),
            )
        }
        Err(reap_error) => {
            let watcher_pid = watcher.id();
            transfer_process_group_watcher_to_reaper(
                watcher_reaper,
                watcher,
                sentinel,
                process_group,
            );
            std::io::Error::new(
                primary_error.kind(),
                format!(
                    "{primary_error}; process-group watcher reap failed: {reap_error} \
                     and was transferred to the durable reaper (pid={watcher_pid})"
                ),
            )
        }
    }
}

#[cfg(unix)]
fn start_retained_fallback_reaper(job: WatcherReaperJob) {
    let retained = std::sync::Arc::new(std::sync::Mutex::new(Some(job)));
    let worker_retained = std::sync::Arc::clone(&retained);
    let spawn = std::thread::Builder::new()
        .name("kin-process-group-fallback-reaper".to_string())
        .spawn(move || {
            let mut job = worker_retained
                .lock()
                .expect("fallback reaper job lock poisoned")
                .take()
                .expect("fallback reaper job already taken");
            run_retained_watcher_reaper_job(&mut job);
        });
    if let Err(error) = spawn {
        tracing::error!(
            %error,
            "could not start fallback reaper thread; attempting bounded synchronous drain"
        );
        let mut job = retained
            .lock()
            .expect("fallback reaper job lock poisoned")
            .take()
            .expect("failed fallback thread must leave its job owned");
        let drain_deadline = std::time::Instant::now() + PROCESS_GROUP_GUARDIAN_PARENT_REAP_MARGIN;
        while std::time::Instant::now() < drain_deadline {
            if poll_watcher_reaper_job(&mut job) {
                return;
            }
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
        issue_reaper_group_barrier(&mut job, std::time::Instant::now());
        tracing::error!(
            watcher_pid = ?job.watcher.as_ref().map(std::process::Child::id),
            sentinel_pid = ?job.sentinel.as_ref().map(std::process::Child::id),
            "catastrophic reaper failure: intentionally retaining owned child handles after bounded drain"
        );
        let _retained_forever = Box::leak(Box::new(job));
    }
}

#[cfg(unix)]
fn run_retained_watcher_reaper_job(job: &mut WatcherReaperJob) {
    while !poll_watcher_reaper_job(job) {
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessGroupSignalOutcome {
    Delivered,
    Absent,
}

#[cfg(unix)]
fn quiesce_pinned_process_group(
    process_group: libc::pid_t,
    deadline: std::time::Instant,
) -> std::io::Result<()> {
    if signal_process_group_strict(process_group, libc::SIGSTOP)?
        == ProcessGroupSignalOutcome::Absent
    {
        return Ok(());
    }
    if signal_process_group_strict(process_group, libc::SIGKILL)?
        == ProcessGroupSignalOutcome::Absent
    {
        return Ok(());
    }
    for _ in 1..PROCESS_GROUP_GUARDIAN_KILL_PASSES {
        if signal_process_group_after_delivered_kill(process_group)?
            == ProcessGroupSignalOutcome::Absent
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "process-group STOP/KILL barrier exceeded its deadline",
            ));
        }
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }
    Ok(())
}

/// Wait out the kill-to-exit window of the group's remaining members.
///
/// The cleanup barrier delivers SIGKILL to the whole group before finalization
/// runs, but delivery is not death: the kernel retires a condemned process on
/// its own schedule, and on a loaded host that lags the barrier by whole
/// scheduler quanta, longer when the member is mid-fsync in uninterruptible
/// sleep. The probe after sentinel reap runs exactly once, so any settling has
/// to happen here, while the unreaped sentinel handle still pins the numeric
/// group id and every member this reads is provably ours.
///
/// This settles and never judges. Whatever state the group is in at the
/// deadline, the caller's single post-reap probe stays the one authority that
/// can fail, with its richer diagnosis (sentinel exit reason included) intact.
#[cfg(unix)]
fn settle_pinned_group_member_exits(process_group: libc::pid_t, deadline: std::time::Instant) {
    loop {
        match process_group_containment(process_group) {
            ProcessGroupContainment::Empty | ProcessGroupContainment::OnlyExited => return,
            ProcessGroupContainment::LiveMember { .. }
            | ProcessGroupContainment::Indeterminate { .. } => {
                if std::time::Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
            }
        }
    }
}

#[cfg(unix)]
fn finalize_owned_process_group(
    sentinel: &mut Option<std::process::Child>,
    process_group: libc::pid_t,
    deadline: std::time::Instant,
) -> std::io::Result<()> {
    let sentinel_child = sentinel
        .as_mut()
        .ok_or_else(|| std::io::Error::other("process-group sentinel was already finalized"))?;
    settle_pinned_group_member_exits(process_group, deadline);
    let status = reap_child_until(sentinel_child, deadline)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "process-group sentinel did not exit before finalization deadline",
        )
    })?;
    let sentinel_was_killed = sentinel_exit_was_signalled(status);
    // Taking the already-reaped handle releases the PID pin. From this point
    // onward no code may send STOP/KILL to the numeric process group.
    sentinel.take();

    // This is deliberately the one and only post-reap numeric group probe.
    let containment = process_group_containment(process_group);
    if !sentinel_was_killed {
        return Err(std::io::Error::other(format!(
            "process-group sentinel exited unexpectedly: {status}; group containment: \
             {containment:?}"
        )));
    }
    match containment {
        ProcessGroupContainment::Empty | ProcessGroupContainment::OnlyExited => Ok(()),
        ProcessGroupContainment::LiveMember { pid } => Err(std::io::Error::other(format!(
            "process group {process_group} still holds live process {pid} after sentinel reap; \
             callers must kill and wait owned direct children before guardian finalization"
        ))),
        ProcessGroupContainment::Indeterminate { detail } => Err(std::io::Error::other(format!(
            "process group {process_group} containment could not be established after sentinel \
             reap: {detail}"
        ))),
    }
}

/// What the process group holds once the sentinel has been reaped.
///
/// The distinction that matters is between a process that can still run and one
/// that only still has a slot in the process table.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessGroupContainment {
    /// No member remains: `kill(-pgid, 0)` reported ESRCH.
    Empty,
    /// Members remain, and every one of them has already exited.
    OnlyExited,
    /// A member remains that has not exited.
    LiveMember { pid: libc::pid_t },
    /// The group is non-empty and its members could not be classified.
    Indeterminate { detail: String },
}

/// Classify a process group after its members have been killed.
///
/// `kill(-pgid, 0)` answers "does this group have members", which is not the
/// question. A process that has exited but has not been waited keeps its slot in
/// the process table and stays a member of its group, so an ESRCH-only test
/// cannot tell a group that still runs code from a group that holds nothing but
/// corpses.
///
/// The caller waits the children it owns, but that does not close the gap. A
/// grandchild that outlives its parent is reparented to init, and its exited
/// slot is cleared when init gets around to it, which is a window no caller
/// participates in. Failing closed on that window is what turned a correct
/// cleanup into an intermittent error whenever the machine was busy enough to
/// widen it.
///
/// An exited process holds no address space, executes no instructions, and
/// cannot fork, so it cannot leave the group or outlive this call in any sense
/// the containment guarantee is about. Reporting it as contained is what the
/// guarantee already means, stated precisely.
///
/// Indeterminate is kept separate from both answers on purpose. A group that is
/// non-empty and unreadable is not proof of containment, and quietly treating it
/// as empty would be the silent-pass failure this whole path exists to prevent.
#[cfg(unix)]
fn process_group_containment(process_group: libc::pid_t) -> ProcessGroupContainment {
    if unsafe { libc::kill(-process_group, 0) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return ProcessGroupContainment::Empty;
    }
    match process_group_members(process_group) {
        Ok(members) if members.is_empty() => {
            // The group emptied between the two calls. Nothing remains to run.
            ProcessGroupContainment::Empty
        }
        Ok(members) => {
            for pid in members {
                match process_has_exited(pid) {
                    Ok(true) => {}
                    Ok(false) => return ProcessGroupContainment::LiveMember { pid },
                    Err(error) => {
                        return ProcessGroupContainment::Indeterminate {
                            detail: format!("classify member {pid}: {error}"),
                        };
                    }
                }
            }
            ProcessGroupContainment::OnlyExited
        }
        Err(error) => ProcessGroupContainment::Indeterminate {
            detail: format!("enumerate group members: {error}"),
        },
    }
}

/// `proc_listpids` selector for "processes in this process group".
///
/// Declared here because `libc` exposes `proc_listpids` and the other selectors
/// but not this one. The value is `PROC_PGRP_ONLY` from
/// `<sys/proc_info.h>`; it is part of the same stable numbering as
/// [`libc::PROC_PIDTBSDINFO`], which this crate's sibling identity probe
/// already depends on.
#[cfg(target_os = "macos")]
const PROC_PGRP_ONLY: u32 = 2;

/// Bytes reported by one `proc_listpids` call, with failure kept distinct from
/// an empty answer.
///
/// `proc_listpids` does not use the -1/errno convention the rest of this module
/// reads. libproc turns a failed `__proc_info` into a return of 0, and rejects
/// an unknown selector the same way, leaving the reason in errno. So the return
/// value alone cannot separate "this group has no members" from "this query
/// failed", and a `< 0` test never fires. Clearing errno first is what makes the
/// two distinguishable.
///
/// That distinction is the point of the call. An unreadable group reported as an
/// empty one classifies as [`ProcessGroupContainment::Empty`], which
/// finalization accepts, so anything that denies `proc_info` would silently
/// disable the containment check for the lifetime of the process while
/// reporting success.
#[cfg(target_os = "macos")]
fn list_process_group_bytes(
    group: u32,
    buffer: *mut libc::c_void,
    byte_len: i32,
) -> std::io::Result<usize> {
    unsafe { *libc::__error() = 0 };
    let written = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group, buffer, byte_len) };
    if written > 0 {
        return Ok(written as usize);
    }
    let failure = std::io::Error::last_os_error();
    // Only a failing call writes errno here, so an untouched errno is the one
    // reading under which zero means the group is genuinely empty.
    if written == 0 && failure.raw_os_error() == Some(0) {
        return Ok(0);
    }
    Err(failure)
}

/// PIDs currently reported as members of a process group.
#[cfg(target_os = "macos")]
fn process_group_members(process_group: libc::pid_t) -> std::io::Result<Vec<libc::pid_t>> {
    let group = u32::try_from(process_group)
        .map_err(|_| std::io::Error::other("process group id does not fit a selector argument"))?;
    // Ask for the size first, then read with headroom: the group can only be
    // shrinking here, so a buffer sized for the earlier answer cannot truncate a
    // later one, and the headroom absorbs the case where it somehow grew.
    let needed = list_process_group_bytes(group, std::ptr::null_mut(), 0)?;
    if needed == 0 {
        return Ok(Vec::new());
    }
    let slots = needed / std::mem::size_of::<u32>() + 8;
    let mut buffer = vec![0u32; slots];
    let byte_len = i32::try_from(buffer.len() * std::mem::size_of::<u32>())
        .map_err(|_| std::io::Error::other("process group member buffer exceeds a c_int"))?;
    let written = list_process_group_bytes(group, buffer.as_mut_ptr().cast(), byte_len)?;
    let count = written / std::mem::size_of::<u32>();
    Ok(buffer
        .into_iter()
        .take(count)
        // A zero slot is padding, not a process.
        .filter(|pid| *pid != 0)
        .map(|pid| pid as libc::pid_t)
        .collect())
}

/// Whether a process has exited but still occupies a process-table slot.
///
/// Two probes decide this, because each one alone is ambiguous and together
/// they are not.
///
/// [`libc::PROC_PIDTBSDINFO`] is assembled from the process's task. An exited
/// process has released its task while keeping its proc entry, so this query
/// fails with ESRCH for exactly the processes this function exists to
/// recognize. `kill(pid, 0)` reads the proc entry instead, and still succeeds
/// for them. So info-unavailable *and* signallable is a positive identification
/// of a process that has exited, not an absence of evidence.
///
/// The remaining combinations are unambiguous. Info available means a task
/// exists, so the process has not exited. Neither available means the entry is
/// gone, which is more than exited. Any other error is neither, and is reported
/// as an error rather than guessed, because these members are this program's
/// own descendants and a failure to inspect one is not something to paper over.
///
/// The state field would say this directly, but the struct that carries it for
/// exited processes is not in the `libc` version this workspace pins, and
/// hand-declaring a kernel struct layout to save two syscalls is a worse trade
/// than deriving it from two calls whose meanings are documented.
#[cfg(target_os = "macos")]
fn process_has_exited(pid: libc::pid_t) -> std::io::Result<bool> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::addr_of_mut!(info).cast(),
            expected as i32,
        )
    };
    if written == expected as i32 {
        return Ok(false);
    }
    let info_error = std::io::Error::last_os_error();
    if info_error.raw_os_error() != Some(libc::ESRCH) {
        return Err(info_error);
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        // A proc entry with no task behind it.
        return Ok(true);
    }
    let signal_error = std::io::Error::last_os_error();
    match signal_error.raw_os_error() {
        // Gone from the table entirely.
        Some(libc::ESRCH) => Ok(true),
        _ => Err(signal_error),
    }
}

/// PIDs currently reported as members of a process group.
///
/// Linux has no group-scoped process query, so this reads the one place the
/// kernel publishes a process's group. This is process-table IO, not repository
/// content: it answers a question about this program's own children.
#[cfg(target_os = "linux")]
fn process_group_members(process_group: libc::pid_t) -> std::io::Result<Vec<libc::pid_t>> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        // A process that exits mid-scan is simply not a member any more.
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if parse_proc_stat_process_group(&stat) == Some(process_group) {
            members.push(pid);
        }
    }
    Ok(members)
}

/// Whether a process has exited but still occupies a process-table slot.
#[cfg(target_os = "linux")]
fn process_has_exited(pid: libc::pid_t) -> std::io::Result<bool> {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => parse_proc_stat_state(&stat)
            .map(|state| state == 'Z')
            .ok_or_else(|| std::io::Error::other(format!("unparseable /proc/{pid}/stat"))),
        // Gone entirely, which is more than exited.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

/// Fields after the executable name in `/proc/<pid>/stat`.
///
/// The name is parenthesized and may itself contain spaces and parentheses, so
/// splitting the whole line on whitespace mis-parses any process whose name
/// contains one. Everything after the final `)` is fixed-width and safe to
/// split, which is what `proc(5)` documents and what every correct reader does.
#[cfg(target_os = "linux")]
fn proc_stat_fields_after_name(stat: &str) -> Option<Vec<&str>> {
    let tail = &stat[stat.rfind(')')? + 1..];
    Some(tail.split_whitespace().collect())
}

/// The single-character run state: field 3 overall, first after the name.
#[cfg(target_os = "linux")]
fn parse_proc_stat_state(stat: &str) -> Option<char> {
    proc_stat_fields_after_name(stat)?.first()?.chars().next()
}

/// The process group id: field 5 overall, third after the name.
#[cfg(target_os = "linux")]
fn parse_proc_stat_process_group(stat: &str) -> Option<libc::pid_t> {
    proc_stat_fields_after_name(stat)?
        .get(2)?
        .parse::<libc::pid_t>()
        .ok()
}

/// Targets with neither a group query nor a published process table cannot
/// classify members, so containment stays indeterminate rather than assumed.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn process_group_members(_process_group: libc::pid_t) -> std::io::Result<Vec<libc::pid_t>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-group member enumeration is unsupported on this platform",
    ))
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn process_has_exited(_pid: libc::pid_t) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process exit-state inspection is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn guardian_watcher_failure(
    failure: impl std::fmt::Display,
    finalization_error: Option<std::io::Error>,
) -> std::io::Error {
    match finalization_error {
        Some(error) => {
            std::io::Error::other(format!("{failure}; group finalization failed: {error}"))
        }
        None => std::io::Error::other(failure.to_string()),
    }
}

#[cfg(unix)]
fn guardian_startup_failure(
    primary: std::io::Error,
    arm_error: Option<std::io::Error>,
    fallback_error: Option<std::io::Error>,
    finalization_error: Option<std::io::Error>,
) -> std::io::Error {
    let mut message = primary.to_string();
    if let Some(error) = arm_error {
        message.push_str(&format!("; sentinel arm failed: {error}"));
    }
    if let Some(error) = fallback_error {
        message.push_str(&format!("; parent fallback barrier failed: {error}"));
    }
    if let Some(error) = finalization_error {
        message.push_str(&format!("; group finalization failed: {error}"));
    }
    std::io::Error::new(primary.kind(), message)
}

/// Run the internal guardian or sentinel mode selected in the environment.
///
/// Product executables call this before parsing normal arguments. Exact Rust
/// test workers call it as their complete test body. `Ok(false)` means no
/// internal mode was requested and normal executable startup should continue.
#[cfg(unix)]
pub fn run_process_group_guardian_if_requested() -> std::io::Result<bool> {
    match std::env::var(PROCESS_GROUP_GUARDIAN_MODE_ENV).as_deref() {
        Ok(PROCESS_GROUP_GUARDIAN_WATCHER_MODE) => {
            run_process_group_watcher()?;
            Ok(true)
        }
        Ok(PROCESS_GROUP_GUARDIAN_SENTINEL_MODE) => {
            run_process_group_sentinel();
        }
        _ => Ok(false),
    }
}

/// Non-Unix executables have no process-group guardian mode.
#[cfg(not(unix))]
pub fn run_process_group_guardian_if_requested() -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn run_process_group_sentinel() -> ! {
    use std::io::Read as _;

    let launcher_pid = match required_positive_pid_env(PROCESS_GROUP_GUARDIAN_LAUNCHER_PID_ENV) {
        Ok(pid) => pid,
        Err(_) => unsafe { libc::_exit(70) },
    };
    if set_nonblocking(libc::STDIN_FILENO).is_err() {
        unsafe { libc::_exit(70) };
    }

    // Before the watcher publishes readiness, the sentinel is deliberately
    // unarmed. Launcher death changes PPID (and closes stdin), so a death in
    // the sentinel/watcher launch gap cannot strand a pinned numeric PGID.
    let mut arm = std::io::stdin().lock();
    let mut byte = [0_u8; 1];
    loop {
        match arm.read(&mut byte) {
            Ok(1) => break,
            Ok(0) => unsafe { libc::_exit(0) },
            Ok(_) => unreachable!("one-byte sentinel arm buffer"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => unsafe { libc::_exit(70) },
        }
        if unsafe { libc::getppid() } != launcher_pid {
            unsafe { libc::_exit(0) };
        }
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }

    loop {
        if unsafe { libc::getppid() } != launcher_pid {
            // The watcher remains the owner-death STOP/KILL authority. This
            // direct group kill is the last-resort backstop for simultaneous
            // launcher and watcher loss; it necessarily includes the sentinel.
            let process_group = unsafe { libc::getpgrp() };
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
                libc::_exit(70);
            }
        }
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn run_process_group_watcher() -> std::io::Result<()> {
    if std::env::var_os(PROCESS_GROUP_GUARDIAN_EXIT_BEFORE_READY_ENV).is_some() {
        return Err(std::io::Error::other(
            "injected process-group watcher exit before readiness",
        ));
    }

    let readiness_path = std::env::var_os(PROCESS_GROUP_GUARDIAN_READY_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "process-group watcher has no readiness path",
            )
        })?;
    let cleanup_timeout = std::env::var(PROCESS_GROUP_GUARDIAN_CLEANUP_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|value| !value.is_zero())
        .unwrap_or(PROCESS_GROUP_GUARDIAN_DEFAULT_CLEANUP_TIMEOUT);
    let launcher_pid = required_positive_pid_env(PROCESS_GROUP_GUARDIAN_LAUNCHER_PID_ENV)?;
    let process_group = required_positive_pid_env(PROCESS_GROUP_GUARDIAN_TARGET_PGID_ENV)?;
    let observed_group = unsafe { libc::getpgid(process_group) };
    if observed_group != process_group {
        return Err(std::io::Error::other(format!(
            "process-group watcher did not find its launcher-owned sentinel: \
             pid={process_group}, pgid={observed_group}"
        )));
    }

    set_nonblocking(libc::STDIN_FILENO).map_err(|error| {
        contextual_guardian_io(error, "make process-group ownership channel nonblocking")
    })?;
    publish_process_group_guardian_readiness(&readiness_path, process_group)?;
    match wait_for_process_group_cleanup_trigger(launcher_pid) {
        Ok(ProcessGroupCleanupTrigger::ParentBarrierComplete) => Ok(()),
        Ok(ProcessGroupCleanupTrigger::WatcherBarrierRequired) => {
            quiesce_pinned_process_group(process_group, std::time::Instant::now() + cleanup_timeout)
        }
        Err(trigger_error) => {
            let cleanup = quiesce_pinned_process_group(
                process_group,
                std::time::Instant::now() + cleanup_timeout,
            );
            match cleanup {
                Ok(()) => Err(trigger_error),
                Err(cleanup_error) => Err(std::io::Error::new(
                    trigger_error.kind(),
                    format!(
                        "{trigger_error}; fail-closed watcher barrier also failed: {cleanup_error}"
                    ),
                )),
            }
        }
    }
}

#[cfg(unix)]
fn publish_process_group_guardian_readiness(
    readiness_path: &Path,
    process_group: libc::pid_t,
) -> std::io::Result<()> {
    let watcher_pid = unsafe { libc::getpid() };
    let watcher_group = unsafe { libc::getpgrp() };
    if watcher_pid <= 0 || watcher_group != watcher_pid || watcher_pid == process_group {
        return Err(std::io::Error::other(format!(
            "invalid process-group watcher topology: pid={watcher_pid}, pgid={watcher_group}, target={process_group}"
        )));
    }
    let readiness = format!("kin-pg-guardian-v1 {watcher_pid} {process_group}\n");
    let temporary_path = readiness_path.with_extension(format!("tmp-{watcher_pid}"));
    std::fs::write(&temporary_path, readiness)
        .map_err(|error| contextual_guardian_io(error, "write process-group watcher readiness"))?;
    std::fs::rename(&temporary_path, readiness_path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary_path);
        contextual_guardian_io(error, "publish process-group watcher readiness")
    })
}

#[cfg(unix)]
fn wait_for_process_group_cleanup_trigger(
    launcher_pid: libc::pid_t,
) -> std::io::Result<ProcessGroupCleanupTrigger> {
    use std::io::Read as _;

    let mut ownership = std::io::stdin().lock();
    let mut buffer = [0_u8; 1];
    loop {
        match ownership.read(&mut buffer) {
            Ok(0) => return Ok(ProcessGroupCleanupTrigger::WatcherBarrierRequired),
            Ok(1) => return ProcessGroupCleanupTrigger::parse(buffer[0]),
            Ok(_) => unreachable!("one-byte process-group cleanup buffer"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(contextual_guardian_io(
                    error,
                    "read process-group watcher ownership pipe",
                ));
            }
        }
        if unsafe { libc::getppid() } != launcher_pid {
            return Ok(ProcessGroupCleanupTrigger::WatcherBarrierRequired);
        }
        std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn required_positive_pid_env(name: &str) -> std::io::Result<libc::pid_t> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("process-group internal mode has no valid {name}"),
            )
        })
}

#[cfg(unix)]
fn signal_process_group_strict(
    process_group: libc::pid_t,
    signal: libc::c_int,
) -> std::io::Result<ProcessGroupSignalOutcome> {
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == 0 {
        return Ok(ProcessGroupSignalOutcome::Delivered);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(ProcessGroupSignalOutcome::Absent)
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn signal_process_group_after_delivered_kill(
    process_group: libc::pid_t,
) -> std::io::Result<ProcessGroupSignalOutcome> {
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(ProcessGroupSignalOutcome::Delivered);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(ProcessGroupSignalOutcome::Absent),
        Some(libc::EPERM) => {
            // This path is reachable only after a same-credential SIGKILL was
            // delivered successfully. Darwin reports EPERM once that group is
            // zombie-only. An initial STOP or KILL EPERM remains a hard error.
            Ok(ProcessGroupSignalOutcome::Absent)
        }
        _ => Err(error),
    }
}

/// Whether the sentinel died because something signalled it rather than
/// because it decided to leave.
///
/// The distinction this draws is between a sentinel the barrier killed and a
/// sentinel that returned on its own, because only the second one releases the
/// PID pin early and leaves a numeric PGID free to be recycled under a caller
/// still signalling it. A sentinel that leaves on its own always does so
/// through [`libc::_exit`], so every self-exit carries a code and no signal;
/// rejecting those is what gives this check its teeth, and both `_exit(0)` and
/// `_exit(70)` stay rejected here.
///
/// SIGKILL is the barrier's own signal. SIGHUP is the kernel's, and it arrives
/// as a direct consequence of the barrier: `quiesce_pinned_process_group`
/// opens by stopping the whole group, and POSIX requires that when a process
/// group becomes orphaned while any member is stopped, every member is sent
/// SIGHUP followed by SIGCONT. The window between that STOP and the KILL that
/// follows it is small but real, so a group orphaned inside it loses its
/// sentinel to SIGHUP before the barrier's own KILL can land. Reading that as
/// an unexpected exit failed runs whose containment had actually succeeded.
///
/// Accepting SIGHUP costs nothing that was being checked here. This crate
/// never sends SIGHUP and the sentinel installs no handler for it, so a SIGHUP
/// death cannot be self-inflicted. Containment itself is proven separately by
/// [`process_group_containment`], which enumerates the group and classifies
/// every member, and which keeps deciding both callers.
#[cfg(unix)]
fn sentinel_exit_was_signalled(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;

    matches!(status.signal(), Some(libc::SIGKILL) | Some(libc::SIGHUP))
}

#[cfg(unix)]
fn contextual_guardian_io(
    error: std::io::Error,
    context: impl std::fmt::Display,
) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{context}: {error}"))
}

// ── Spawn plan ──────────────────────────────────────────────────────────

/// Everything a daemon spawn needs, assembled once so both callers pass the
/// same argv, environment, and process-group treatment.
#[derive(Debug, Clone)]
pub struct DaemonSpawnPlan {
    /// The `kin-daemon` executable to run.
    pub daemon_bin: PathBuf,
    /// The repository working directory (the parent of `.kin`).
    pub working_dir: PathBuf,
    /// Idle timeout to inject, or `None` to leave the daemon's default alone.
    ///
    /// An explicit `KIN_DAEMON_IDLE_TIMEOUT_SECS` in the caller's environment
    /// always wins; resolve that before building the plan.
    pub idle_timeout_secs: Option<&'static str>,
    /// Supervisor endpoint to hand the daemon, when the caller has one.
    pub supervisor_url: Option<String>,
}

impl DaemonSpawnPlan {
    /// Build the command that starts the daemon.
    ///
    /// Callers still choose stdio: the CLI redirects into the daemon log so a
    /// failed start has a tail to report, while the MCP path has no log handle
    /// of its own. Everything that governs *which daemon comes up* is decided
    /// here.
    pub fn command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.daemon_bin);
        scrub_daemon_process_authority(&mut cmd);
        cmd.args([
            "--repo",
            &self.working_dir.display().to_string(),
            "--port",
            DAEMON_PORT_ARGUMENT,
        ]);
        if let Some(timeout) = self.idle_timeout_secs {
            cmd.env("KIN_DAEMON_IDLE_TIMEOUT_SECS", timeout);
        }
        if let Some(supervisor_url) = &self.supervisor_url {
            cmd.env("KIN_SUPERVISOR_URL", supervisor_url);
        }
        carry_operator_auto_embed(&mut cmd, std::env::var_os(DAEMON_AUTO_EMBED_ENV));
        detach_from_caller(&mut cmd);
        cmd
    }
}

/// Pin the operator's background-embedding opt-out onto a daemon spawn.
///
/// `value` is the spawning command's own setting, or `None` when it set none.
/// An unset variable pins nothing: the daemon's default is on, and inventing a
/// value here would turn "the operator said nothing" into "the operator said
/// yes", which reads identically in the child and is not the same statement.
///
/// Pinning a set value is not redundant with inheritance. It states the
/// carriage at the boundary, so a later addition to the ambient-authority
/// denylist, or a caller that rebuilds the child environment instead of
/// inheriting it, cannot drop an operator's opt-out silently — the failure mode
/// the daemon has no way to report, because a dropped opt-out is
/// indistinguishable from one that was never set.
fn carry_operator_auto_embed(cmd: &mut Command, value: Option<std::ffi::OsString>) {
    if let Some(value) = value {
        cmd.env(DAEMON_AUTO_EMBED_ENV, value);
    }
}

/// Cut the daemon loose from the caller so it outlives the process that started
/// it and takes none of that process's session with it.
///
/// Unix reads that as the signal side: `setsid` puts the daemon in its own
/// session, where the caller's terminal signals cannot reach it, and the file
/// descriptors it does not need are already gone because Rust opens everything
/// `CLOEXEC`.
///
/// Windows has no `CLOEXEC`, so the same sentence has to be enforced on the
/// handle side instead; see [`release_caller_standard_handles`].
///
/// A test runtime is the one exception on the signal side. Its guardian puts
/// the invoking process in a stable process group and passes both an owner
/// capability and the exact group id. Keeping the daemon in that verified group
/// lets the harness reap the complete process tree even if graceful product
/// cleanup fails. The owner marker alone is never sufficient: a missing,
/// malformed, non-positive, or mismatched group keeps normal production
/// detachment enabled.
pub fn detach_from_caller(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        if should_detach_from_caller() {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() == -1 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = cmd;
        release_caller_standard_handles();
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = cmd;
    }
}

/// Stop a spawned daemon from holding the caller's standard handles open.
///
/// `CreateProcess` hands a child every handle currently marked inheritable, not
/// only the three the parent chose for its stdio. A handle the caller itself
/// inherited keeps that mark, so a shell pipeline's write end reaches the daemon
/// even though the daemon's own stdout and stderr were redirected into the
/// daemon log. Nothing in the daemon knows it holds that handle, so it stays
/// open for the daemon's whole life and the reader on the far side never sees
/// end of file: `kin search --json | jq` prints its answer and then hangs until
/// the daemon idles out, and whatever runs next in that shell observes a daemon
/// that has just retired its endpoint rather than the live one that served the
/// query.
///
/// Clearing the inherit flag on this process's standard handles is the
/// equivalent of the `CLOEXEC` Unix gets for free. It does not affect stdio the
/// caller assigns to a child, because `std::process` duplicates whatever handle
/// a `Stdio` names into a fresh inheritable one for the child rather than
/// passing this flag through, and it does not affect this process's own use of
/// its handles, which is why it is safe to do once and leave done.
#[cfg(windows)]
fn release_caller_standard_handles() {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };

    let standard = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for handle in standard {
        // A process started without a console reports its standard handles as
        // null or as the invalid sentinel. Neither names anything a child could
        // inherit, and asking the kernel about them only produces an error to
        // discard.
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // Nothing here can be repaired by a caller: the flag is either cleared
        // or the handle was never inheritable in the first place.
        unsafe {
            let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

#[cfg(unix)]
fn should_detach_from_caller() -> bool {
    let owner = std::env::var_os(TEST_RUNTIME_OWNER_ENV);
    let declared_group = std::env::var_os(TEST_RUNTIME_PROCESS_GROUP_ENV);
    should_detach_from_caller_for(owner.as_deref(), declared_group.as_deref(), unsafe {
        libc::getpgrp()
    })
}

#[cfg(unix)]
fn should_detach_from_caller_for(
    owner: Option<&std::ffi::OsStr>,
    declared_group: Option<&std::ffi::OsStr>,
    actual_group: libc::pid_t,
) -> bool {
    let has_owner = owner.is_some_and(|value| !value.is_empty());
    let declared_group = declared_group
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|group| *group > 0);
    !(has_owner && actual_group > 0 && declared_group == Some(actual_group))
}

/// Resolve the idle timeout to inject, honouring an explicit user setting.
///
/// The user's environment always wins: returning `None` leaves whatever they
/// exported in place rather than overwriting it with a path default.
pub fn resolve_idle_timeout(
    user_env_is_set: bool,
    requested: Option<&'static str>,
) -> Option<&'static str> {
    if user_env_is_set {
        return None;
    }
    requested
}

// ── Port handshake ──────────────────────────────────────────────────────

/// Read the port the daemon reported, if it has published one yet.
pub fn read_reported_port(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join(PORT_FILE_NAME))
        .ok()
        .and_then(|content| content.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
}

/// Why waiting for the daemon's port ended without one.
///
/// Every variant is a refusal to guess. There is no variant carrying a fallback
/// port, because a spawn that cannot learn the real port has nothing to talk
/// to: binding a default would address whatever else happens to be listening
/// there, which is worse than failing.
#[derive(Debug)]
pub enum PortWaitError {
    /// The child exited before publishing a port.
    ChildExited(String),
    /// The deadline elapsed while the child was still alive. Not evidence of
    /// anything except slowness, so the child is left running.
    StillStarting,
    /// The child could not be inspected at all.
    Unwatchable(std::io::Error),
}

impl std::fmt::Display for PortWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChildExited(status) => {
                write!(f, "daemon exited during startup with status {status}")
            }
            Self::StillStarting => write!(
                f,
                "daemon is still starting and has not reported a port yet; it was left running \
                 rather than killed. Wait for it, or stop it with `kin daemon stop`"
            ),
            Self::Unwatchable(error) => write!(f, "cannot observe the daemon process: {error}"),
        }
    }
}

impl std::error::Error for PortWaitError {}

/// Poll the port file until the daemon publishes its bound port.
///
/// Returns the port only when the daemon itself reported one. Reaching the
/// deadline yields [`PortWaitError::StillStarting`] and leaves the child alive:
/// see [`StartupDisposition`] for why a deadline is not evidence of death.
pub async fn await_reported_port(
    kin_root: &Path,
    child: &mut std::process::Child,
    deadline: tokio::time::Instant,
) -> Result<u16, PortWaitError> {
    loop {
        match startup_disposition(child) {
            Ok(StartupDisposition::Exited(status)) => {
                return Err(PortWaitError::ChildExited(status));
            }
            Ok(_) => {}
            Err(error) => return Err(PortWaitError::Unwatchable(error)),
        }

        if let Some(port) = read_reported_port(kin_root) {
            return Ok(port);
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(PortWaitError::StillStarting);
        }
        tokio::time::sleep(PORT_POLL_INTERVAL).await;
    }
}

// ── Startup child disposition ───────────────────────────────────────────

/// What can be established about a daemon we started but that is not serving
/// yet.
///
/// The distinction is the same one endpoint probing settled on: a daemon that
/// has not answered yet is alive, and only a daemon proven gone may be treated
/// as dead. A startup deadline measures the caller's patience, not the child's
/// health, so it appears in none of these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupDisposition {
    /// The child is gone and its status is known.
    Exited(String),
    /// The child is running and simply has not finished starting.
    Alive,
    /// Liveness could not be established. Treated as alive: an unreadable
    /// process is not a dead one.
    Indeterminate,
}

impl StartupDisposition {
    /// Whether this disposition authorizes terminating the child.
    ///
    /// Only a child already gone qualifies, which makes termination a reap
    /// rather than a kill. This is the whole point: a live-but-slow daemon
    /// holds the repo singleton and has done real warm-up work, so killing it
    /// on a timer throws that away and guarantees its replacement starts from
    /// cold and hits the same deadline.
    pub fn authorizes_termination(&self) -> bool {
        matches!(self, Self::Exited(_))
    }
}

/// Classify a child we started.
pub fn startup_disposition(child: &mut std::process::Child) -> std::io::Result<StartupDisposition> {
    if let Some(status) = child.try_wait()? {
        return Ok(StartupDisposition::Exited(status.to_string()));
    }
    Ok(match process_liveness(child.id()) {
        Liveness::Dead => StartupDisposition::Exited("unknown (process is gone)".to_string()),
        Liveness::Alive => StartupDisposition::Alive,
        Liveness::Unknown => StartupDisposition::Indeterminate,
    })
}

/// Terminate a startup child, but only when its disposition proves it is
/// already gone.
///
/// Returns whether anything was terminated, so callers can report honestly.
pub fn terminate_if_proven_dead(
    child: &mut std::process::Child,
    disposition: &StartupDisposition,
) -> bool {
    if !disposition.authorizes_termination() {
        return false;
    }
    let _ = child.kill();
    let _ = child.wait();
    true
}

/// How often the detached-daemon reaper asks whether an adopted child has
/// exited. Cheap: `try_wait` is one `waitpid(WNOHANG)` per adopted handle.
const DETACHED_DAEMON_REAP_POLL: Duration = Duration::from_millis(250);

/// Hand a started, detached daemon to a reaper that waits on it.
///
/// Every spawn path here calls `setsid`, and every spawn path then relies on
/// the launcher exiting: once it does the daemon reparents to init, and init
/// waits on it. `setsid` starts a new session and process group and does not
/// change the parent pid, so the arrangement only holds while the launcher is
/// short-lived. Under a launcher that outlives the daemon it does not hold at
/// all, and dropping a [`std::process::Child`] waits on nothing, so the daemon
/// stays in the process table as `[kin-daemon] <defunct>` from the moment it
/// dies until the launcher does.
///
/// That launcher exists: `kin mcp start` runs for a whole agent session and
/// reaches a daemon spawn on startup binding, on every workspace rebind, and on
/// every tool call that revives one, while the supervisor's reaper and redeploy
/// paths end daemons underneath it. Six corpses accumulated in one brownfield
/// session that way.
///
/// Adoption transfers the handle to a named background thread that polls it to
/// completion. It never signals the child, because the caller has no evidence
/// the daemon should stop: this collects an exit status and nothing else.
/// Failing to start the thread is not fatal — the handle is dropped, which is
/// exactly the behavior every caller had before.
pub fn adopt_detached_daemon_child(child: std::process::Child) {
    let Some(reaper) = detached_daemon_reaper() else {
        return;
    };
    let _ = reaper.send(child);
}

/// The process-wide sender for [`adopt_detached_daemon_child`], started on first
/// use. `None` once thread creation has failed, so a failed start is not retried
/// per spawn.
fn detached_daemon_reaper() -> Option<std::sync::mpsc::Sender<std::process::Child>> {
    static REAPER: OnceLock<Option<std::sync::mpsc::Sender<std::process::Child>>> = OnceLock::new();
    REAPER
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::channel::<std::process::Child>();
            std::thread::Builder::new()
                .name("kin-detached-daemon-reaper".to_string())
                .spawn(move || detached_daemon_reaper_loop(receiver))
                .ok()
                .map(|_handle| sender)
        })
        .clone()
}

/// Poll every adopted child until it is reaped.
///
/// A handle is retired on `Ok(Some(status))` (the child was waited on here) and
/// on `Err(_)` (nobody can wait on it any more, most often because something
/// else already did). `Ok(None)` means still running, which for a healthy daemon
/// is the case for as long as it serves.
fn detached_daemon_reaper_loop(receiver: std::sync::mpsc::Receiver<std::process::Child>) {
    let mut adopted: Vec<std::process::Child> = Vec::new();
    loop {
        match receiver.recv_timeout(DETACHED_DAEMON_REAP_POLL) {
            Ok(child) => adopted.push(child),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if adopted.is_empty() => return,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        }
        while let Ok(child) = receiver.try_recv() {
            adopted.push(child);
        }
        adopted.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
    }
}

/// Coarse process liveness, fail-closed on anything indeterminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Liveness {
    Alive,
    Dead,
    Unknown,
}

fn process_liveness(pid: u32) -> Liveness {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return Liveness::Dead;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return Liveness::Alive;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Liveness::Dead,
            _ => Liveness::Unknown,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Liveness::Unknown
    }
}

/// Whether the daemon recorded for `kin_root` is provably still running.
///
/// [`startup_disposition`] answers this with `Child::try_wait`, which only the
/// process that spawned the daemon can call. A client that *attached* to a
/// daemon it did not start asks the same question and holds none of that
/// evidence, so it reads the record the daemon publishes about itself.
///
/// Deliberately one-directional: `true` is positive proof of life, and every
/// other outcome — no record, an unreadable record, a PID the OS will not
/// classify — is merely the absence of proof, never proof of death. Callers use
/// it to withhold destruction, never to authorize it, which is the same
/// direction [`StartupDisposition::authorizes_termination`] runs in.
pub fn recorded_owner_is_alive(kin_root: &Path) -> bool {
    let Some(pid) = std::fs::read_to_string(kin_root.join(PID_FILE_NAME))
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
    else {
        return false;
    };
    matches!(process_liveness(pid), Liveness::Alive)
}

// ── Stale endpoint records ──────────────────────────────────────────────

/// Whether a port record is orphaned: a port with no PID owner beside it.
///
/// A port file alone names an endpoint nobody is accountable for. A port file
/// *with* a PID file may belong to a daemon that is still publishing its
/// endpoint, and clearing that strands the repo, so both spawn paths clear only
/// the orphaned shape.
pub fn port_record_is_orphaned(kin_root: &Path) -> bool {
    kin_root.join(PORT_FILE_NAME).exists() && !kin_root.join(PID_FILE_NAME).exists()
}

/// File the daemon writes its publishing incarnation into beside the endpoint.
///
/// Read by nothing here; named so this repair retires it with the endpoint it
/// attributes, rather than leaving an attribution behind for a record that no
/// longer exists.
pub const OWNER_FILE_NAME: &str = "daemon.owner";

/// Clear an orphaned port record so a fresh spawn is not read against a dead
/// predecessor's port. Returns whether anything was removed.
pub fn clear_orphaned_port_record(kin_root: &Path) -> bool {
    if !port_record_is_orphaned(kin_root) {
        return false;
    }
    // The PID file is already gone, so the sidecar attributes nothing. Retire
    // it with the port rather than leaving the two repair surfaces disagreeing
    // about what an endpoint is made of.
    let _ = std::fs::remove_file(kin_root.join(OWNER_FILE_NAME));
    match std::fs::remove_file(kin_root.join(PORT_FILE_NAME)) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            tracing::warn!(
                kin_root = %kin_root.display(),
                %error,
                "could not clear an orphaned daemon port record"
            );
            false
        }
    }
}

// ── Supervisor registration seam ────────────────────────────────────────

/// Registers a freshly started daemon with the process supervisor.
///
/// Supervisor registration lives in `kin-cli`, which `kin-mcp` cannot call.
/// Rather than let the MCP path go on skipping registration — leaving revived
/// daemons invisible to the supervisor's routing table — `kin-cli` installs its
/// implementation here and both spawn paths reach it through this seam.
pub trait DaemonSpawnRegistrar: Send + Sync {
    /// The supervisor endpoint a daemon about to be spawned should be told
    /// about, starting the supervisor if it is not already up.
    ///
    /// Spawning without this leaves the daemon unable to reach its supervisor
    /// even after registration succeeds, so both paths resolve it before
    /// building their spawn plan.
    fn supervisor_url(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>;

    /// Register `daemon_url` as the daemon serving `kin_root`.
    fn register(
        &self,
        kin_root: PathBuf,
        daemon_url: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

    /// The endpoint of a daemon that is **already** serving `kin_root`, or
    /// `None` when none is. Starts nothing.
    ///
    /// This is the same resolution `kin doctor` reports its daemon-reachability
    /// verdict from, exposed here so a process that cannot depend on the CLI
    /// asks the identical question. Two surfaces answering "is the daemon
    /// reachable" from two different resolutions is how `kin doctor` came to
    /// report a healthy daemon at the same instant every MCP tool call reported
    /// it unavailable: the CLI resolved the route at call time while MCP read a
    /// URL resolved once at startup.
    fn route_if_running(
        &self,
        kin_root: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>;
}

/// Resolve the supervisor endpoint through the installed seam, if there is one.
pub async fn supervisor_url_for_spawn() -> Option<String> {
    let registrar = registrar()?;
    registrar.supervisor_url().await
}

/// The endpoint of a daemon already serving `kin_root`, resolved through the
/// installed seam without starting anything.
///
/// `None` covers both "no daemon serves this repository" and "no seam is
/// installed in this process", which are the same thing to a caller: it has no
/// route to a daemon and must not invent one.
pub async fn running_daemon_route(kin_root: &Path) -> Option<String> {
    let registrar = registrar()?;
    registrar.route_if_running(kin_root.to_path_buf()).await
}

static REGISTRAR: OnceLock<Arc<dyn DaemonSpawnRegistrar>> = OnceLock::new();

/// Install the process-wide registrar. Returns whether this call installed it;
/// a second call leaves the first in place.
pub fn install_registrar(registrar: Arc<dyn DaemonSpawnRegistrar>) -> bool {
    REGISTRAR.set(registrar).is_ok()
}

/// The installed registrar, if any.
pub fn registrar() -> Option<Arc<dyn DaemonSpawnRegistrar>> {
    REGISTRAR.get().cloned()
}

/// Register a started daemon with the supervisor through the installed seam.
///
/// A missing registrar is reported rather than passed over: it means this
/// process started a daemon the supervisor will not know about, which is the
/// exact gap that made revived MCP daemons unroutable.
pub async fn register_started_daemon(kin_root: &Path, daemon_url: &str) -> Result<(), String> {
    let Some(registrar) = registrar() else {
        tracing::warn!(
            kin_root = %kin_root.display(),
            daemon_url,
            "started a daemon with no supervisor registrar installed; it will not appear in \
             supervisor routing"
        );
        return Err("no supervisor registrar is installed in this process".to_string());
    };
    registrar
        .register(kin_root.to_path_buf(), daemon_url.to_string())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are intentionally cross-platform. The permanent native-Windows
    // authority leg selects this name prefix so Windows proves the same
    // shared/exclusive lease and retired-root contract as Unix.
    #[test]
    fn managed_spawn_fence_blocks_exclusive_uninstall_authority_until_release() {
        use std::sync::mpsc;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(".kin");
        fs::create_dir_all(root.join("bin")).unwrap();
        let daemon = root.join("bin/kin-daemon");
        fs::write(&daemon, b"managed daemon fixture").unwrap();

        let fence = ManagedInstallSpawnFence::acquire(&daemon, &root)
            .unwrap()
            .expect("managed binary must acquire install admission");
        let lock_path = root.join("update.lock");
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(lock_path)
                .unwrap();
            FileExt::lock_exclusive(&file).unwrap();
            acquired_tx.send(()).unwrap();
            file
        });

        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "exclusive uninstall lease passed a live managed spawn"
        );
        drop(fence);
        acquired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("exclusive uninstall lease did not proceed after readiness release");
        drop(waiter.join().unwrap());
    }

    #[test]
    fn managed_spawn_fence_rejects_binary_resolved_inside_retired_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(".kin");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/kin-daemon"), b"managed daemon fixture").unwrap();
        let retired = tmp
            .path()
            .join(".kin-uninstall-retired-00000000-0000-4000-8000-000000000001");
        fs::rename(&root, &retired).unwrap();

        let error = ManagedInstallSpawnFence::acquire(&retired.join("bin/kin-daemon"), &root)
            .err()
            .expect("retired managed executable must never regain spawn admission");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("retired uninstall state"));
    }

    /// The four `fs::Metadata` fields the pre-fix Windows arm of
    /// `same_file_object` compared, rendered for a CI log.
    fn root_field_probe(root: &Path) -> String {
        match fs::symlink_metadata(root) {
            Ok(metadata) => format!(
                "is_dir={} len={} modified={:?} created={:?}",
                metadata.file_type().is_dir(),
                metadata.len(),
                metadata.modified().ok(),
                metadata.created().ok()
            ),
            Err(error) => format!("unreadable: {error}"),
        }
    }

    fn managed_fixture(dir: &Path, precreate_lock: bool) -> (PathBuf, PathBuf) {
        let root = dir.join(".kin");
        fs::create_dir_all(root.join("bin")).unwrap();
        let daemon = root.join("bin/kin-daemon");
        fs::write(&daemon, b"managed daemon fixture").unwrap();
        if precreate_lock {
            fs::write(root.join("update.lock"), b"").unwrap();
        }
        (daemon, root)
    }

    /// Admission must not depend on whether `update.lock` already exists.
    ///
    /// The two cases are the first spawn against a fresh install and every spawn
    /// after it. They differ only in that the first one creates a directory entry
    /// inside the root while admission is in flight, which is the install working
    /// as intended and must not read as the root being swapped underneath it.
    #[test]
    fn managed_spawn_fence_admits_whether_or_not_the_lock_already_exists() {
        for precreate_lock in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (daemon, root) = managed_fixture(tmp.path(), precreate_lock);
            // The four fields the pre-fix Windows predicate compared, read on
            // either side of admission. This host's answer is not the runner's:
            // on a native Windows 11 host none of them move when the lock is
            // created inside the root, while `windows-latest` refused the same
            // admission twelve consecutive times. Emitted so the next refusal
            // names the field that diverged instead of only the guard that
            // fired. Captured output surfaces when this test fails, which is
            // exactly the case it exists for.
            eprintln!(
                "FENCE_ROOT_FIELDS: precreate_lock={precreate_lock} at=snapshot {}",
                root_field_probe(&root)
            );
            let fence = ManagedInstallSpawnFence::acquire(&daemon, &root);
            eprintln!(
                "FENCE_ROOT_FIELDS: precreate_lock={precreate_lock} at=recheck {}",
                root_field_probe(&root)
            );
            let outcome = match &fence {
                Ok(Some(_)) => "admitted".to_string(),
                Ok(None) => "not treated as a managed install".to_string(),
                Err(error) => format!("refused with {error}"),
            };
            assert!(
                matches!(fence, Ok(Some(_))),
                "managed binary must acquire install admission with \
                 precreate_lock={precreate_lock}; got {outcome}"
            );
        }
    }

    /// The negative control for the Windows root check, at the predicate level.
    ///
    /// Both green arms above pass equally well against a guard that has stopped
    /// guarding, so on their own they cannot tell "no longer trips falsely" from
    /// "no longer trips at all". This pins that the comparison the guard performs
    /// can still distinguish: a fresh open of the SAME directory agrees with the
    /// held handle, and a DIFFERENT directory does not.
    ///
    /// The end-to-end arm this stands in for -- re-pointing the root path to
    /// another directory between admission and re-check -- is not expressible
    /// portably here, because that window lives inside `acquire`. This is the
    /// strongest statement available without instrumenting the function.
    #[cfg(windows)]
    #[test]
    fn managed_spawn_fence_windows_root_identity_distinguishes_a_swapped_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let admitted = tmp.path().join("admitted");
        let impostor = tmp.path().join("impostor");
        fs::create_dir_all(&admitted).unwrap();
        fs::create_dir_all(&impostor).unwrap();

        let held = open_windows_root_guard(&admitted).unwrap();
        let fresh_same = open_windows_root_guard(&admitted).unwrap();
        let fresh_other = open_windows_root_guard(&impostor).unwrap();

        assert_eq!(
            windows_file_identity(&held).unwrap().0,
            windows_file_identity(&fresh_same).unwrap().0,
            "a fresh open of the admitted root must agree with the held handle, \
             or the guard would refuse every legitimate admission"
        );
        assert_ne!(
            windows_file_identity(&held).unwrap().0,
            windows_file_identity(&fresh_other).unwrap().0,
            "a different directory must not compare equal to the admitted root, \
             or the guard would admit a swapped install"
        );
    }

    // ── Process-group containment ─────────────────────────────────────────
    //
    // The failure these close: containment was decided by kill(-pgid, 0), which
    // reports a group non-empty while it holds a process that has exited and
    // not yet been waited. A grandchild that outlives its parent is reparented
    // to init, and init clears that slot on its own schedule, so a cleanup that
    // had genuinely killed everything reported failure whenever the machine was
    // busy enough to widen that window.
    //
    // These drive the states directly rather than racing for them, and each one
    // asserts the old probe's answer alongside the new one, so the arrangement
    // that used to fail is pinned rather than described.

    /// Spawn a command in a process group of its own, so the test owns a group
    /// whose identity is the child's PID.
    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    fn spawn_in_own_group(program: &str, args: &[&str]) -> std::process::Child {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new(program);
        command.args(args);
        command.process_group(0);
        command.spawn().expect("spawn a group leader")
    }

    /// Whether the pre-fix probe would call this group occupied.
    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    fn legacy_group_probe_reports_occupied(process_group: libc::pid_t) -> bool {
        let probe = unsafe { libc::kill(-process_group, 0) };
        !(probe == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
    }

    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_member_that_exited_without_being_waited_is_contained() {
        // Exactly the arrangement that failed: the group's only member has run
        // to completion, and nobody has collected it yet.
        let mut child = spawn_in_own_group("true", &[]);
        let pgid = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if process_has_exited(pgid).expect("classify the member") {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            process_has_exited(pgid).expect("classify the member"),
            "the member must have exited before the containment claim is meaningful"
        );
        assert!(
            legacy_group_probe_reports_occupied(pgid),
            "this test is only meaningful while the group still looks occupied to kill(-pgid, 0)"
        );

        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::OnlyExited,
            "a group holding nothing but an uncollected corpse is contained"
        );

        child.wait().expect("collect the member");
    }

    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_member_that_is_still_running_is_not_contained() {
        // The inverse, so the fix cannot degenerate into always reporting
        // containment.
        let mut child = spawn_in_own_group("sleep", &["30"]);
        let pgid = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");

        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::LiveMember { pid: pgid },
            "a running member must be reported, and named"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn finalization_settle_outwaits_a_member_the_kill_has_not_yet_torn_down() {
        // The merge-queue shape: the barrier's SIGKILL is delivered, the member
        // has not yet been retired by the kernel, and finalization begins. The
        // settle must keep reading until the member stops being live instead of
        // judging the transient.
        let mut child = spawn_in_own_group("sleep", &["30"]);
        let pgid = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");
        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::LiveMember { pid: pgid },
            "the member must still be live when the settle begins"
        );

        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            unsafe { libc::kill(pgid, libc::SIGKILL) };
        });
        settle_pinned_group_member_exits(pgid, std::time::Instant::now() + Duration::from_secs(10));
        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::OnlyExited,
            "the settle returned while its member could still run"
        );

        killer.join().expect("join the killer thread");
        child.wait().expect("collect the member");
    }

    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn finalization_settle_stays_bounded_and_leaves_a_live_member_reported() {
        // The inverse: a member nothing killed must not be settled away. The
        // wait uses its whole bound, returns, and leaves the live member for
        // the post-reap probe to report, so failing loud still works.
        let mut child = spawn_in_own_group("sleep", &["30"]);
        let pgid = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");

        let bound = Duration::from_millis(200);
        let began = std::time::Instant::now();
        settle_pinned_group_member_exits(pgid, began + bound);
        let waited = began.elapsed();
        assert!(
            waited >= bound,
            "the settle gave up on a live member after {waited:?}, before its {bound:?} bound"
        );
        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::LiveMember { pid: pgid },
            "a member that never exits must stay reported for the probe to judge"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_group_whose_members_are_all_collected_is_empty() {
        let mut child = spawn_in_own_group("true", &[]);
        let pgid = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");
        child.wait().expect("collect the member");

        assert!(
            !legacy_group_probe_reports_occupied(pgid),
            "a collected member leaves no group behind"
        );
        assert_eq!(
            process_group_containment(pgid),
            ProcessGroupContainment::Empty
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_parsing_survives_a_process_name_containing_spaces_and_parens() {
        // Splitting the whole line would mis-count every field after the name.
        let stat = "42 (weird ) name) Z 7 99 0 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100";
        assert_eq!(parse_proc_stat_state(stat), Some('Z'));
        assert_eq!(parse_proc_stat_process_group(stat), Some(99));
    }

    #[cfg(unix)]
    const INERT_GROUP_MEMBER_ENV: &str = "KIN_INTERNAL_TEST_INERT_GROUP_MEMBER";

    #[cfg(unix)]
    const ESCAPE_GROUP_ENV: &str = "KIN_INTERNAL_TEST_ESCAPE_GROUP";

    #[cfg(unix)]
    const OWNER_DEATH_DRIVER_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_OWNER_DEATH_DRIVER";

    #[cfg(unix)]
    const OWNER_DEATH_REPORT_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_OWNER_DEATH_REPORT";

    #[cfg(unix)]
    const LATE_RELAY_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_LATE_RELAY";

    #[cfg(unix)]
    const LATE_RELAY_TRIGGER_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_LATE_RELAY_TRIGGER";

    #[cfg(unix)]
    const LATE_RELAY_REPORT_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_LATE_RELAY_REPORT";

    #[cfg(unix)]
    const LATE_RELAY_ESCAPE_CHILD_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_LATE_RELAY_ESCAPE_CHILD";

    #[cfg(unix)]
    const PREEXEC_STALL_DRIVER_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_PREEXEC_STALL_DRIVER";

    #[cfg(unix)]
    const PREEXEC_STALL_REPORT_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_PREEXEC_STALL_REPORT";

    #[cfg(unix)]
    const FORK_BOUNDARY_WORKER_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_FORK_BOUNDARY_WORKER";

    #[cfg(unix)]
    const FORK_BOUNDARY_TRIGGER_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_FORK_BOUNDARY_TRIGGER";

    #[cfg(unix)]
    const FORK_BOUNDARY_RACE_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_FORK_BOUNDARY_RACE";

    #[cfg(unix)]
    const FORK_BOUNDARY_REPORT_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_FORK_BOUNDARY_REPORT";

    #[cfg(unix)]
    const FORK_BOUNDARY_SIGNAL_ENV: &str = "KIN_INTERNAL_TEST_GUARDIAN_FORK_BOUNDARY_SIGNAL";

    #[cfg(unix)]
    #[test]
    fn process_group_guardian_worker() {
        let requested = std::env::var_os(PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
        let dispatched = run_process_group_guardian_if_requested()
            .expect("run exact process-group guardian worker");
        assert_eq!(dispatched, requested);
    }

    #[cfg(unix)]
    #[test]
    fn inert_process_group_member_worker() {
        if std::env::var_os(INERT_GROUP_MEMBER_ENV).is_none() {
            return;
        }
        if std::env::var_os(ESCAPE_GROUP_ENV).is_some() {
            assert_ne!(unsafe { libc::setsid() }, -1, "escape target process group");
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn late_group_relay_worker() {
        use std::process::Stdio;

        if std::env::var_os(LATE_RELAY_ENV).is_none() {
            return;
        }
        let trigger =
            PathBuf::from(std::env::var_os(LATE_RELAY_TRIGGER_ENV).expect("late relay trigger"));
        let report =
            PathBuf::from(std::env::var_os(LATE_RELAY_REPORT_ENV).expect("late relay report"));
        wait_for_test_path(&trigger, Duration::from_secs(5));
        let mut child = Command::new(std::env::current_exe().expect("late relay executable"));
        child
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if std::env::var_os(LATE_RELAY_ESCAPE_CHILD_ENV).is_some() {
            child.env(ESCAPE_GROUP_ENV, "1");
        }
        let child = child.spawn().expect("spawn late inherited member");
        let child_id = child.id();
        // This worker is deliberately killed as a process-group member. Moving
        // the handle out of Drop makes that intentional non-wait explicit.
        std::mem::forget(child);
        publish_test_report(&report, format!("{child_id}\n"));
        if std::env::var_os(LATE_RELAY_ESCAPE_CHILD_ENV).is_some() {
            return;
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn guardian_owner_death_driver_worker() {
        use std::process::Stdio;

        if std::env::var_os(OWNER_DEATH_DRIVER_ENV).is_none() {
            return;
        }
        let report_path =
            PathBuf::from(std::env::var_os(OWNER_DEATH_REPORT_ENV).expect("owner-death report"));
        let readiness_path = report_path.with_extension("guardian-ready");
        let executable = std::env::current_exe().expect("resolve owner-death test executable");
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .expect("spawn owner-death process-group guardian");
        let watcher_id = guardian.watcher_id().expect("owned watcher");
        let process_group = guardian.process_group();
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let member = guardian
            .spawn(member_command)
            .expect("spawn owner-death contained member");
        let member_id = member.id();
        // The hard `_exit` below intentionally bypasses Rust cleanup so the
        // watcher, rather than this driver, must reap the containment tree.
        std::mem::forget(member);
        publish_test_report(
            &report_path,
            format!("{watcher_id} {process_group} {member_id}\n"),
        );

        // Do not unwind and do not run `ProcessGroupGuardian::drop`. Exact PPID
        // change (with ownership EOF as a secondary trigger) is under test.
        unsafe {
            libc::_exit(0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn guardian_preexec_stall_driver_worker() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;

        if std::env::var_os(PREEXEC_STALL_DRIVER_ENV).is_none() {
            return;
        }
        let report_path = PathBuf::from(
            std::env::var_os(PREEXEC_STALL_REPORT_ENV).expect("pre-exec stall report"),
        );
        let stalled_path = report_path.with_extension("stalled");
        let readiness_path = report_path.with_extension("guardian-ready");
        let executable = std::env::current_exe().expect("resolve pre-exec stall executable");
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .expect("spawn pre-exec stall guardian");
        publish_test_report(
            &report_path,
            format!(
                "{} {}\n",
                guardian.watcher_id().expect("owned watcher"),
                guardian.process_group()
            ),
        );

        let stalled_path =
            CString::new(stalled_path.as_os_str().as_bytes()).expect("NUL-free stall marker");
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            member_command.pre_exec(move || {
                let fd = libc::open(
                    stalled_path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o600,
                );
                if fd == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let marker = b"stalled\n";
                if libc::write(fd, marker.as_ptr().cast(), marker.len()) == -1 {
                    let error = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(error);
                }
                libc::close(fd);
                loop {
                    libc::pause();
                }
            });
        }

        // This blocks in Command::spawn's exec handshake. The outer test kills
        // this driver after observing the marker from the earlier callback.
        let _ = guardian.spawn(member_command);
        unsafe { libc::_exit(71) };
    }

    #[cfg(unix)]
    #[test]
    fn fork_boundary_worker() {
        if std::env::var_os(FORK_BOUNDARY_WORKER_ENV).is_none() {
            return;
        }
        let trigger = PathBuf::from(
            std::env::var_os(FORK_BOUNDARY_TRIGGER_ENV).expect("fork boundary trigger"),
        );
        let race =
            PathBuf::from(std::env::var_os(FORK_BOUNDARY_RACE_ENV).expect("fork boundary race"));
        let report =
            PathBuf::from(std::env::var_os(FORK_BOUNDARY_REPORT_ENV).expect("fork report"));
        let signal_path =
            PathBuf::from(std::env::var_os(FORK_BOUNDARY_SIGNAL_ENV).expect("fork signal"));
        let signal =
            std::os::unix::net::UnixDatagram::unbound().expect("create fork-boundary signal");
        std::fs::write(&report, b"ready\n").expect("publish fork-boundary readiness");
        wait_for_test_path(&trigger, Duration::from_secs(5));

        let seed_child = unsafe { libc::fork() };
        assert_ne!(seed_child, -1, "seed fork-boundary child");
        if seed_child == 0 {
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        {
            use std::io::Write as _;

            let mut report = std::fs::OpenOptions::new()
                .append(true)
                .open(&report)
                .expect("open fork-boundary report");
            writeln!(report, "{seed_child}\narmed").expect("publish armed fork boundary");
            report.flush().expect("flush armed fork boundary");
        }

        // Spin only inside this short-lived adversarial worker. Once released,
        // stop at the instruction immediately before fork so the parent can
        // resume this process and enter cleanup against the same boundary.
        while !race.exists() {
            std::hint::spin_loop();
        }
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
        assert_eq!(
            signal
                .send_to(&[1], &signal_path)
                .expect("send pre-fork signal"),
            1
        );
        let boundary_child = unsafe { libc::fork() };
        assert_ne!(boundary_child, -1, "cleanup-boundary child");
        if boundary_child > 0 {
            use std::io::Write as _;

            assert_eq!(
                signal
                    .send_to(&[2], &signal_path)
                    .expect("send post-fork signal"),
                1
            );
            let mut report = std::fs::OpenOptions::new()
                .append(true)
                .open(&report)
                .expect("reopen fork-boundary report");
            writeln!(report, "{boundary_child}").expect("publish cleanup-boundary child");
            report.flush().expect("flush cleanup-boundary child");
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn readiness_parser_is_versioned_and_fail_closed() {
        assert_eq!(
            parse_process_group_guardian_readiness("kin-pg-guardian-v1 41 42\n").unwrap(),
            ProcessGroupGuardianReadiness {
                watcher_pid: 41,
                process_group: 42,
            }
        );
        for malformed in [
            "",
            "41 42",
            "kin-pg-guardian-v2 41 42",
            "kin-pg-guardian-v1 0 42",
            "kin-pg-guardian-v1 41 -42",
            "kin-pg-guardian-v1 42 42",
            "kin-pg-guardian-v1 41 42 trailing",
        ] {
            assert!(
                parse_process_group_guardian_readiness(malformed).is_err(),
                "{malformed:?} bypassed readiness validation"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_trigger_parser_is_typed_and_fail_closed() {
        assert_eq!(
            ProcessGroupCleanupTrigger::parse(
                ProcessGroupCleanupTrigger::ParentBarrierComplete as u8
            )
            .unwrap(),
            ProcessGroupCleanupTrigger::ParentBarrierComplete
        );
        assert_eq!(
            ProcessGroupCleanupTrigger::parse(
                ProcessGroupCleanupTrigger::WatcherBarrierRequired as u8
            )
            .unwrap(),
            ProcessGroupCleanupTrigger::WatcherBarrierRequired
        );
        for unknown in [0, 3, u8::MAX] {
            let error = ProcessGroupCleanupTrigger::parse(unknown)
                .expect_err("unknown cleanup trigger must fail closed");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_spawn_consumes_command_without_poisoning_next_admission() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();

        let missing = Command::new(root.path().join("definitely-not-an-executable"));
        assert_eq!(
            guardian.spawn(missing).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );

        let mut fresh = Command::new(executable);
        fresh
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn(fresh).unwrap();
        guardian.request_cleanup();
        let status = member.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owner_sigkill_during_earlier_preexec_stall_cleans_the_group() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let report_path = root.path().join("preexec-stall.report");
        let stalled_path = report_path.with_extension("stalled");
        let executable = std::env::current_exe().unwrap();
        let mut driver = Command::new(executable);
        driver
            .args([
                "--exact",
                "tests::guardian_preexec_stall_driver_worker",
                "--nocapture",
            ])
            .env(PREEXEC_STALL_DRIVER_ENV, "1")
            .env(PREEXEC_STALL_REPORT_ENV, &report_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut driver = driver.spawn().unwrap();
        // Both fields, not merely the file: a partially written report reads
        // back short and the parse below would fail on a loaded host.
        let ids = wait_for_test_report_fields(&report_path, 2, Duration::from_secs(5))
            .iter()
            .map(|value| value.parse::<libc::pid_t>().unwrap())
            .collect::<Vec<_>>();
        wait_for_test_path(&stalled_path, Duration::from_secs(5));
        assert_eq!(ids.len(), 2, "malformed pre-exec stall report");

        driver.kill().unwrap();
        let status = driver.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        wait_for_test_pid_gone(ids[0], Duration::from_secs(5));
        wait_for_test_process_group_gone(ids[1], Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn watcher_death_during_cleanup_request_cannot_skip_parent_barrier() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        )
        .with_cleanup_timeout(Duration::from_millis(100));
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let watcher_pid = libc::pid_t::try_from(guardian.watcher_id().unwrap()).unwrap();
        let sentinel_pid = guardian.process_group();
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn(member_command).unwrap();

        // Freeze the watcher so it cannot win the race by completing normally,
        // then release its SIGKILL concurrently with the explicit request. No
        // sleep or preliminary try_wait makes its death observable first.
        assert_eq!(unsafe { libc::kill(watcher_pid, libc::SIGSTOP) }, 0);
        let race = std::sync::Arc::new(std::sync::Barrier::new(2));
        let killer_race = std::sync::Arc::clone(&race);
        let killer = std::thread::spawn(move || {
            killer_race.wait();
            unsafe { libc::kill(watcher_pid, libc::SIGKILL) }
        });
        race.wait();
        guardian.request_cleanup();
        assert_eq!(killer.join().unwrap(), 0);
        let member_status = member.wait().unwrap();
        assert_eq!(member_status.signal(), Some(libc::SIGKILL));
        let error = guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .expect_err("killed watcher must remain a reported cleanup failure");
        assert!(error.to_string().contains("watcher cleanup failed"));
        wait_for_test_pid_gone(sentinel_pid, Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn stopped_watcher_and_sentinel_reach_terminal_reaper_deadline() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        )
        .with_cleanup_timeout(Duration::from_millis(50));
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let watcher_pid = libc::pid_t::try_from(guardian.watcher_id().unwrap()).unwrap();
        let sentinel_pid = guardian.process_group();
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn(member_command).unwrap();

        assert_eq!(unsafe { libc::kill(watcher_pid, libc::SIGSTOP) }, 0);
        drop(guardian);
        let member_status = member.wait().unwrap();
        assert_eq!(member_status.signal(), Some(libc::SIGKILL));
        wait_for_test_pid_gone(watcher_pid, Duration::from_secs(5));
        wait_for_test_pid_gone(sentinel_pid, Duration::from_secs(5));
        assert_test_child_reaped(watcher_pid);
        assert_test_child_reaped(sentinel_pid);
    }

    /// A target that enters a second stop is exactly the shape a single
    /// fire-and-forget `SIGCONT` cannot clear, so this pins the property the
    /// fork-boundary handshake depends on: a release is complete only once the
    /// target's own progress proves it is running, not once a signal has been
    /// sent.
    ///
    /// Falsify it by replacing the repeat loop INSIDE [`resume_test_pid_until`]
    /// with a single `kill(SIGCONT)`: the child stays parked at its second stop,
    /// never publishes its marker, and the assertion below fails. That
    /// assertion is deliberately outside the helper, because the closure the
    /// helper takes is its own success condition, and a test whose only
    /// observation lives inside the thing under test cannot fail when that
    /// thing stops working.
    #[cfg(unix)]
    #[test]
    fn resuming_a_stopped_target_clears_every_stop_it_enters() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("resumed");
        // Built before the fork: the child runs between a fork and an `_exit`
        // in a multi-threaded process, where allocating can deadlock against a
        // lock another thread held at fork time.
        let marker_path = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();

        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork resume-probe child");
        if child == 0 {
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::raise(libc::SIGSTOP);
                let fd = libc::open(
                    marker_path.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                    0o600 as libc::c_int,
                );
                if fd < 0 {
                    libc::_exit(1);
                }
                let body = b"resumed\n";
                let written = libc::write(fd, body.as_ptr().cast(), body.len());
                libc::close(fd);
                if written != body.len() as isize {
                    libc::_exit(1);
                }
                // Park rather than exit, matching the worker this helper serves.
                // A target that exits inside the helper's window would have its
                // status collected there instead of by the caller.
                loop {
                    libc::pause();
                }
            }
        }

        // The child's terminal state is `pause()`, so it never exits on its
        // own: if the helper below trips its deadline assert, an unguarded
        // cleanup line would never run and would leave a permanently stopped,
        // reparented child pinning this lane's target directory. The neighbouring
        // multi-process tests take an owner for the same reason.
        let child = StoppedProbeChild(child);

        wait_for_test_pid_stopped(child.0, Duration::from_secs(5));
        resume_test_pid_until(child.0, Duration::from_secs(5), || marker.is_file());
        // Outside the helper on purpose: the closure above is the helper's own
        // success condition, so observing the marker only there would leave this
        // test green if the helper stopped proving anything.
        assert!(
            marker.is_file(),
            "the target must have cleared both stops and published its marker"
        );
    }

    /// Kills and reaps a probe child that cannot terminate on its own, however
    /// the test leaves its scope.
    #[cfg(unix)]
    struct StoppedProbeChild(libc::pid_t);

    #[cfg(unix)]
    impl Drop for StoppedProbeChild {
        fn drop(&mut self) {
            // SIGCONT first: SIGKILL is delivered to a stopped process, but a
            // stopped process that is never continued is not reaped promptly on
            // every platform, and the point of this guard is to leave nothing.
            unsafe {
                libc::kill(self.0, libc::SIGCONT);
                libc::kill(self.0, libc::SIGKILL);
            }
            let mut status = 0;
            unsafe { libc::waitpid(self.0, &mut status, 0) };
        }
    }

    #[cfg(unix)]
    #[test]
    fn stop_barrier_catches_repeated_forks_at_the_cleanup_boundary() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut observed_completed_boundary_forks = 0;
        const ROUNDS: usize = 16;

        for round in 0..ROUNDS {
            let readiness_path = root.path().join(format!("guardian-{round}.ready"));
            let trigger_path = root.path().join(format!("fork-{round}.trigger"));
            let race_path = root.path().join(format!("fork-{round}.race"));
            let report_path = root.path().join(format!("fork-{round}.report"));
            let signal_path = root.path().join(format!("fork-{round}.signal.sock"));
            let fork_boundary_signal =
                std::os::unix::net::UnixDatagram::bind(&signal_path).expect("bind pre-fork signal");
            fork_boundary_signal
                .set_nonblocking(true)
                .expect("make fork-boundary signal nonblocking");
            let launcher = ProcessGroupGuardianLauncher::exact_test(
                &executable,
                "tests::process_group_guardian_worker",
            );
            let mut guardian = launcher
                .spawn_with(
                    &readiness_path,
                    std::time::Instant::now() + Duration::from_secs(5),
                    |_| {},
                )
                .unwrap();
            let mut worker_command = Command::new(&executable);
            worker_command
                .args(["--exact", "tests::fork_boundary_worker", "--nocapture"])
                .env(FORK_BOUNDARY_WORKER_ENV, "1")
                .env(FORK_BOUNDARY_TRIGGER_ENV, &trigger_path)
                .env(FORK_BOUNDARY_RACE_ENV, &race_path)
                .env(FORK_BOUNDARY_REPORT_ENV, &report_path)
                .env(FORK_BOUNDARY_SIGNAL_ENV, &signal_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let worker = guardian.spawn(worker_command).unwrap();
            let mut round_owner = ForkBoundaryRoundOwner::new(guardian, worker);
            let worker_pid = libc::pid_t::try_from(round_owner.worker.id()).unwrap();
            wait_for_test_path(&report_path, Duration::from_secs(5));
            std::fs::write(&trigger_path, b"seed\n").unwrap();
            let armed = wait_for_test_report_fields(&report_path, 3, Duration::from_secs(5));
            assert_eq!(armed[2], "armed");

            // Put the worker at the instruction immediately before its second
            // fork. Byte 1 is the exact pre-fork edge. Even rounds enter the
            // STOP/KILL barrier immediately and preserve the race; odd rounds
            // require byte 2, sent after a successful fork but before PID
            // publication, so completed-fork coverage is deterministic.
            std::fs::write(&race_path, b"fork-at-cleanup\n").unwrap();
            wait_for_test_pid_stopped(worker_pid, Duration::from_secs(5));
            // The signal the worker publishes on the far side of its stop IS the
            // proof it resumed, so release it until that byte arrives rather
            // than releasing once and then blaming the socket for 15s.
            resume_test_pid_until(worker_pid, Duration::from_secs(15), || {
                poll_fork_boundary_signal(&fork_boundary_signal, &mut round_owner.worker, 1)
            });
            if round % 2 == 1 {
                receive_fork_boundary_signal(
                    &fork_boundary_signal,
                    &mut round_owner.worker,
                    2,
                    Duration::from_secs(15),
                );
                observed_completed_boundary_forks += 1;
            }
            round_owner.guardian.request_cleanup();
            let worker_status = round_owner.worker.wait().unwrap();
            assert_eq!(worker_status.signal(), Some(libc::SIGKILL));
            round_owner
                .guardian
                .reap_until(std::time::Instant::now() + Duration::from_secs(5))
                .unwrap();
            round_owner.completed = true;
        }

        assert_eq!(
            observed_completed_boundary_forks,
            ROUNDS / 2,
            "every odd round must prove a completed boundary fork before cleanup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unfinished_fork_boundary_round_reaps_every_owned_process() {
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let watcher_pid = libc::pid_t::try_from(guardian.watcher_id().unwrap()).unwrap();
        let sentinel_pid = guardian.process_group();
        let mut worker_command = Command::new(executable);
        worker_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let worker = guardian.spawn(worker_command).unwrap();
        let worker_pid = libc::pid_t::try_from(worker.id()).unwrap();

        drop(ForkBoundaryRoundOwner::new(guardian, worker));

        for pid in [worker_pid, watcher_pid, sentinel_pid] {
            wait_for_test_pid_gone(pid, Duration::from_secs(5));
            assert_test_child_reaped(pid);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreaped_direct_child_prevents_false_empty_success() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let process_group = guardian.process_group();
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn(member_command).unwrap();

        guardian.request_cleanup();
        // This used to require an error. Blocking success on an uncollected
        // corpse could not survive contact with the grandchild case: a process
        // that outlives its parent is reparented to init, and init clears its
        // slot on a schedule no caller takes part in, so the same state arrived
        // with nobody at fault and cleanup reported failure under load. The
        // barrier is still what has to hold, and it is asserted below: the
        // member was killed, not merely observed.
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .expect("a group holding only an uncollected corpse is contained");
        let member_status = member.wait().unwrap();
        assert_eq!(member_status.signal(), Some(libc::SIGKILL));
        wait_for_test_process_group_gone(process_group, Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn late_forked_member_inherits_group_and_is_killed_by_barrier() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let trigger_path = root.path().join("late-relay.trigger");
        let report_path = root.path().join("late-relay.report");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();

        let mut relay_command = Command::new(executable);
        relay_command
            .args(["--exact", "tests::late_group_relay_worker", "--nocapture"])
            .env(LATE_RELAY_ENV, "1")
            .env(LATE_RELAY_TRIGGER_ENV, &trigger_path)
            .env(LATE_RELAY_REPORT_ENV, &report_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut relay = guardian.spawn(relay_command).unwrap();
        std::fs::write(&trigger_path, b"fork\n").unwrap();
        // Wait for the field, not merely for the file. A report the worker has
        // created but not yet written reads back empty, and on a loaded host the
        // reader wins that race often enough to fail the suite.
        let late_member_pid = wait_for_test_report_fields(&report_path, 1, Duration::from_secs(5))
            [0]
        .parse::<libc::pid_t>()
        .unwrap();

        guardian.request_cleanup();
        let status = relay.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "late-member relay escaped cleanup: {status}"
        );
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .expect("guardian proves the inherited late-member group empty");
        wait_for_test_pid_gone(late_member_pid, Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn deliberate_late_setsid_escape_is_outside_the_guardian_contract() {
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let trigger_path = root.path().join("late-escape.trigger");
        let report_path = root.path().join("late-escape.report");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        )
        .with_cleanup_timeout(Duration::from_millis(150));
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let target_group = guardian.process_group();
        let mut relay_command = Command::new(executable);
        relay_command
            .args(["--exact", "tests::late_group_relay_worker", "--nocapture"])
            .env(LATE_RELAY_ENV, "1")
            .env(LATE_RELAY_TRIGGER_ENV, &trigger_path)
            .env(LATE_RELAY_REPORT_ENV, &report_path)
            .env(LATE_RELAY_ESCAPE_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut relay = guardian.spawn(relay_command).unwrap();
        std::fs::write(&trigger_path, b"fork\n").unwrap();
        // Wait for the field, not merely for the file. A report the worker has
        // created but not yet written reads back empty, and on a loaded host the
        // reader wins that race often enough to fail the suite.
        let late_member_pid = wait_for_test_report_fields(&report_path, 1, Duration::from_secs(5))
            [0]
        .parse::<libc::pid_t>()
        .unwrap();
        assert!(relay.wait().unwrap().success());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while unsafe { libc::getpgid(late_member_pid) } == target_group {
            assert!(
                std::time::Instant::now() < deadline,
                "late inherited member did not escape the target group"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }

        guardian.request_cleanup();
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(2))
            .expect("detached child is explicitly outside the cooperative group contract");
        assert_eq!(unsafe { libc::kill(late_member_pid, 0) }, 0);

        assert_eq!(unsafe { libc::kill(late_member_pid, libc::SIGKILL) }, 0);
        wait_for_test_pid_gone(late_member_pid, Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_drop_synchronously_reaps_the_watcher() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let watcher_pid = libc::pid_t::try_from(guardian.watcher_id().unwrap()).unwrap();
        let mut member_command = Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn(member_command).unwrap();

        guardian.request_cleanup();
        let status = member.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        drop(guardian);

        let mut watcher_status = 0;
        let wait = unsafe { libc::waitpid(watcher_pid, &mut watcher_status, libc::WNOHANG) };
        assert_eq!(wait, -1, "Drop left watcher {watcher_pid} waitable");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "Drop did not reap watcher {watcher_pid}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tokio_spawn_is_atomically_admitted_and_reaped() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let mut member_command = tokio::process::Command::new(executable);
        member_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut member = guardian.spawn_tokio(member_command).unwrap();

        guardian.request_cleanup();
        let status = member.wait().await.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_seals_future_admission() {
        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        guardian.request_cleanup();
        let rejected = Command::new("true");
        let error = guardian.spawn(rejected).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    /// Every WARN and ERROR message a closure emits on this thread.
    ///
    /// A missing log line is invisible to an ordinary assertion, so the quiet
    /// path has to be captured to be checked at all.
    #[derive(Clone, Default)]
    struct CapturedDiagnostics(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl CapturedDiagnostics {
        fn messages(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    impl tracing::field::Visit for CapturedDiagnostics {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.lock().unwrap().push(format!("{value:?}"));
            }
        }
    }

    impl tracing::Subscriber for CapturedDiagnostics {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::WARN
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = self.clone();
            event.record(&mut visitor);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[cfg(unix)]
    #[test]
    fn dropping_a_guardian_its_owner_reaped_reports_no_cleanup_failure() {
        // Every bounded probe reaps its guardian and then drops the handle, so
        // the second finalization attempt is the normal case, not a fault. When
        // Drop warned about it, a single failed daemon start printed one
        // "failed cleanup during Drop" line per probe above the one line saying
        // why the daemon would not start.
        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        );
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        assert!(
            !guardian.finalized,
            "a live guardian has not been finalized yet"
        );
        guardian.request_cleanup();
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(
            guardian.finalized,
            "an explicit reap must record that finalization already happened"
        );
        let repeated = guardian
            .try_reap()
            .expect_err("a guardian finalizes exactly once");
        assert!(
            repeated.to_string().contains("already finalized"),
            "unexpected repeat-finalization error: {repeated}"
        );

        let captured = CapturedDiagnostics::default();
        tracing::subscriber::with_default(captured.clone(), || drop(guardian));
        assert!(
            captured.messages().is_empty(),
            "dropping an already-reaped guardian must stay quiet: {:?}",
            captured.messages()
        );
    }

    #[test]
    fn captured_diagnostics_records_a_warning_it_is_meant_to_catch() {
        // The check above passes when nothing is logged, which is also what it
        // would report if the capture never worked. This is the positive
        // control that proves the capture can see a warning at all.
        let captured = CapturedDiagnostics::default();
        tracing::subscriber::with_default(captured.clone(), || {
            tracing::warn!("process-group guardian reported failed cleanup during Drop");
        });
        assert_eq!(
            captured.messages(),
            vec!["process-group guardian reported failed cleanup during Drop".to_string()],
            "the capture must see a warning emitted inside its scope"
        );
    }

    #[cfg(unix)]
    #[test]
    fn deliberate_direct_setsid_escape_is_outside_the_guardian_contract() {
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let readiness_path = root.path().join("guardian.ready");
        let executable = std::env::current_exe().unwrap();
        let launcher = ProcessGroupGuardianLauncher::exact_test(
            &executable,
            "tests::process_group_guardian_worker",
        )
        .with_cleanup_timeout(Duration::from_millis(150));
        let mut guardian = launcher
            .spawn_with(
                &readiness_path,
                std::time::Instant::now() + Duration::from_secs(5),
                |_| {},
            )
            .unwrap();
        let target_group = guardian.process_group();
        let mut escaped_command = Command::new(executable);
        escaped_command
            .args([
                "--exact",
                "tests::inert_process_group_member_worker",
                "--nocapture",
            ])
            .env(INERT_GROUP_MEMBER_ENV, "1")
            .env(ESCAPE_GROUP_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut escaped = guardian.spawn(escaped_command).unwrap();
        let escaped_pid = libc::pid_t::try_from(escaped.id()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while unsafe { libc::getpgid(escaped_pid) } == target_group {
            assert!(
                std::time::Instant::now() < deadline,
                "escaped worker did not leave the target group"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }

        guardian.request_cleanup();
        guardian
            .reap_until(std::time::Instant::now() + Duration::from_secs(2))
            .expect("detached child is explicitly outside the cooperative group contract");
        assert_eq!(
            unsafe { libc::kill(escaped_pid, 0) },
            0,
            "watcher falsely claimed success by killing an out-of-group member"
        );

        escaped.kill().unwrap();
        escaped.wait().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn kernel_owner_death_eof_leaves_watcher_to_finish_cleanup() {
        use std::process::Stdio;

        let root = tempfile::tempdir().unwrap();
        let report_path = root.path().join("owner-death.report");
        let executable = std::env::current_exe().unwrap();
        let mut driver = Command::new(executable);
        driver
            .args([
                "--exact",
                "tests::guardian_owner_death_driver_worker",
                "--nocapture",
            ])
            .env(OWNER_DEATH_DRIVER_ENV, "1")
            .env(OWNER_DEATH_REPORT_ENV, &report_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut driver = driver.spawn().unwrap();
        let status = driver.wait().unwrap();
        assert!(status.success(), "owner-death driver failed: {status}");
        // All three fields, not merely the file: a partially written report
        // reads back short and the parse below would fail on a loaded host.
        let fields = wait_for_test_report_fields(&report_path, 3, Duration::from_secs(5));
        let pids = fields
            .iter()
            .map(|value| value.parse::<libc::pid_t>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 3, "malformed owner-death report: {fields:?}");

        wait_for_test_pid_gone(pids[0], Duration::from_secs(5));
        wait_for_test_pid_gone(pids[1], Duration::from_secs(5));
        wait_for_test_pid_gone(pids[2], Duration::from_secs(5));
    }

    // A report file is a rendezvous: a worker publishes process ids and the
    // test polls for the path and parses what it finds. `fs::write` creates the
    // file before it writes any bytes, so a poller can observe the path and
    // read an empty file, which surfaces as a parse error on a value the worker
    // did produce. Publish through a temporary sibling and one rename, the same
    // way the guardian publishes its own readiness, so the path appears only
    // once its contents are complete.
    #[cfg(unix)]
    fn publish_test_report(path: &Path, contents: impl AsRef<[u8]>) {
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&temporary, contents).expect("stage test report");
        std::fs::rename(&temporary, path).expect("publish test report");
    }

    #[cfg(unix)]
    fn wait_for_test_path(path: &Path, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while !path.is_file() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn wait_for_test_report_fields(
        path: &Path,
        minimum_fields: usize,
        timeout: Duration,
    ) -> Vec<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(report) = std::fs::read_to_string(path) {
                let fields = report
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if fields.len() >= minimum_fields {
                    return fields;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {minimum_fields} fields in {}",
                path.display()
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn wait_for_test_pid_stopped(pid: libc::pid_t, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut status = 0;
            let result =
                unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
            if result == pid {
                assert!(
                    libc::WIFSTOPPED(status),
                    "process {pid} reached a terminal state before its fork boundary: {status}"
                );
                return;
            }
            if result == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                panic!(
                    "could not observe process {pid} at its fork boundary: {}",
                    std::io::Error::last_os_error()
                );
            }
            assert!(
                std::time::Instant::now() < deadline,
                "process {pid} did not stop at its fork boundary"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    /// Release a process parked at a job-control stop, and keep releasing it
    /// until it proves it is running.
    ///
    /// Every cheap observation available here is a proxy. `waitpid(WUNTRACED)`
    /// reporting a stop says the parent was told a stop happened, not that the
    /// target is parked where exactly one process-directed `SIGCONT` will move
    /// it: `raise(SIGSTOP)` inside a test binary is thread-directed, and on a
    /// contended host the stop can still be settling when that `SIGCONT`
    /// arrives, so it is spent against a stop the target then completes.
    /// `waitpid(WCONTINUED)` is no better, because it reports the continue that
    /// was granted and says nothing about the pending stop that parks the
    /// target again immediately afterwards. Measured on a loaded host, a single
    /// release left the target parked in roughly 3% of rounds, and confirming
    /// that release through `WIFCONTINUED` did not move the rate at all.
    ///
    /// The only trustworthy evidence is the target's own progress, so repeat
    /// the release until `proved_running` observes it. That is the same shape
    /// as the production cleanup barrier in this file, which repeats its signal
    /// rather than trusting one delivery. `SIGCONT` to a process that is
    /// already running carries no handler and is discarded, so repeating costs
    /// nothing and cannot disturb a target that already resumed.
    #[cfg(unix)]
    fn resume_test_pid_until(
        pid: libc::pid_t,
        timeout: Duration,
        mut proved_running: impl FnMut() -> bool,
    ) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if proved_running() {
                return;
            }
            assert_eq!(
                unsafe { libc::kill(pid, libc::SIGCONT) },
                0,
                "could not continue process {pid}: {}",
                std::io::Error::last_os_error()
            );
            if proved_running() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "process {pid} did not resume from its stop"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    struct ForkBoundaryRoundOwner {
        guardian: ProcessGroupGuardian,
        worker: std::process::Child,
        completed: bool,
    }

    #[cfg(unix)]
    impl ForkBoundaryRoundOwner {
        fn new(guardian: ProcessGroupGuardian, worker: std::process::Child) -> Self {
            Self {
                guardian,
                worker,
                completed: false,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for ForkBoundaryRoundOwner {
        fn drop(&mut self) {
            if self.completed {
                return;
            }
            self.guardian.request_cleanup();
            let _ = self.worker.kill();
            let _ = self.worker.wait();
            let _ = self
                .guardian
                .reap_until(std::time::Instant::now() + Duration::from_secs(5));
        }
    }

    /// One non-blocking attempt at the fork-boundary signal.
    ///
    /// `true` means the expected byte arrived. `false` means nothing was queued
    /// yet and the worker is still alive to publish it. Everything else is a
    /// protocol violation and panics here rather than being retried.
    #[cfg(unix)]
    fn poll_fork_boundary_signal(
        signal_socket: &std::os::unix::net::UnixDatagram,
        worker: &mut std::process::Child,
        expected: u8,
    ) -> bool {
        let mut signal = [0_u8; 1];
        match signal_socket.recv(&mut signal) {
            Ok(1) => {
                assert_eq!(
                    signal,
                    [expected],
                    "fork-boundary worker published an out-of-order signal"
                );
                true
            }
            Ok(received) => {
                panic!("fork-boundary worker published a {received}-byte signal")
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => false,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                match worker.try_wait() {
                    Ok(Some(status)) => {
                        panic!("fork-boundary worker exited before signal {expected}: {status}")
                    }
                    Ok(None) => false,
                    Err(error) => {
                        panic!(
                            "failed to poll fork-boundary worker before signal {expected}: {error}"
                        )
                    }
                }
            }
            Err(error) => {
                panic!("failed to receive fork-boundary signal {expected}: {error}")
            }
        }
    }

    #[cfg(unix)]
    fn receive_fork_boundary_signal(
        signal_socket: &std::os::unix::net::UnixDatagram,
        worker: &mut std::process::Child,
        expected: u8,
        timeout: Duration,
    ) {
        let deadline = std::time::Instant::now() + timeout;
        while !poll_fork_boundary_signal(signal_socket, worker, expected) {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for fork-boundary signal {expected}"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn wait_for_test_pid_gone(pid: libc::pid_t, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "process {pid} survived guardian cleanup"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn wait_for_test_process_group_gone(process_group: libc::pid_t, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let result = unsafe { libc::kill(-process_group, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "process group {process_group} survived guardian cleanup"
            );
            std::thread::sleep(PROCESS_GROUP_GUARDIAN_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn assert_test_child_reaped(pid: libc::pid_t) {
        let mut child_status = 0;
        let result = unsafe { libc::waitpid(pid, &mut child_status, libc::WNOHANG) };
        assert_eq!(result, -1, "child {pid} remained waitable");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "child {pid} was gone but not reaped by its owner"
        );
    }

    #[test]
    fn spawn_plan_always_lets_the_daemon_choose_the_port() {
        let plan = DaemonSpawnPlan {
            daemon_bin: PathBuf::from("/usr/bin/kin-daemon"),
            working_dir: PathBuf::from("/repo"),
            idle_timeout_secs: None,
            supervisor_url: None,
        };
        let cmd = plan.command();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args, vec!["--repo", "/repo", "--port", "0"]);
    }

    #[test]
    fn spawn_plan_passes_idle_timeout_and_supervisor_when_present() {
        let plan = DaemonSpawnPlan {
            daemon_bin: PathBuf::from("/usr/bin/kin-daemon"),
            working_dir: PathBuf::from("/repo"),
            idle_timeout_secs: Some(MCP_IDLE_TIMEOUT_SECS),
            supervisor_url: Some("http://127.0.0.1:9000".to_string()),
        };
        let cmd = plan.command();
        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().to_string(),
                    v.map(|v| v.to_string_lossy().to_string()),
                )
            })
            .collect();
        assert!(envs.contains(&(
            "KIN_DAEMON_IDLE_TIMEOUT_SECS".to_string(),
            Some("1800".to_string())
        )));
        assert!(envs.contains(&(
            "KIN_SUPERVISOR_URL".to_string(),
            Some("http://127.0.0.1:9000".to_string())
        )));
    }

    /// The command's explicit environment overlay as a map, with a removal
    /// recorded as `Some(None)` exactly as `Command::get_envs` reports it.
    fn command_env(command: &Command) -> std::collections::BTreeMap<String, Option<String>> {
        command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    #[test]
    fn a_spawn_carries_the_operator_background_embed_opt_out() {
        let mut command = Command::new("/usr/bin/kin-daemon");
        carry_operator_auto_embed(&mut command, Some(std::ffi::OsString::from("0")));
        assert_eq!(
            command_env(&command).get(DAEMON_AUTO_EMBED_ENV),
            Some(&Some("0".to_string())),
            "a daemon spawn dropped the operator's background-embedding opt-out"
        );
    }

    #[test]
    fn a_spawn_invents_no_opt_out_the_operator_did_not_state() {
        let mut command = Command::new("/usr/bin/kin-daemon");
        carry_operator_auto_embed(&mut command, None);
        assert_eq!(
            command_env(&command).get(DAEMON_AUTO_EMBED_ENV),
            None,
            "a daemon spawn stated a background-embedding choice the operator never made"
        );
    }

    #[test]
    fn the_authority_scrub_cannot_drop_the_background_embed_opt_out() {
        // The scrub runs before the pin inside `command()`, and callers run it
        // again afterwards. Neither ordering may remove the opt-out: it is
        // operator configuration, not ambient repository authority.
        let mut command = Command::new("/usr/bin/kin-daemon");
        carry_operator_auto_embed(&mut command, Some(std::ffi::OsString::from("false")));
        scrub_daemon_process_authority(&mut command);
        assert_eq!(
            command_env(&command).get(DAEMON_AUTO_EMBED_ENV),
            Some(&Some("false".to_string())),
            "the daemon authority scrub removed the operator's background-embedding opt-out"
        );
    }

    #[test]
    fn daemon_authority_scrub_is_final_and_preserves_declared_configuration() {
        let mut command = Command::new("/usr/bin/kin-daemon");
        for (key, value) in [
            ("GIT_DIR", "/ambient/repository/.git"),
            ("GIT_WORK_TREE", "/ambient/repository"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/ambient/hooks"),
            ("GIT_CONFIG_GLOBAL", "/ambient/gitconfig"),
            ("GIT_DEFAULT_HASH", "sha256"),
            ("GIT_TRACE", "/ambient/git-trace"),
            ("KIN_DAEMON_URL", "http://stale.invalid"),
            ("KIN_MCP_REPO", "/ambient/repo"),
            ("KIN_SESSION", "ambient-session"),
            ("KIN_SOURCE_ROOT", "/ambient/projection"),
            ("KIN_SUPERVISOR_STARTUP_GENERATION", "ambient-generation"),
            ("DYLD_LIBRARY_PATH", "/ambient/dyld"),
            ("LD_DEBUG_OUTPUT", "/tmp/ambient-loader-output"),
        ] {
            command.env(key, value);
        }
        command
            .env("KIN_TEST_RUNTIME_OWNER_TOKEN", "test-owner")
            .env("KIN_REGISTRY_PATH", "/declared/registry.toml")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "900");

        scrub_daemon_process_authority(&mut command);

        let envs = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for removed in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_GLOBAL",
            "GIT_DEFAULT_HASH",
            "GIT_TRACE",
            "KIN_DAEMON_URL",
            "KIN_MCP_REPO",
            "KIN_SESSION",
            "KIN_SOURCE_ROOT",
            "KIN_SUPERVISOR_STARTUP_GENERATION",
            "DYLD_LIBRARY_PATH",
            "LD_DEBUG_OUTPUT",
        ] {
            assert_eq!(
                envs.get(removed),
                Some(&None),
                "{removed} retained daemon authority"
            );
        }
        assert_eq!(
            envs.get("KIN_TEST_RUNTIME_OWNER_TOKEN"),
            Some(&Some("test-owner".to_string()))
        );
        assert_eq!(
            envs.get("KIN_REGISTRY_PATH"),
            Some(&Some("/declared/registry.toml".to_string()))
        );
        assert_eq!(
            envs.get("KIN_DAEMON_IDLE_TIMEOUT_SECS"),
            Some(&Some("900".to_string()))
        );
        assert_eq!(envs.get("KIN_VFS_DISABLE"), Some(&Some("1".to_string())));
        assert!(
            envs.get("PATH").is_some_and(Option::is_some),
            "daemon scrub must bind the child to a host PATH"
        );
    }

    #[cfg(unix)]
    #[test]
    fn guardian_environment_scrub_matches_the_daemon_command_boundary() {
        let mut command = Command::new("/usr/bin/kin-daemon");
        let mut guardian_environment = ProcessGroupGuardianEnvironment::default();
        for (key, value) in [
            ("GIT_DIR", "/ambient/repository/.git"),
            ("KIN_DAEMON_URL", "http://stale.invalid"),
            ("DYLD_LIBRARY_PATH", "/ambient/dyld"),
            ("KIN_REGISTRY_PATH", "/declared/registry.toml"),
        ] {
            command.env(key, value);
            guardian_environment.env(key, value);
        }

        scrub_daemon_process_authority(&mut command);
        scrub_daemon_guardian_environment(&mut guardian_environment);

        let command_environment = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let guardian_environment = guardian_environment
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(guardian_environment, command_environment);
    }

    #[cfg(windows)]
    #[test]
    fn daemon_authority_names_are_case_insensitive_on_windows() {
        for hostile in [
            "git_dir",
            "Git_Work_Tree",
            "git_config_key_0",
            "Git_Default_Hash",
            "kin_daemon_url",
            "Kin_Mcp_Repo",
            "dyld_library_path",
            "Ld_Debug_Output",
        ] {
            assert!(
                is_daemon_ambient_authority(std::ffi::OsStr::new(hostile)),
                "{hostile} bypassed Windows daemon authority isolation"
            );
        }
    }

    #[test]
    fn an_explicit_user_idle_timeout_is_never_overwritten() {
        assert_eq!(
            resolve_idle_timeout(true, Some(MCP_IDLE_TIMEOUT_SECS)),
            None
        );
        assert_eq!(
            resolve_idle_timeout(false, Some(MCP_IDLE_TIMEOUT_SECS)),
            Some("1800")
        );
        assert_eq!(resolve_idle_timeout(false, None), None);
    }

    #[cfg(unix)]
    #[test]
    fn daemon_detachment_requires_owner_and_exact_live_process_group() {
        use std::ffi::OsStr;

        let actual_group = 4123;
        assert!(should_detach_from_caller_for(None, None, actual_group));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("")),
            Some(OsStr::new("4123")),
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            None,
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("not-a-pid")),
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("0")),
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("-4123")),
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("4124")),
            actual_group
        ));
        assert!(should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("4123")),
            0
        ));
        assert!(!should_detach_from_caller_for(
            Some(OsStr::new("owner")),
            Some(OsStr::new("4123")),
            actual_group
        ));
    }

    #[test]
    fn port_is_read_from_the_file_the_daemon_wrote() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_reported_port(dir.path()), None);
        std::fs::write(dir.path().join(PORT_FILE_NAME), "45123\n").unwrap();
        assert_eq!(read_reported_port(dir.path()), Some(45123));
    }

    #[test]
    fn an_unpublished_or_zero_port_is_not_a_port() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PORT_FILE_NAME), "0").unwrap();
        assert_eq!(read_reported_port(dir.path()), None);
        std::fs::write(dir.path().join(PORT_FILE_NAME), "not-a-port").unwrap();
        assert_eq!(read_reported_port(dir.path()), None);
    }

    #[test]
    fn only_a_dead_child_authorizes_termination() {
        assert!(!StartupDisposition::Alive.authorizes_termination());
        assert!(!StartupDisposition::Indeterminate.authorizes_termination());
        assert!(StartupDisposition::Exited("signal: 9".to_string()).authorizes_termination());
    }

    #[test]
    fn an_orphaned_port_record_is_one_with_no_pid_owner() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!port_record_is_orphaned(dir.path()));

        std::fs::write(dir.path().join(PORT_FILE_NAME), "45123").unwrap();
        assert!(port_record_is_orphaned(dir.path()));

        std::fs::write(dir.path().join(PID_FILE_NAME), "4242").unwrap();
        assert!(
            !port_record_is_orphaned(dir.path()),
            "a port beside a live PID record may belong to a daemon mid-publication"
        );
    }

    /// Run a child to completion under `sh`, returning how it ended.
    ///
    /// The child is signalled or exits on its own depending on `end`, which is
    /// the only difference the classifier is being asked to read.
    #[cfg(unix)]
    fn reaped_child_status(end: ChildEnding) -> std::process::ExitStatus {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(match end {
                ChildEnding::Signalled(_) => "while :; do sleep 1; done".to_string(),
                ChildEnding::SelfExit(code) => format!("exit {code}"),
            })
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child whose ending the classifier will read");
        if let ChildEnding::Signalled(signal) = end {
            let pid = libc::pid_t::try_from(child.id()).expect("child pid fits a pid_t");
            assert_eq!(
                unsafe { libc::kill(pid, signal) },
                0,
                "deliver the ending signal"
            );
        }
        child.wait().expect("reap the child")
    }

    #[cfg(unix)]
    #[derive(Clone, Copy)]
    enum ChildEnding {
        Signalled(libc::c_int),
        SelfExit(i32),
    }

    /// A sentinel the barrier stopped may be killed by the kernel instead.
    ///
    /// `quiesce_pinned_process_group` stops the group before it kills it, and
    /// POSIX sends SIGHUP to every member of a process group that becomes
    /// orphaned while a member is stopped. A sentinel lost that way was read as
    /// an unexpected exit, which failed runs whose containment had succeeded.
    /// The self-exit codes stay rejected in the same assertion, because those
    /// are the endings that really do release the PID pin early.
    #[cfg(unix)]
    #[test]
    fn a_signalled_sentinel_is_not_an_unexpected_exit_but_a_self_exit_still_is() {
        assert!(
            sentinel_exit_was_signalled(reaped_child_status(ChildEnding::Signalled(libc::SIGKILL))),
            "SIGKILL is the barrier's own signal"
        );
        assert!(
            sentinel_exit_was_signalled(reaped_child_status(ChildEnding::Signalled(libc::SIGHUP))),
            "SIGHUP reaches a stopped sentinel whose group is orphaned before the barrier's kill \
             lands, and this crate never sends it, so it cannot be self-inflicted"
        );

        for code in [0, 70] {
            let status = reaped_child_status(ChildEnding::SelfExit(code));
            assert!(
                !sentinel_exit_was_signalled(status),
                "a sentinel that leaves through _exit({code}) releases the PID pin early and must \
                 still be reported"
            );
        }
    }

    #[test]
    fn clearing_leaves_a_port_that_still_has_a_pid_owner() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PORT_FILE_NAME), "45123").unwrap();
        std::fs::write(dir.path().join(PID_FILE_NAME), "4242").unwrap();
        assert!(!clear_orphaned_port_record(dir.path()));
        assert!(dir.path().join(PORT_FILE_NAME).exists());

        std::fs::remove_file(dir.path().join(PID_FILE_NAME)).unwrap();
        assert!(clear_orphaned_port_record(dir.path()));
        assert!(!dir.path().join(PORT_FILE_NAME).exists());
    }

    // These three drive a real child process, so they need the POSIX stand-in
    // binaries. The contract itself is platform-neutral.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_live_child_that_never_reports_a_port_is_left_running() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a long-lived stand-in child");

        let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
        let outcome = await_reported_port(dir.path(), &mut child, deadline).await;

        assert!(
            matches!(outcome, Err(PortWaitError::StillStarting)),
            "a deadline with a live child must not be reported as death: {outcome:?}"
        );
        assert!(
            matches!(
                startup_disposition(&mut child),
                Ok(StartupDisposition::Alive)
            ),
            "the child must still be running after the deadline elapsed"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_child_that_exits_before_publishing_is_reported_as_exited() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a child that exits immediately");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let outcome = await_reported_port(dir.path(), &mut child, deadline).await;

        assert!(
            matches!(outcome, Err(PortWaitError::ChildExited(_))),
            "an exited child is positive evidence and must be reported as such: {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_published_port_is_returned_as_soon_as_it_appears() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a long-lived stand-in child");

        let port_path = dir.path().join(PORT_FILE_NAME);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            std::fs::write(port_path, "45999").unwrap();
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let port = await_reported_port(dir.path(), &mut child, deadline)
            .await
            .expect("the published port is the answer");
        assert_eq!(port, 45999);

        let _ = child.kill();
        let _ = child.wait();
    }

    // ── A detached spawn releases the caller's stdio ─────────────────────

    /// Set on the process standing in for a spawned daemon; its value is the
    /// path that process publishes to prove it really started.
    const DETACHED_HOLDER_ENV: &str = "KIN_INTERNAL_TEST_DETACHED_HOLDER";

    /// Set on the process standing in for the CLI that does the spawning; its
    /// value is the readiness path it passes down.
    const DETACHED_RELAY_ENV: &str = "KIN_INTERNAL_TEST_DETACHED_RELAY";

    /// Long enough that anything still waiting on this process is waiting for
    /// it and not for a slow runner, short enough that a failing run leaves
    /// nothing behind for long.
    const DETACHED_HOLDER_LIFETIME: Duration = Duration::from_secs(60);

    /// A third of the holder's lifetime, so the pass and the failure are told
    /// apart by a wide margin rather than by a race.
    const DETACHED_CLOSE_BUDGET: Duration = Duration::from_secs(20);

    /// Stand-in for the spawned daemon: publish readiness, then outlive the
    /// process that started it.
    #[test]
    fn detached_spawn_holder_worker() {
        let Some(ready) = std::env::var_os(DETACHED_HOLDER_ENV) else {
            return;
        };
        let ready = PathBuf::from(ready);
        let staged = ready.with_extension("staging");
        std::fs::write(&staged, b"holding\n").expect("stage holder readiness");
        std::fs::rename(&staged, &ready).expect("publish holder readiness");
        std::thread::sleep(DETACHED_HOLDER_LIFETIME);
    }

    /// Stand-in for the CLI: spawn a daemon through the shared contract and
    /// exit immediately, leaving only the question of what the daemon still
    /// holds.
    #[test]
    fn detached_spawn_relay_worker() {
        use std::process::Stdio;

        let Some(ready) = std::env::var_os(DETACHED_RELAY_ENV) else {
            return;
        };
        let executable = std::env::current_exe().expect("resolve the relay executable");
        let mut holder = Command::new(executable);
        holder
            .args([
                "--exact",
                "tests::detached_spawn_holder_worker",
                "--nocapture",
            ])
            .env(DETACHED_HOLDER_ENV, ready)
            .env_remove(DETACHED_RELAY_ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detach_from_caller(&mut holder);
        let holder = holder.spawn().expect("spawn the detached holder");
        // Outliving this process is the point, so the handle is released
        // deliberately rather than waited on.
        std::mem::forget(holder);
    }

    fn detached_probe_started(ready: &Path, budget: Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        while !ready.is_file() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }

    /// A daemon started through the shared contract must not keep the stdio the
    /// caller was given.
    ///
    /// Unix gets this from `CLOEXEC` and has always had it. Windows hands a
    /// child every inheritable handle, so before the caller's standard handles
    /// were released the daemon silently held its spawner's stdout: the reader
    /// on the far side of `kin search --json | jq` saw no end of file until the
    /// daemon idled out, and by then the daemon had retired the endpoint the
    /// next command was about to read.
    #[test]
    fn a_detached_spawn_does_not_hold_the_callers_stdout_open() {
        use std::io::Read as _;
        use std::process::Stdio;

        let dir = tempfile::tempdir().expect("temporary directory for the detach probe");
        let ready = dir.path().join("holder.ready");
        let executable = std::env::current_exe().expect("resolve the probe executable");

        let mut relay = Command::new(executable)
            .args([
                "--exact",
                "tests::detached_spawn_relay_worker",
                "--nocapture",
            ])
            .env(DETACHED_RELAY_ENV, &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the detach relay");
        let mut relay_stdout = relay.stdout.take().expect("the relay's stdout is a pipe");

        // Read on a thread the test never joins: when the handle did leak, this
        // read cannot return until the holder's own lifetime ends, and the test
        // has to be able to report that rather than wait it out.
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut drained = Vec::new();
            let closed = relay_stdout.read_to_end(&mut drained).is_ok();
            let _ = closed_tx.send(closed);
        });

        // Readiness first, and it is not a formality: a relay that never
        // managed to start a holder closes the pipe on its own, which is the
        // exact observation this test would otherwise call a pass.
        let started = detached_probe_started(&ready, DETACHED_CLOSE_BUDGET);
        let closed = closed_rx.recv_timeout(DETACHED_CLOSE_BUDGET);

        let _ = relay.kill();
        let _ = relay.wait();

        assert!(
            started,
            "the relay never started a detached holder, so this run proves nothing about what a \
             holder keeps open"
        );
        assert_eq!(
            closed.ok(),
            Some(true),
            "the detached holder is still holding its spawner's stdout open {} seconds after the \
             spawner exited",
            DETACHED_CLOSE_BUDGET.as_secs()
        );
    }
}
