// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin daemon` — inspect and gracefully stop the Kin daemon topology.
//!
//! The Kin daemon is a mandatory, long-lived per-user runtime: one supervisor
//! per user plus one worker daemon per repo it has served. Because the worker
//! outlives the command that spawned it and freezes that command's environment,
//! operators need a supported way to see what is running and to stop it (the
//! behavior-env divergence warning tells them to). This command group is that
//! surface, replacing raw `kill $(cat .kin/daemon.pid)`.
//!
//! Stop authority is always bound to one process incarnation. Linux uses a
//! pidfd, native Windows uses a process handle, and macOS uses an authenticated
//! cooperative endpoint whose request names the expected birth identity. The
//! wait is a ceiling, not a fixed delay.
//!
//! `--all` bounds the sweep, not just each step in it. Stopping identities in
//! sequence under a per-identity ceiling left the command's real bound
//! proportional to how many daemons happened to be running, so `stop --all`
//! could outlive its caller's patience and be killed before reporting anything.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::daemon_client::{
    fetch_registered_daemons, is_port_open, is_process_alive, process_identity,
    process_identity_is_current, read_endpoint_owner_record, read_supervisor_owner_record,
    remove_stale_daemon_files, remove_stale_supervisor_files, repo_daemon_owner_path,
    repo_daemon_pid_path, repo_daemon_port_path, repo_daemon_recorded_endpoint,
    supervisor_owner_path, supervisor_pid_path, supervisor_port_path, supervisor_recorded_endpoint,
    try_acquire_supervisor_startup_lock_in_dir, ProcessIdentity, RegisteredRepoDaemon,
    SupervisorStartupLock,
};

/// Liveness of a recorded daemon/supervisor endpoint. Pure classification of the
/// recorded pid plus the observed process/port state, so the policy is testable
/// without a live process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLiveness {
    /// Recorded process is alive and its port accepts connections.
    Running,
    /// Recorded process is alive but its port does not accept connections —
    /// still starting up, or wedged.
    Unresponsive,
    /// A pid was recorded but that process is not alive: the endpoint files are
    /// stale and should be cleared.
    Stale,
    /// No pid was recorded — no endpoint files present.
    NotRunning,
}

impl DaemonLiveness {
    fn label(self) -> &'static str {
        match self {
            DaemonLiveness::Running => "running",
            DaemonLiveness::Unresponsive => "unresponsive (process alive, port closed)",
            DaemonLiveness::Stale => "stale (recorded process is gone)",
            DaemonLiveness::NotRunning => "not running",
        }
    }

    fn is_stale(self) -> bool {
        matches!(self, DaemonLiveness::Stale)
    }
}

/// Classify liveness from the recorded pid and the observed process/port state.
/// `process_alive` and `port_open` are only meaningful when `pid` is `Some`.
pub fn classify_liveness(pid: Option<u32>, process_alive: bool, port_open: bool) -> DaemonLiveness {
    match pid {
        None => DaemonLiveness::NotRunning,
        Some(_) if !process_alive => DaemonLiveness::Stale,
        Some(_) if port_open => DaemonLiveness::Running,
        Some(_) => DaemonLiveness::Unresponsive,
    }
}

/// Bounded wait for a stop to complete. The daemon's shutdown-escalation
/// watchdog force-exits ~25s after SIGTERM, so 30s comfortably covers a graceful
/// stop plus a final snapshot flush. Override with `KIN_DAEMON_STOP_TIMEOUT_SECS`.
fn stop_timeout() -> Duration {
    let secs = std::env::var("KIN_DAEMON_STOP_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    Duration::from_secs(secs)
}

/// Worst case for one daemon that rides its force-exit escalation all the way:
/// `DEFAULT_SHUTDOWN_ESCALATION_GRACE` (25s) plus one `SHUTDOWN_WATCH_POLL`
/// (250ms) for the watchdog to notice. Any sweep budget has to clear this for
/// the FIRST identity alone, or a single wedged daemon consumes the whole sweep.
const DAEMON_FORCE_EXIT_WORST_CASE: Duration = Duration::from_millis(25_250);

/// Reserved for the supervisor, which is stopped last.
const SUPERVISOR_STOP_RESERVE: Duration = Duration::from_secs(10);

/// How long the whole `--all` sweep may take, as opposed to how long any one
/// identity may take.
///
/// `--all` stops identities in sequence, so giving each the full per-identity
/// ceiling made the command's real bound `identities × ceiling` with nothing
/// bounding the product. An ordinary install is one worker plus the supervisor,
/// which is already 60s of worst case against a caller that commonly allows 60s,
/// so the command was killed before it could report anything, turning a stop
/// that failed into a stop with no verdict at all.
///
/// Sizing it is not free choice. `stop_timeout()`'s 30s was picked as a
/// PER-IDENTITY margin over the daemon's ~25.25s hard bound, so reusing it as
/// the whole-sweep budget leaves that 5s of margin to cover every identity after
/// the first. One worker riding the full escalation would hand the supervisor
/// 4.75s, and a supervisor reported `timeout` fails the command just as loudly
/// as a hang. The budget is therefore derived from the daemon's bound rather
/// than borrowed from a per-identity constant, and still leaves headroom under
/// the 60s callers typically allow.
fn stop_all_budget() -> Duration {
    DAEMON_FORCE_EXIT_WORST_CASE
        .saturating_add(SUPERVISOR_STOP_RESERVE)
        .max(stop_timeout())
}

/// Budget left before `deadline`.
///
/// Reaching zero does not skip an identity: the stop request is still delivered,
/// and only the wait for the process to disappear is what the exhausted budget
/// gives up. The identity is then reported `timeout`, which is the honest
/// outcome, since the request went out and this command did not stay to watch.
fn remaining_budget(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Outcome of a graceful stop request against one recorded pid.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StopOutcome {
    /// No live process was found for the pid — nothing to stop.
    NotRunning,
    /// The platform stop request was delivered and the process exited.
    Stopped,
    /// The stop request was delivered but the process survived the wait window.
    Timeout,
    /// Delivering the platform stop request failed while the owner remained.
    SignalFailed(String),
}

impl StopOutcome {
    /// Whether this outcome leaves nothing alive: a clean stop or an
    /// already-dead process both satisfy "it is not running".
    fn is_success(&self) -> bool {
        matches!(self, StopOutcome::NotRunning | StopOutcome::Stopped)
    }

    fn detail(&self) -> &str {
        match self {
            StopOutcome::NotRunning => "not-running",
            StopOutcome::Stopped => "stopped",
            StopOutcome::Timeout => "timeout",
            StopOutcome::SignalFailed(_) => "signal-failed",
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_attributed_process(identity: &ProcessIdentity) -> std::io::Result<bool> {
    // pidfd_open pins the task incarnation before identity revalidation. PID
    // reuse after this point cannot redirect pidfd_send_signal to a successor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid(), 0) as libc::c_int };
    if fd < 0 {
        return if !process_identity_is_current(identity)? {
            Ok(false)
        } else {
            Err(std::io::Error::last_os_error())
        };
    }
    let outcome = if !process_identity_is_current(identity)? {
        Ok(false)
    } else {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            Ok(true)
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else {
                Err(error)
            }
        }
    };
    let _ = unsafe { libc::close(fd) };
    outcome
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn terminate_attributed_process(_identity: &ProcessIdentity) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "incarnation-bound daemon stop is unsupported on this Unix platform",
    ))
}

#[cfg(windows)]
fn terminate_attributed_process(identity: &ProcessIdentity) -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };

    // Opening a process handle pins the incarnation that PID names. Revalidate
    // the full creation identity while that handle is live, then terminate via
    // the handle rather than looking the PID up a second time. PID reuse after
    // this point can therefore never redirect termination to a successor.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
            0,
            identity.pid(),
        )
    };
    if handle.is_null() {
        return if !process_identity_is_current(identity)? {
            Ok(false)
        } else {
            Err(std::io::Error::last_os_error())
        };
    }
    let still_current = process_identity_is_current(identity);
    let outcome = match still_current {
        Ok(false) => Ok(false),
        Err(error) => Err(error),
        Ok(true) => {
            if unsafe { TerminateProcess(handle, 0) } == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(true)
            }
        }
    };
    let _ = unsafe { CloseHandle(handle) };
    outcome
}

#[cfg(not(any(unix, windows)))]
fn terminate_attributed_process(identity: &ProcessIdentity) -> std::io::Result<bool> {
    let _ = identity;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "daemon stop is unsupported on this platform",
    ))
}

/// Stop exactly one attributed process incarnation and wait up to `wait` for
/// that incarnation to disappear. A reused numeric PID compares unequal and is
/// never signaled or mistaken for a surviving daemon.
#[cfg(not(target_os = "macos"))]
fn stop_identity_graceful(identity: &ProcessIdentity, wait: Duration) -> StopOutcome {
    match terminate_attributed_process(identity) {
        Ok(false) => return StopOutcome::NotRunning,
        Ok(true) => {}
        Err(error) => {
            if matches!(process_identity_is_current(identity), Ok(false)) {
                return StopOutcome::NotRunning;
            }
            return StopOutcome::SignalFailed(error.to_string());
        }
    }
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if matches!(process_identity_is_current(identity), Ok(false)) {
            return StopOutcome::Stopped;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if matches!(process_identity_is_current(identity), Ok(false)) {
        StopOutcome::Stopped
    } else {
        StopOutcome::Timeout
    }
}

#[cfg(target_os = "macos")]
fn stop_identity_cooperatively<F>(
    identity: &ProcessIdentity,
    wait: Duration,
    request_shutdown: F,
) -> StopOutcome
where
    F: FnOnce(&ProcessIdentity) -> std::io::Result<bool>,
{
    if matches!(process_identity_is_current(identity), Ok(false)) {
        return StopOutcome::NotRunning;
    }
    match request_shutdown(identity) {
        Ok(false) => return StopOutcome::NotRunning,
        Ok(true) => {}
        Err(error) => {
            if matches!(process_identity_is_current(identity), Ok(false)) {
                return StopOutcome::NotRunning;
            }
            return StopOutcome::SignalFailed(error.to_string());
        }
    }
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if matches!(process_identity_is_current(identity), Ok(false)) {
            return StopOutcome::Stopped;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if matches!(process_identity_is_current(identity), Ok(false)) {
        StopOutcome::Stopped
    } else {
        StopOutcome::Timeout
    }
}

#[cfg(target_os = "macos")]
fn cooperative_shutdown_request(
    port: u16,
    token: Option<String>,
    identity: &ProcessIdentity,
) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let body = serde_json::to_vec(identity).map_err(std::io::Error::other)?;
    let authorization = match token {
        Some(token) if token.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "daemon auth token contains a forbidden newline",
            ))
        }
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let head = format!(
        "POST /shutdown HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        body.len(),
        authorization
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.take(16 * 1024).read_to_end(&mut response)?;
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("invalid cooperative shutdown HTTP response"))?;
    match status {
        200..=299 => Ok(true),
        409 | 410 => Ok(false),
        _ => Err(std::io::Error::other(format!(
            "cooperative shutdown endpoint returned HTTP {status}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn stop_worker_identity(
    kin_root: &Path,
    identity: &ProcessIdentity,
    wait: Duration,
) -> StopOutcome {
    let (recorded_pid, recorded_port) = repo_daemon_recorded_endpoint(kin_root);
    if recorded_pid != Some(identity.pid()) {
        return StopOutcome::SignalFailed(format!(
            "worker endpoint changed before cooperative shutdown for pid {}",
            identity.pid()
        ));
    }
    let Some(port) = recorded_port else {
        return StopOutcome::SignalFailed(format!(
            "worker pid {} has no recorded cooperative shutdown port",
            identity.pid()
        ));
    };
    let token = std::env::var("KIN_DAEMON_AUTH_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string(kin_root.join("daemon.token"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    stop_identity_cooperatively(identity, wait, |expected| {
        cooperative_shutdown_request(port, token, expected)
    })
}

#[cfg(not(target_os = "macos"))]
fn stop_worker_identity(
    _kin_root: &Path,
    identity: &ProcessIdentity,
    wait: Duration,
) -> StopOutcome {
    stop_identity_graceful(identity, wait)
}

#[cfg(target_os = "macos")]
fn stop_supervisor_identity(identity: &ProcessIdentity, wait: Duration) -> StopOutcome {
    let (recorded_pid, recorded_port) = supervisor_recorded_endpoint();
    if recorded_pid != Some(identity.pid()) {
        return StopOutcome::SignalFailed(format!(
            "supervisor endpoint changed before cooperative shutdown for pid {}",
            identity.pid()
        ));
    }
    let Some(port) = recorded_port else {
        return StopOutcome::SignalFailed(format!(
            "supervisor pid {} has no recorded cooperative shutdown port",
            identity.pid()
        ));
    };
    let token = std::env::var("KIN_SUPERVISOR_AUTH_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let path = supervisor_owner_path().with_file_name("supervisor.token");
            std::fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    stop_identity_cooperatively(identity, wait, |expected| {
        cooperative_shutdown_request(port, token, expected)
    })
}

#[cfg(not(target_os = "macos"))]
fn stop_supervisor_identity(identity: &ProcessIdentity, wait: Duration) -> StopOutcome {
    stop_identity_graceful(identity, wait)
}

fn attributed_worker_identity(kin_root: &Path, pid: u32) -> Result<Option<ProcessIdentity>> {
    let owner = read_endpoint_owner_record(kin_root).with_context(|| {
        format!(
            "worker endpoint {} has no valid process-incarnation owner record",
            repo_daemon_pid_path(kin_root).display()
        )
    })?;
    if owner.identity().pid() != pid {
        bail!(
            "worker endpoint ownership is torn at {}: pid file names {}, owner record names {}",
            kin_root.display(),
            pid,
            owner.identity().pid()
        );
    }
    match process_identity_is_current(owner.identity()) {
        Ok(true) => Ok(Some(owner.identity().clone())),
        Ok(false) => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not verify worker process incarnation {} for {}",
                pid,
                kin_root.display()
            )
        }),
    }
}

fn attributed_supervisor_identity(pid: u32) -> Result<Option<ProcessIdentity>> {
    let owner = read_supervisor_owner_record().with_context(|| {
        format!(
            "supervisor endpoint {} has no valid process-incarnation owner record",
            supervisor_pid_path().display()
        )
    })?;
    if owner.identity().pid() != pid {
        bail!(
            "supervisor endpoint ownership is torn: pid file names {}, owner record names {}",
            pid,
            owner.identity().pid()
        );
    }
    match process_identity_is_current(owner.identity()) {
        Ok(true) => Ok(Some(owner.identity().clone())),
        Ok(false) => Ok(None),
        Err(error) => Err(error).context("could not verify supervisor process incarnation"),
    }
}

fn stop_worker_at(
    kin_root: &Path,
    pid: u32,
    wait: Duration,
    legacy_install_root: Option<&Path>,
) -> Result<StopOutcome> {
    let identity = match attributed_worker_identity(kin_root, pid) {
        Ok(identity) => identity,
        Err(error)
            if legacy_install_root.is_some()
                && matches!(
                    std::fs::symlink_metadata(repo_daemon_owner_path(kin_root)),
                    Err(ref io_error) if io_error.kind() == std::io::ErrorKind::NotFound
                ) =>
        {
            legacy_managed_identity(
                legacy_install_root.context("legacy install root disappeared")?,
                pid,
                Some(kin_root.parent().unwrap_or(kin_root)),
            )
            .with_context(|| format!("legacy worker attribution failed after: {error:#}"))?
        }
        Err(error) => return Err(error),
    };
    Ok(match identity {
        Some(identity) => stop_worker_identity(kin_root, &identity, wait),
        None => StopOutcome::NotRunning,
    })
}

fn supervisor_identity_for_stop(
    pid: u32,
    legacy_install_root: Option<&Path>,
) -> Result<Option<ProcessIdentity>> {
    match attributed_supervisor_identity(pid) {
        Ok(identity) => Ok(identity),
        Err(error)
            if legacy_install_root.is_some()
                && matches!(
                    std::fs::symlink_metadata(supervisor_owner_path()),
                    Err(ref io_error) if io_error.kind() == std::io::ErrorKind::NotFound
                ) =>
        {
            legacy_managed_identity(
                legacy_install_root.context("legacy install root disappeared")?,
                pid,
                None,
            )
            .with_context(|| format!("legacy supervisor attribution failed after: {error:#}"))
        }
        Err(error) => Err(error),
    }
}

fn stop_supervisor_pid(
    pid: u32,
    wait: Duration,
    legacy_install_root: Option<&Path>,
) -> Result<StopOutcome> {
    Ok(
        match supervisor_identity_for_stop(pid, legacy_install_root)? {
            Some(identity) => stop_supervisor_identity(&identity, wait),
            None => StopOutcome::NotRunning,
        },
    )
}

/// The supervisor URL if a live supervisor is recorded, without ever spawning
/// one. `status` and `stop` must observe the running topology, not create it.
fn supervisor_url_if_running() -> Option<String> {
    let (pid, port) = supervisor_recorded_endpoint();
    let (pid, port) = (pid?, port?);
    if is_process_alive(pid) && is_port_open(port) {
        Some(format!("http://127.0.0.1:{port}"))
    } else {
        None
    }
}

fn require_supervisor_port_for_stop(
    pid: u32,
    recorded_port: Option<u16>,
    port_open: bool,
) -> Result<u16> {
    let port = recorded_port.with_context(|| {
        format!("live supervisor pid {pid} has no published port; refusing partial stop")
    })?;
    if !port_open {
        bail!(
            "live supervisor pid {pid} is unresponsive on recorded port {port}; refusing to guess an incomplete daemon topology"
        );
    }
    Ok(port)
}

fn repo_label(working_dir: &Path) -> String {
    working_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn canonical(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

// ── status ──────────────────────────────────────────────────────────────────

/// `kin daemon status` — report the supervisor and every repo worker daemon.
pub async fn status(json: bool) -> Result<()> {
    let (sup_pid, sup_port) = supervisor_recorded_endpoint();
    let sup_alive = sup_pid.map(is_process_alive).unwrap_or(false);
    let sup_port_open = sup_port.map(is_port_open).unwrap_or(false);
    let sup_state = classify_liveness(sup_pid, sup_alive, sup_port_open);

    // The per-repo worker list comes from the supervisor's `/daemons` registry —
    // the same surface `kin registry daemons` reads. Only reachable when the
    // supervisor is actually up; never spawn one just to list.
    let supervisor_url = supervisor_url_if_running();
    let daemons: Vec<RegisteredRepoDaemon> = match &supervisor_url {
        Some(url) => fetch_registered_daemons(url).await.unwrap_or_default(),
        None => Vec::new(),
    };

    // The current repo's own worker endpoint files, classified independently so a
    // stale local endpoint is visible even when the supervisor has pruned it.
    let current = current_repo_status();

    if json {
        let daemons_json: Vec<_> = daemons
            .iter()
            .map(|d| {
                let alive = is_process_alive(d.pid);
                let port_open = is_port_open(d.port);
                let state = classify_liveness(Some(d.pid), alive, port_open);
                serde_json::json!({
                    "repo_id": d.repo_id,
                    "display_name": d.display_name,
                    "repo_root": d.repo_root,
                    "pid": d.pid,
                    "port": d.port,
                    "endpoint": d.endpoint,
                    "graph_entity_count": d.graph_entity_count,
                    "last_heartbeat_at": d.last_heartbeat_at,
                    "state": state.label(),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "schema": "kin.daemon-status.v1",
            "supervisor": {
                "state": sup_state.label(),
                "pid": sup_pid,
                "port": sup_port,
                "pid_file": supervisor_pid_path().display().to_string(),
                "port_file": supervisor_port_path().display().to_string(),
            },
            "repo_daemons": daemons_json,
            "current_repo": current.as_ref().map(|c| serde_json::json!({
                "label": c.label,
                "repo_root": c.repo_root,
                "state": c.state.label(),
                "pid": c.pid,
                "port": c.port,
                "pid_file": c.pid_file,
                "port_file": c.port_file,
            })),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    match (sup_pid, sup_port) {
        (Some(pid), port) => {
            println!(
                "Supervisor: {} (pid {}{})",
                sup_state.label(),
                pid,
                port.map(|p| format!(", port {p}")).unwrap_or_default(),
            );
        }
        (None, _) => println!("Supervisor: not running"),
    }
    println!("  pid file:  {}", supervisor_pid_path().display());
    println!("  port file: {}", supervisor_port_path().display());
    if sup_state.is_stale() {
        println!("  note: supervisor endpoint files are stale; run `kin daemon stop --all` to clear them");
    }

    println!();
    if supervisor_url.is_none() {
        println!("Repo daemons: unavailable (supervisor not running)");
    } else if daemons.is_empty() {
        println!("Repo daemons: none registered");
    } else {
        println!("Repo daemons ({}):", daemons.len());
        for daemon in &daemons {
            let alive = is_process_alive(daemon.pid);
            let port_open = is_port_open(daemon.port);
            let state = classify_liveness(Some(daemon.pid), alive, port_open);
            let label = if daemon.display_name.trim().is_empty() {
                daemon.repo_id.clone()
            } else {
                daemon.display_name.clone()
            };
            let entities = daemon
                .graph_entity_count
                .map(|n| format!("{n} entities"))
                .unwrap_or_else(|| "- entities".to_string());
            println!(
                "  {}  {}  pid {}  port {}  {}  {}",
                label,
                state.label(),
                daemon.pid,
                daemon.port,
                entities,
                daemon.repo_root
            );
            println!("    route:     {}", daemon.repo_id);
            println!("    endpoint:  {}", daemon.endpoint);
            if !daemon.last_heartbeat_at.trim().is_empty() {
                println!("    heartbeat: {}", daemon.last_heartbeat_at);
            }
        }
    }

    if let Some(current) = current {
        println!();
        println!(
            "Current repo ({}): worker daemon {}",
            current.label,
            current.state.label(),
        );
        if current.state.is_stale() {
            println!("  note: endpoint files are stale; `kin daemon stop` will clear them");
        }
    }

    Ok(())
}

struct CurrentRepoStatus {
    label: String,
    repo_root: String,
    state: DaemonLiveness,
    pid: Option<u32>,
    port: Option<u16>,
    pid_file: String,
    port_file: String,
}

fn current_repo_status() -> Option<CurrentRepoStatus> {
    let cwd = std::env::current_dir().ok()?;
    let layout = kin_core::KinLayout::discover(&cwd)?;
    let kin_root = layout.root();
    let working_dir = kin_root.parent().unwrap_or(kin_root);
    let (pid, port) = repo_daemon_recorded_endpoint(kin_root);
    let alive = pid.map(is_process_alive).unwrap_or(false);
    let port_open = port.map(is_port_open).unwrap_or(false);
    let state = classify_liveness(pid, alive, port_open);
    Some(CurrentRepoStatus {
        label: repo_label(working_dir),
        repo_root: canonical(working_dir),
        state,
        pid,
        port,
        pid_file: repo_daemon_pid_path(kin_root).display().to_string(),
        port_file: repo_daemon_port_path(kin_root).display().to_string(),
    })
}

// ── stop ────────────────────────────────────────────────────────────────────

/// `kin daemon stop` — gracefully stop the current repo's worker daemon, or with
/// `--all` every worker plus the supervisor (supervisor last).
pub async fn stop(all: bool, json: bool) -> Result<()> {
    if all {
        stop_all(json, false).await
    } else {
        stop_current_repo(json).await
    }
}

/// Stop every managed Kin daemon without writing a second command's report to
/// stdout. Full uninstall uses this before deleting the managed install root;
/// failures still propagate so it never removes binaries out from under a live
/// daemon.
pub(crate) async fn stop_all_quiet() -> Result<()> {
    stop_all(false, true).await
}

/// Startup authority retained by full uninstall until the install root is
/// retired. While this value is alive no cooperating CLI can publish a new
/// supervisor generation. The final process scan closes the remaining direct
/// worker-spawn gap immediately before root retirement.
pub(crate) struct UninstallDaemonFence {
    _startup_authority: SupervisorStartupLock,
}

impl UninstallDaemonFence {
    pub(crate) fn verify_quiescent(&self, install_root: &Path) -> Result<()> {
        let remaining = managed_daemon_processes(install_root);
        if remaining.is_empty() {
            return Ok(());
        }
        let labels = remaining
            .iter()
            .map(ManagedDaemonProcess::description)
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "full uninstall refused because managed Kin daemon processes appeared after shutdown: {labels}"
        )
    }
}

/// Fail closed when an install root is already absent but a process still
/// advertises an executable or argv path owned by that root. This is the
/// absent-root counterpart to `UninstallDaemonFence::verify_quiescent` and
/// prevents a retry from turning an incomplete prior uninstall into a false
/// `fully_removed` result.
pub(crate) fn verify_install_owned_processes_absent(install_root: &Path) -> Result<()> {
    let remaining = managed_daemon_processes(install_root);
    verify_no_install_owned_processes(remaining)
}

fn verify_no_install_owned_processes(remaining: Vec<ManagedDaemonProcess>) -> Result<()> {
    if remaining.is_empty() {
        return Ok(());
    }
    bail!(
        "full uninstall is incomplete: install-owned Kin processes remain after the public root disappeared: {}; refusing to report fully_removed",
        remaining
            .iter()
            .map(ManagedDaemonProcess::description)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Stop and verify the complete install-owned daemon topology while retaining
/// supervisor startup authority for the caller's subsequent root retirement.
pub(crate) async fn stop_all_for_uninstall(install_root: &Path) -> Result<UninstallDaemonFence> {
    let supervisor_dir = supervisor_pid_path()
        .parent()
        .context("supervisor PID path has no parent")?
        .to_path_buf();
    let deadline = Instant::now() + stop_timeout();
    let startup_authority = loop {
        match try_acquire_supervisor_startup_lock_in_dir(&supervisor_dir) {
            Ok(authority) => break authority,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() >= deadline {
                    return Err(error).context(
                        "timed out waiting for supervisor startup authority before full uninstall",
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(error)
                    .context("failed to acquire supervisor startup authority for full uninstall")
            }
        }
    };
    stop_all_inner(false, true, Some(install_root)).await?;
    let fence = UninstallDaemonFence {
        _startup_authority: startup_authority,
    };
    fence.verify_quiescent(install_root)?;
    Ok(fence)
}

/// One stopped (or attempted-to-stop) endpoint, for the report.
struct StopReport {
    kind: &'static str,
    label: String,
    pid: u32,
    outcome: StopOutcome,
}

async fn stop_current_repo(json: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        bail!(
            "not inside a Kin repository — run `kin daemon stop` from a repo, or \
             `kin daemon stop --all` to stop every daemon"
        );
    };
    let kin_root = layout.root().to_path_buf();
    let working_dir = kin_root.parent().unwrap_or(&kin_root).to_path_buf();
    let label = repo_label(&working_dir);

    let pid = resolve_repo_worker_pid(&kin_root, &working_dir).await?;

    let Some(pid) = pid else {
        // Nothing live to stop. Clear any stale endpoint files so a later status
        // does not report a dead endpoint.
        remove_stale_daemon_files(&kin_root);
        if json {
            let payload = serde_json::json!({
                "schema": "kin.daemon-stop.v1",
                "scope": "current-repo",
                "repo": label,
                "stopped": [],
                "all_stopped": true,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("No worker daemon running for repo '{label}' (nothing to stop).");
        }
        return Ok(());
    };

    let outcome = stop_worker_at(&kin_root, pid, stop_timeout(), None)?;
    if outcome.is_success() {
        remove_stale_daemon_files(&kin_root);
    }
    let report = vec![StopReport {
        kind: "repo-daemon",
        label: label.clone(),
        pid,
        outcome,
    }];
    finish_stop("current-repo", &report, json)
}

/// Resolve the pid of the current repo's worker daemon, the way the daemon
/// client resolves it: prefer the local `.kin/daemon.pid` record, and if that is
/// absent or dead, fall back to the supervisor's `/daemons` registry (matched by
/// canonical repo root). Returns a pid only when the process is actually alive.
async fn resolve_repo_worker_pid(kin_root: &Path, working_dir: &Path) -> Result<Option<u32>> {
    let (local_pid, _) = repo_daemon_recorded_endpoint(kin_root);
    if let Some(pid) = local_pid {
        if attributed_worker_identity(kin_root, pid)?.is_some() {
            return Ok(Some(pid));
        }
    }
    // Local file missing or stale — ask the supervisor if it still routes a live
    // worker for this repo root.
    let Some(url) = supervisor_url_if_running() else {
        return Ok(None);
    };
    let daemons = fetch_registered_daemons(&url)
        .await
        .with_context(|| format!("failed to fetch authenticated daemon topology from {url}"))?;
    let target = canonical(working_dir);
    Ok(daemons
        .into_iter()
        .find(|d| canonical(Path::new(&d.repo_root)) == target && is_process_alive(d.pid))
        .map(|d| d.pid))
}

async fn stop_all(json: bool, quiet: bool) -> Result<()> {
    stop_all_inner(json, quiet, None).await
}

async fn stop_all_inner(json: bool, quiet: bool, uninstall_root: Option<&Path>) -> Result<()> {
    // One budget for the whole sweep. Each identity below waits only for what
    // is left of it, so this command's bound is the budget rather than the
    // budget multiplied by however many daemons happen to be running.
    //
    // Workers stop against an earlier deadline so the supervisor, which stops
    // last, cannot be starved by them. Without that reserve a single worker
    // riding its force-exit escalation leaves the supervisor a few seconds, and
    // a supervisor reported `timeout` fails the command exactly as loudly as
    // the hang this change exists to remove.
    let deadline = Instant::now() + stop_all_budget();
    let worker_deadline = deadline - SUPERVISOR_STOP_RESERVE;
    let mut reports: Vec<StopReport> = Vec::new();

    // A live supervisor is the only authoritative registry of every repo
    // worker. Missing/closed endpoint components and HTTP/auth/JSON failures
    // are hard errors, never an empty topology.
    let (sup_pid, sup_port) = supervisor_recorded_endpoint();
    let mut supervisor_identity = None;
    let mut daemons = Vec::new();
    if let Some(pid) = sup_pid {
        if !is_process_alive(pid) {
            remove_stale_supervisor_files();
        } else if let Some(identity) = supervisor_identity_for_stop(pid, uninstall_root)? {
            let port = require_supervisor_port_for_stop(
                pid,
                sup_port,
                sup_port.is_some_and(is_port_open),
            )?;
            let url = format!("http://127.0.0.1:{port}");
            daemons = fetch_registered_daemons(&url).await.with_context(|| {
                format!("failed to fetch the complete authenticated daemon topology from {url}")
            })?;
            supervisor_identity = Some(identity);
        } else {
            // The recorded owner is affirmatively gone (including PID reuse).
            // Never signal the process that now has the numeric PID.
            remove_stale_supervisor_files();
        }
    } else if (sup_port.is_some() || std::fs::symlink_metadata(supervisor_owner_path()).is_ok())
        && uninstall_root.is_none()
    {
        remove_stale_supervisor_files();
        if supervisor_recorded_endpoint() != (None, None)
            || std::fs::symlink_metadata(supervisor_owner_path()).is_ok()
        {
            bail!(
                "supervisor endpoint is incomplete: a live or indeterminate port/owner record exists without a valid PID"
            );
        }
    }

    // Full uninstall has retained startup authority. If an endpoint is
    // incomplete, its install-owned process scan below either attributes/stops
    // the owner-sidecar process or proves no managed supervisor remains.

    // During full uninstall, stop the supervisor first after snapshotting its
    // complete registry. Retained startup authority prevents a successor, and
    // the install-owned process scan below catches any worker spawned between
    // the registry snapshot and supervisor exit.
    if uninstall_root.is_some() {
        if let (Some(pid), Some(identity)) = (sup_pid, supervisor_identity.as_ref()) {
            let outcome = stop_supervisor_identity(identity, remaining_budget(deadline));
            reports.push(StopReport {
                kind: "supervisor",
                label: "supervisor".to_string(),
                pid,
                outcome,
            });
        }
    }

    for daemon in daemons {
        let label = if daemon.display_name.trim().is_empty() {
            daemon.repo_id.clone()
        } else {
            daemon.display_name.clone()
        };
        let kin_root = Path::new(&daemon.repo_root).join(".kin");
        let outcome = stop_worker_at(
            &kin_root,
            daemon.pid,
            remaining_budget(worker_deadline),
            uninstall_root,
        )?;
        if outcome.is_success() {
            remove_stale_daemon_files(&kin_root);
        }
        reports.push(StopReport {
            kind: "repo-daemon",
            label,
            pid: daemon.pid,
            outcome,
        });
    }

    // Also stop the current repo's worker if it is not registered with the
    // supervisor (e.g. supervisor down but a worker process lingering).
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(layout) = kin_core::KinLayout::discover(&cwd) {
            let kin_root = layout.root().to_path_buf();
            let (pid, _) = repo_daemon_recorded_endpoint(&kin_root);
            if let Some(pid) = pid {
                let already = reports.iter().any(|r| r.pid == pid);
                if !already && is_process_alive(pid) {
                    let working_dir = kin_root.parent().unwrap_or(&kin_root).to_path_buf();
                    let outcome = stop_worker_at(
                        &kin_root,
                        pid,
                        remaining_budget(worker_deadline),
                        uninstall_root,
                    )?;
                    if outcome.is_success() {
                        remove_stale_daemon_files(&kin_root);
                    }
                    reports.push(StopReport {
                        kind: "repo-daemon",
                        label: repo_label(&working_dir),
                        pid,
                        outcome,
                    });
                }
            }
        }
    }

    // The ordinary `kin daemon stop --all` path keeps the historical order:
    // workers first, supervisor last. Full uninstall already stopped it above.
    if uninstall_root.is_none() {
        if let (Some(pid), Some(identity)) = (sup_pid, supervisor_identity.as_ref()) {
            let outcome = stop_supervisor_identity(identity, remaining_budget(deadline));
            if outcome.is_success() {
                remove_stale_supervisor_files();
            }
            reports.push(StopReport {
                kind: "supervisor",
                label: "supervisor".to_string(),
                pid,
                outcome,
            });
        }
    }

    if let Some(install_root) = uninstall_root {
        stop_install_owned_daemons(install_root, deadline, &mut reports)?;
    }

    if reports.is_empty() {
        if quiet {
            // The absence of managed daemons is a successful precondition for
            // full uninstall and needs no nested command output.
        } else if json {
            let payload = serde_json::json!({
                "schema": "kin.daemon-stop.v1",
                "scope": "all",
                "stopped": [],
                "all_stopped": true,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("No Kin daemons running.");
        }
        return Ok(());
    }

    finish_stop_with_output("all", &reports, json, quiet)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagedDaemonKind {
    Supervisor,
    Worker { repo_root: PathBuf },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedDaemonProcess {
    pid: u32,
    kind: ManagedDaemonKind,
}

impl ManagedDaemonProcess {
    fn description(&self) -> String {
        match &self.kind {
            ManagedDaemonKind::Supervisor => format!("supervisor pid {}", self.pid),
            ManagedDaemonKind::Worker { repo_root } => {
                format!("worker pid {} for {}", self.pid, repo_root.display())
            }
            ManagedDaemonKind::Unknown => format!("unclassified kin-daemon pid {}", self.pid),
        }
    }
}

fn command_argument(args: &[String], flag: &str) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = args[index]
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value.to_string());
        }
        index += 1;
    }
    None
}

fn is_managed_daemon_executable(executable: Option<&Path>, managed_bin: &Path) -> bool {
    let Some(executable) = executable else {
        return false;
    };
    let Ok(executable) = executable.canonicalize() else {
        return false;
    };
    let name_matches = executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            #[cfg(windows)]
            {
                name.eq_ignore_ascii_case("kin-daemon.exe")
            }
            #[cfg(not(windows))]
            {
                name == "kin-daemon"
            }
        });
    name_matches && executable.parent() == Some(managed_bin)
}

fn managed_daemon_processes(install_root: &Path) -> Vec<ManagedDaemonProcess> {
    let Ok(managed_bin) = install_root
        .canonicalize()
        .and_then(|root| root.join("bin").canonicalize())
    else {
        // Ownership cannot be proven from a missing or unresolvable install
        // root. In particular, never recover by trusting argv spelling: a
        // lexical `bin/../../outside/kin-daemon.exe` prefix is not authority.
        return Vec::new();
    };
    let mut system = sysinfo::System::new_all();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut found = Vec::new();
    for (pid, process) in system.processes() {
        let pid = pid.as_u32();
        if pid == std::process::id() {
            continue;
        }
        let args = process
            .cmd()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if !is_managed_daemon_executable(process.exe(), &managed_bin) {
            continue;
        }
        let kind = if args.iter().any(|arg| arg == "--supervisor") {
            ManagedDaemonKind::Supervisor
        } else if let Some(repo_root) = command_argument(&args, "--repo") {
            ManagedDaemonKind::Worker {
                repo_root: PathBuf::from(repo_root),
            }
        } else {
            ManagedDaemonKind::Unknown
        };
        found.push(ManagedDaemonProcess { pid, kind });
    }
    found.sort_by_key(|process| process.pid);
    found
}

/// Mixed-version bridge for a daemon started before endpoint owner sidecars
/// existed. Exact install-owned executable provenance plus the expected role
/// and repo argument establishes the current incarnation; callers additionally
/// require the authenticated supervisor topology before using this identity.
/// A present-but-malformed sidecar never reaches this bridge.
fn legacy_managed_identity(
    install_root: &Path,
    pid: u32,
    expected_repo: Option<&Path>,
) -> Result<Option<ProcessIdentity>> {
    // Capture the incarnation before inspecting its executable/arguments. The
    // old order scanned one process and then captured whatever later reused
    // its PID, accidentally lending the predecessor's provenance to a
    // successor.
    let Some(identity) = process_identity(pid)
        .with_context(|| format!("failed to capture legacy daemon process identity {pid}"))?
    else {
        return Ok(None);
    };
    let expected_repo = expected_repo.map(canonical);
    let matched = managed_daemon_processes(install_root)
        .into_iter()
        .find(|process| {
            if process.pid != pid {
                return false;
            }
            match (&process.kind, &expected_repo) {
                (ManagedDaemonKind::Supervisor, None) => true,
                (ManagedDaemonKind::Worker { repo_root }, Some(expected)) => {
                    canonical(repo_root) == *expected
                }
                _ => false,
            }
        });
    if matched.is_none() {
        bail!(
            "legacy daemon pid {pid} is not an exact install-owned process with the expected role; refusing to signal it"
        );
    }
    if process_identity_is_current(&identity)? {
        Ok(Some(identity))
    } else {
        Ok(None)
    }
}

fn stop_install_owned_daemons(
    install_root: &Path,
    deadline: Instant,
    reports: &mut Vec<StopReport>,
) -> Result<()> {
    // Takes the sweep DEADLINE, not a remaining-budget snapshot. A snapshot is
    // re-spent by every process on every pass, so the real bound here would be
    // passes x processes x budget rather than the budget the caller meant.
    // Recomputing against the deadline keeps the whole sweep inside one bound.
    //
    // A second pass catches a worker spawned while the supervisor was exiting;
    // the retained startup authority means no successor supervisor can appear.
    for _ in 0..3 {
        let processes = managed_daemon_processes(install_root);
        if processes.is_empty() {
            return Ok(());
        }
        for process in processes {
            if reports
                .iter()
                .any(|report| report.pid == process.pid && !report.outcome.is_success())
            {
                continue;
            }
            if reports
                .iter()
                .any(|report| report.pid == process.pid && report.outcome.is_success())
                && !is_process_alive(process.pid)
            {
                continue;
            }
            match process.kind {
                ManagedDaemonKind::Worker { repo_root } => {
                    let kin_root = repo_root.join(".kin");
                    let outcome = stop_worker_at(
                        &kin_root,
                        process.pid,
                        remaining_budget(deadline),
                        Some(install_root),
                    )?;
                    if outcome.is_success() {
                        remove_stale_daemon_files(&kin_root);
                    }
                    reports.push(StopReport {
                        kind: "repo-daemon",
                        label: repo_label(&repo_root),
                        pid: process.pid,
                        outcome,
                    });
                }
                ManagedDaemonKind::Supervisor => {
                    let outcome = stop_supervisor_pid(
                        process.pid,
                        remaining_budget(deadline),
                        Some(install_root),
                    )?;
                    reports.push(StopReport {
                        kind: "supervisor",
                        label: "supervisor".to_string(),
                        pid: process.pid,
                        outcome,
                    });
                }
                ManagedDaemonKind::Unknown => bail!(
                    "full uninstall found install-owned kin-daemon pid {} but could not attribute it to a supervisor or repo worker",
                    process.pid
                ),
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let remaining = managed_daemon_processes(install_root);
    if !remaining.is_empty() {
        bail!(
            "install-owned Kin daemons survived shutdown: {}",
            remaining
                .iter()
                .map(ManagedDaemonProcess::description)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Emit the stop report and fail loud (nonzero exit) if any endpoint would not
/// die, so scripts can trust the exit code.
fn finish_stop(scope: &str, reports: &[StopReport], json: bool) -> Result<()> {
    finish_stop_with_output(scope, reports, json, false)
}

fn finish_stop_with_output(
    scope: &str,
    reports: &[StopReport],
    json: bool,
    quiet: bool,
) -> Result<()> {
    let all_stopped = reports.iter().all(|r| r.outcome.is_success());

    if quiet {
        // The caller owns user-facing output. We still evaluate every result
        // below and fail loud when a process survived the stop attempt.
    } else if json {
        let stopped: Vec<_> = reports
            .iter()
            .map(|r| {
                serde_json::json!({
                    "kind": r.kind,
                    "label": r.label,
                    "pid": r.pid,
                    "result": r.outcome.detail(),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "schema": "kin.daemon-stop.v1",
            "scope": scope,
            "stopped": stopped,
            "all_stopped": all_stopped,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        for r in reports {
            let line = match &r.outcome {
                StopOutcome::Stopped => format!("{} (pid {}): stopped", r.label, r.pid),
                StopOutcome::NotRunning => {
                    format!("{} (pid {}): was not running", r.label, r.pid)
                }
                StopOutcome::Timeout => format!(
                    "{} (pid {}): STILL ALIVE after stop request + {}s wait",
                    r.label,
                    r.pid,
                    stop_timeout().as_secs()
                ),
                StopOutcome::SignalFailed(err) => {
                    format!("{} (pid {}): stop request failed: {}", r.label, r.pid, err)
                }
            };
            println!("  {line}");
        }
        if all_stopped {
            println!("All targeted Kin daemons stopped.");
        }
    }

    if !all_stopped {
        let failed: Vec<String> = reports
            .iter()
            .filter(|r| !r.outcome.is_success())
            .map(|r| format!("{} (pid {})", r.label, r.pid))
            .collect();
        bail!(
            "one or more Kin daemons did not stop: {}",
            failed.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs;

    #[cfg(windows)]
    const WINDOWS_DAEMON_SCAN_CHILD: &str = "KIN_INTERNAL_TEST_WINDOWS_DAEMON_SCAN_CHILD";

    #[cfg(windows)]
    struct WindowsDaemonScanChild(std::process::Child);

    #[cfg(windows)]
    impl Drop for WindowsDaemonScanChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(windows)]
    fn spawn_windows_daemon_scan_child(executable: &Path) -> Result<WindowsDaemonScanChild> {
        let child = std::process::Command::new(executable)
            .args([
                "commands::daemon::tests::native_managed_daemon_scan_canonicalizes_and_rejects_traversal",
                "--exact",
                "--nocapture",
                "--",
                "--supervisor",
            ])
            .env(WINDOWS_DAEMON_SCAN_CHILD, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn native Windows daemon scan child {}",
                    executable.display()
                )
            })?;
        Ok(WindowsDaemonScanChild(child))
    }

    #[test]
    fn classify_liveness_covers_every_state() {
        // No pid recorded → nothing is running, regardless of the probes.
        assert_eq!(
            classify_liveness(None, false, false),
            DaemonLiveness::NotRunning
        );
        assert_eq!(
            classify_liveness(None, true, true),
            DaemonLiveness::NotRunning
        );
        // Recorded pid, dead process → stale files.
        assert_eq!(
            classify_liveness(Some(4219), false, false),
            DaemonLiveness::Stale
        );
        // A dead process is stale even if some unrelated process holds the port.
        assert_eq!(
            classify_liveness(Some(4219), false, true),
            DaemonLiveness::Stale
        );
        // Alive but port closed → unresponsive (starting up or wedged).
        assert_eq!(
            classify_liveness(Some(4219), true, false),
            DaemonLiveness::Unresponsive
        );
        // Alive and serving → running.
        assert_eq!(
            classify_liveness(Some(4219), true, true),
            DaemonLiveness::Running
        );
    }

    #[test]
    fn liveness_labels_are_distinct_and_stable() {
        let states = [
            DaemonLiveness::Running,
            DaemonLiveness::Unresponsive,
            DaemonLiveness::Stale,
            DaemonLiveness::NotRunning,
        ];
        for (i, a) in states.iter().enumerate() {
            for b in &states[i + 1..] {
                assert_ne!(a.label(), b.label(), "labels must be distinct");
            }
        }
        assert!(DaemonLiveness::Stale.is_stale());
        assert!(!DaemonLiveness::Running.is_stale());
    }

    #[test]
    fn live_supervisor_requires_a_complete_reachable_endpoint() {
        let missing = require_supervisor_port_for_stop(42, None, false).unwrap_err();
        assert!(missing.to_string().contains("no published port"));

        let closed = require_supervisor_port_for_stop(42, Some(51000), false).unwrap_err();
        assert!(closed.to_string().contains("unresponsive"));

        assert_eq!(
            require_supervisor_port_for_stop(42, Some(51000), true).unwrap(),
            51000
        );
    }

    #[test]
    fn uninstall_fence_excludes_a_concurrent_supervisor_restart() {
        let dir = tempfile::tempdir().unwrap();
        let _held = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap();
        let error = try_acquire_supervisor_startup_lock_in_dir(dir.path()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn recorded_endpoint_parsing_handles_good_absent_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let kin_root = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_root).unwrap();

        // Absent files → both components None.
        assert_eq!(repo_daemon_recorded_endpoint(&kin_root), (None, None));

        // Well-formed files (with surrounding whitespace) parse cleanly.
        std::fs::write(kin_root.join("daemon.pid"), "  12345\n").unwrap();
        std::fs::write(kin_root.join("daemon.port"), "51234\n").unwrap();
        assert_eq!(
            repo_daemon_recorded_endpoint(&kin_root),
            (Some(12345), Some(51234))
        );

        // Garbage / out-of-range values parse to None rather than panicking.
        std::fs::write(kin_root.join("daemon.pid"), "not-a-pid").unwrap();
        std::fs::write(kin_root.join("daemon.port"), "99999999").unwrap();
        assert_eq!(repo_daemon_recorded_endpoint(&kin_root), (None, None));
    }

    #[test]
    fn the_sweep_budget_cannot_be_consumed_by_one_wedged_daemon() {
        // The failure this closes: `--all` stops identities in sequence and the
        // supervisor goes last. A worker that rides its force-exit escalation
        // spends ~25.25s, and when the whole-sweep budget was the 30s
        // per-identity constant that left the supervisor 4.75s. A supervisor
        // reported `timeout` fails the command exactly as loudly as the hang
        // this change exists to remove, so the sweep has to clear one full
        // escalation AND still fund the tail.
        let budget = stop_all_budget();
        assert!(
            budget >= DAEMON_FORCE_EXIT_WORST_CASE + SUPERVISOR_STOP_RESERVE,
            "sweep budget {budget:?} must fund one full force-exit escalation \
             plus the supervisor reserve"
        );

        // What the sweep actually hands the supervisor after a worst-case
        // worker, computed the way `stop_all_inner` computes it.
        let sweep_start = Instant::now();
        let worker_deadline = (sweep_start + budget) - SUPERVISOR_STOP_RESERVE;
        let after_wedged_worker = sweep_start + DAEMON_FORCE_EXIT_WORST_CASE;
        assert!(
            worker_deadline >= after_wedged_worker,
            "a single wedged worker must not exhaust the workers' share"
        );
        let supervisor_share = (sweep_start + budget) - after_wedged_worker;
        assert!(
            supervisor_share >= SUPERVISOR_STOP_RESERVE,
            "supervisor was left {supervisor_share:?}, less than its reserve"
        );
    }

    #[test]
    fn stop_outcome_success_semantics() {
        assert!(StopOutcome::Stopped.is_success());
        assert!(StopOutcome::NotRunning.is_success());
        assert!(!StopOutcome::Timeout.is_success());
        assert!(!StopOutcome::SignalFailed("boom".to_string()).is_success());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn stop_identity_graceful_reports_not_running_for_dead_incarnation() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        let identity = process_identity(child.id()).unwrap().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let outcome = stop_identity_graceful(&identity, Duration::from_millis(50));
        assert_eq!(outcome, StopOutcome::NotRunning);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cooperative_incarnation_mismatch_never_authorizes_shutdown() {
        let identity = process_identity(std::process::id()).unwrap().unwrap();
        let delivered = std::cell::Cell::new(false);
        let outcome = stop_identity_cooperatively(&identity, Duration::from_millis(10), |_| {
            delivered.set(true);
            Ok(false)
        });
        assert_eq!(outcome, StopOutcome::NotRunning);
        assert!(
            delivered.get(),
            "the endpoint must receive the expected identity and reject the mismatch"
        );
    }

    #[test]
    fn fully_removed_gate_rejects_any_owned_process_inventory() {
        let error = verify_no_install_owned_processes(vec![ManagedDaemonProcess {
            pid: 4242,
            kind: ManagedDaemonKind::Worker {
                repo_root: PathBuf::from("/tmp/owned-repo"),
            },
        }])
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("refusing to report fully_removed"),
            "{message}"
        );
        assert!(message.contains("4242"), "{message}");
    }

    #[cfg(windows)]
    #[test]
    fn native_managed_daemon_scan_canonicalizes_and_rejects_traversal() -> Result<()> {
        if std::env::var_os(WINDOWS_DAEMON_SCAN_CHILD).is_some() {
            std::thread::sleep(Duration::from_secs(60));
            return Ok(());
        }

        let fixture = tempfile::tempdir()?;
        let install_root = fixture.path().join("install").join(".kin");
        let managed_bin = install_root.join("bin");
        let outside_bin = fixture.path().join("outside");
        fs::create_dir_all(&managed_bin)?;
        fs::create_dir_all(&outside_bin)?;

        let managed_executable = managed_bin.join("kin-daemon.exe");
        let outside_executable = outside_bin.join("kin-daemon.exe");
        fs::copy(std::env::current_exe()?, &managed_executable)?;
        fs::copy(std::env::current_exe()?, &outside_executable)?;

        let managed_child = spawn_windows_daemon_scan_child(&managed_executable)?;
        let traversal_executable = managed_bin
            .join("..")
            .join("..")
            .join("..")
            .join("outside")
            .join("kin-daemon.exe");
        let outside_child = spawn_windows_daemon_scan_child(&traversal_executable)?;

        let canonical_bin = managed_bin.canonicalize()?;
        anyhow::ensure!(
            is_managed_daemon_executable(Some(&managed_executable), &canonical_bin),
            "canonical managed executable was not recognized"
        );
        anyhow::ensure!(
            !is_managed_daemon_executable(Some(&traversal_executable), &canonical_bin),
            "a lexical managed-bin prefix with parent traversal was accepted"
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let found = managed_daemon_processes(&install_root);
            if found
                .iter()
                .any(|process| process.pid == managed_child.0.id())
            {
                anyhow::ensure!(
                    !found
                        .iter()
                        .any(|process| process.pid == outside_child.0.id()),
                    "daemon scan authorized an outside process through lexical traversal"
                );
                let mut reports = Vec::new();
                stop_install_owned_daemons(
                    &install_root,
                    Instant::now() + Duration::from_secs(5),
                    &mut reports,
                )?;
                anyhow::ensure!(
                    reports.iter().any(|report| {
                        report.pid == managed_child.0.id() && report.outcome.is_success()
                    }),
                    "uninstall sweep did not report a successful stop for the actual managed child"
                );
                anyhow::ensure!(
                    !is_process_alive(managed_child.0.id()),
                    "managed child remained alive after the uninstall sweep"
                );
                anyhow::ensure!(
                    is_process_alive(outside_child.0.id()),
                    "uninstall sweep signaled the outside traversal child"
                );
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "native Windows daemon scan did not discover the actual managed child"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn stop_identity_graceful_stops_a_live_process() {
        // Spawn a real process that sleeps, then prove SIGTERM stops it and the
        // wait observes the process actually gone.
        //
        // A SIGTERM'd *child* becomes a zombie until its parent reaps it, and
        // `kill(pid, 0)` still succeeds for a zombie — so we reap concurrently in
        // a background thread. In production this models reality rather than
        // hiding it: the daemon is never the stopping CLI's child (it is detached
        // with setsid and reparented to init), so init reaps it and
        // `is_process_alive` returns false the moment it dies.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        let pid = child.id();
        let identity = process_identity(pid).unwrap().unwrap();
        assert!(is_process_alive(pid));

        let reaper = std::thread::spawn(move || {
            let _ = child.wait();
        });
        let outcome = stop_identity_graceful(&identity, Duration::from_secs(10));
        let _ = reaper.join();

        assert_eq!(outcome, StopOutcome::Stopped);
    }
}
