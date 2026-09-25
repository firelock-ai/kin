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
//! Unix first requests cooperative shutdown of the recorded incarnation.
//! Signals additionally require the executing image recorded at publication.
//! Linux pins the incarnation with a pidfd; macOS rechecks before numeric
//! signals. Image checks are point-in-time, not atomic with delivery. Native
//! Windows retains its existing process-handle stop path.
//!
//! `--all` bounds the sweep, not just each step in it. Stopping identities in
//! sequence under a per-identity ceiling left the command's real bound
//! proportional to how many daemons happened to be running, so `stop --all`
//! could outlive its caller's patience and be killed before reporting anything.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::daemon_client::process_executable::{self, ExecutableIdentity};
use crate::daemon_client::{
    caller_home_id, connect_loopback_port, fetch_registered_daemons, is_process_alive,
    probe_daemon_port, process_identity, process_identity_is_current, read_endpoint_owner_record,
    read_supervisor_owner_record, remove_stale_daemon_files, remove_stale_supervisor_files,
    repo_daemon_owner_path, repo_daemon_pid_path, repo_daemon_port_path,
    repo_daemon_recorded_endpoint, retire_stopped_daemon_endpoint, supervisor_owner_path,
    supervisor_pid_path, supervisor_port_path, supervisor_recorded_endpoint,
    try_acquire_supervisor_startup_lock_in_dir, DaemonHomeScope, DaemonPortProbe,
    EndpointOwnerRecord, PreservedDaemonEndpoint, ProcessIdentity, RegisteredRepoDaemon,
    SupervisorStartupLock,
};

#[derive(Debug, Clone)]
struct AttributedStopTarget {
    owner: EndpointOwnerRecord,
    #[cfg(unix)]
    selected_install_image: Option<ExecutableIdentity>,
}

impl AttributedStopTarget {
    fn published(owner: EndpointOwnerRecord) -> Self {
        Self {
            owner,
            #[cfg(unix)]
            selected_install_image: None,
        }
    }

    #[cfg(unix)]
    fn expected_image(&self) -> std::io::Result<ExecutableIdentity> {
        match &self.selected_install_image {
            Some(image) => Ok(image.clone()),
            None => self.owner.executable_identity(),
        }
    }
}

impl std::ops::Deref for AttributedStopTarget {
    type Target = ProcessIdentity;

    fn deref(&self) -> &Self::Target {
        self.owner.identity()
    }
}

/// One validated process incarnation retained across every Unix signal stage.
/// Linux uses its pinned descriptor exclusively; macOS retains a documented
/// point-in-time image/incarnation check before its numeric signal.
#[cfg(unix)]
struct UnixSignalTarget {
    identity: ProcessIdentity,
    expected_image: ExecutableIdentity,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl UnixSignalTarget {
    fn open(target: &AttributedStopTarget) -> std::io::Result<Option<Self>> {
        Self::open_with_probe(target, process_identity_is_current)
    }

    fn open_with_probe(
        target: &AttributedStopTarget,
        mut probe: impl FnMut(&ProcessIdentity) -> std::io::Result<bool>,
    ) -> std::io::Result<Option<Self>> {
        if !probe(target)? {
            return Ok(None);
        }
        let expected_image = target.expected_image()?;
        #[cfg(target_os = "linux")]
        let pidfd = {
            use std::os::fd::FromRawFd;
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target.pid(), 0) as libc::c_int };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                return if !probe(target)? {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            // Own immediately: any subsequent identity/image failure must
            // close the descriptor, including an error from the probe itself.
            unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
        };
        if !probe(target)? {
            return Ok(None);
        }
        Ok(Some(Self {
            identity: target.owner.identity().clone(),
            expected_image,
            #[cfg(target_os = "linux")]
            pidfd,
        }))
    }

    fn send(&self, signal: libc::c_int, deadline: Instant) -> std::io::Result<bool> {
        self.send_with(
            signal,
            deadline,
            process_identity_is_current,
            process_executable::observe,
        )
    }

    /// [`send`](Self::send) with its two host readers injected.
    ///
    /// A recorded process can stop inside the microseconds between the
    /// incarnation probe and the image read, and what that failure is
    /// classified as decides whether a stop reports a verdict or reports
    /// nothing. Waiting for the host to land in that window is not a test, so
    /// the readers are parameters here and the real ones are what `send`
    /// passes.
    fn send_with(
        &self,
        signal: libc::c_int,
        deadline: Instant,
        mut probe: impl FnMut(&ProcessIdentity) -> std::io::Result<bool>,
        observe: impl FnOnce(u32, Instant) -> std::io::Result<ExecutableIdentity>,
    ) -> std::io::Result<bool> {
        if !probe(&self.identity)? {
            return Ok(false);
        }
        let actual = match observe(self.identity.pid(), deadline) {
            Ok(actual) => actual,
            Err(error) => {
                // A process that stopped between the probe above and this read
                // publishes no image to compare against: Linux drops
                // `/proc/PID/exe` the moment it stops running, including while
                // it is a corpse its parent has not reaped, so the read fails
                // rather than answering. Re-probe the recorded incarnation and
                // report it gone, which is what it is, instead of an
                // unclassifiable stop. A process still running its recorded
                // incarnation keeps the error, so an image this stop may not
                // signal still refuses. No signal is sent on either path.
                if !probe(&self.identity)? {
                    return Ok(false);
                }
                return Err(error);
            }
        };
        if actual != self.expected_image {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the recorded process is no longer executing its published image; refusing to signal it",
            ));
        }
        if !probe(&self.identity)? {
            return Ok(false);
        }
        process_executable::check_deadline(deadline)?;
        #[cfg(target_os = "linux")]
        let rc = {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                ) as libc::c_int
            }
        };
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::kill(self.identity.pid() as libc::pid_t, signal) };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = signal;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "executable-bound process signals are unavailable on this platform",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    }
}

/// Liveness of a recorded daemon/supervisor endpoint. Pure classification of the
/// recorded pid plus the observed process/port state, so the policy is testable
/// without a live process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLiveness {
    /// Recorded process is alive and answered on its port.
    Running,
    /// Recorded process is alive and something holds its port, but the
    /// connection was never accepted. That is what a full accept queue looks
    /// like from outside: the socket is open and nothing is calling accept.
    NotAccepting,
    /// Recorded process is alive, the connection was accepted, and no HTTP
    /// answer came back.
    NotAnswering,
    /// Recorded process is alive but nothing holds its port: still starting
    /// up, or it lost the socket.
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
            DaemonLiveness::NotAccepting => {
                "wedged (process alive, socket open, connection not accepted)"
            }
            DaemonLiveness::NotAnswering => "wedged (process alive, socket open, no answer)",
            DaemonLiveness::Unresponsive => {
                "unresponsive (process alive, nothing listening on the port)"
            }
            DaemonLiveness::Stale => "stale (recorded process is gone)",
            DaemonLiveness::NotRunning => "not running",
        }
    }

    fn is_stale(self) -> bool {
        matches!(self, DaemonLiveness::Stale)
    }

    /// Whether the process is alive and this state says the daemon cannot be
    /// talked to. `kin daemon stop` attempts an attributed shutdown in these
    /// states and reports when the recorded process cannot be stopped.
    fn is_wedged(self) -> bool {
        matches!(
            self,
            DaemonLiveness::NotAccepting | DaemonLiveness::NotAnswering
        )
    }
}

/// Classify liveness from the recorded pid and the observed process/port state.
///
/// `process_alive` and `port` are only meaningful when `pid` is `Some`. A
/// recorded endpoint with no port at all probes as
/// [`DaemonPortProbe::Closed`], which is the same verdict a refused connect
/// earns and the same one this returned before the probe could tell them apart.
pub fn classify_liveness(
    pid: Option<u32>,
    process_alive: bool,
    port: DaemonPortProbe,
) -> DaemonLiveness {
    match pid {
        None => DaemonLiveness::NotRunning,
        Some(_) if !process_alive => DaemonLiveness::Stale,
        Some(_) => match port {
            DaemonPortProbe::Answering => DaemonLiveness::Running,
            DaemonPortProbe::AcceptedNotAnswering => DaemonLiveness::NotAnswering,
            DaemonPortProbe::OpenNotAccepting => DaemonLiveness::NotAccepting,
            DaemonPortProbe::Closed => DaemonLiveness::Unresponsive,
        },
    }
}

/// Probe a recorded endpoint's port, or report `Closed` when none is recorded.
fn probe_recorded_port(port: Option<u16>) -> DaemonPortProbe {
    port.map(probe_daemon_port)
        .unwrap_or(DaemonPortProbe::Closed)
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
///
/// [`ESCALATION_SIGKILL_WAIT`] is in it because a wedged worker is exactly what
/// `--all` has to survive. The signal escalation below can now spend that on
/// top of the daemon's own bound, and without room for it here the first wedged
/// worker would again consume the supervisor's reserve.
fn stop_all_budget() -> Duration {
    DAEMON_FORCE_EXIT_WORST_CASE
        .saturating_add(ESCALATION_SIGKILL_WAIT)
        .saturating_add(SUPERVISOR_STOP_RESERVE)
        .max(stop_timeout())
}

/// Budget left before `deadline`.
///
/// For ordinary explicit stop, zero does not skip an identity: the request is delivered,
/// and only the wait for the process to disappear is what the exhausted budget
/// gives up. The identity is then reported `timeout`, which is the honest
/// outcome, since the request went out and this command did not stay to watch.
/// Retirement instead carries the absolute deadline and refuses unsent requests
/// once it expires, because it has no authority to force a worker down.
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
    /// Asked to retire (`--when-unused`), the daemon is still needed, so it was
    /// left running. It exits on its own once what it named has ended.
    InUse(Vec<String>),
}

impl StopOutcome {
    /// Whether this outcome leaves nothing alive: a clean stop or an
    /// already-dead process both satisfy "it is not running".
    fn is_success(&self) -> bool {
        matches!(self, StopOutcome::NotRunning | StopOutcome::Stopped)
    }

    /// Whether this outcome is what the stop was entitled to. A daemon left
    /// running because it is still in use is the correct answer to a
    /// `--when-unused` stop, never a failure, and never a reason to escalate.
    fn is_settled(&self) -> bool {
        self.is_success() || matches!(self, StopOutcome::InUse(_))
    }

    fn detail(&self) -> &str {
        match self {
            StopOutcome::NotRunning => "not-running",
            StopOutcome::Stopped => "stopped",
            StopOutcome::Timeout => "timeout",
            StopOutcome::SignalFailed(_) => "signal-failed",
            StopOutcome::InUse(_) => "in-use",
        }
    }
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
#[cfg(not(unix))]
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

#[cfg(unix)]
fn stop_identity_cooperatively<F>(
    identity: &ProcessIdentity,
    wait: Duration,
    request_shutdown: F,
) -> StopOutcome
where
    F: FnOnce(&ProcessIdentity, Instant) -> std::io::Result<bool>,
{
    if matches!(process_identity_is_current(identity), Ok(false)) {
        return StopOutcome::NotRunning;
    }
    let deadline = Instant::now() + wait;
    match request_shutdown(identity, deadline) {
        Ok(false) => return StopOutcome::NotRunning,
        Ok(true) => {}
        Err(error) => {
            if matches!(process_identity_is_current(identity), Ok(false)) {
                return StopOutcome::NotRunning;
            }
            return StopOutcome::SignalFailed(error.to_string());
        }
    }
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

#[cfg(unix)]
fn cooperative_shutdown_request(
    port: u16,
    token: Option<String>,
    identity: &ProcessIdentity,
    deadline: Instant,
) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    process_executable::check_deadline(deadline)?;
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr,
        remaining_budget(deadline).min(Duration::from_secs(2)),
    )?;
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
    let mut request = head.into_bytes();
    request.extend(body);
    while !request.is_empty() {
        process_executable::check_deadline(deadline)?;
        stream.set_write_timeout(Some(remaining_budget(deadline).min(Duration::from_secs(5))))?;
        let written = stream.write(&request)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "shutdown request write returned zero",
            ));
        }
        request.drain(..written);
    }
    let mut response = Vec::new();
    // Bound both bytes and elapsed time even if a peer trickles a response.
    while response.len() < 16 * 1024 {
        process_executable::check_deadline(deadline)?;
        stream.set_read_timeout(Some(remaining_budget(deadline).min(Duration::from_secs(5))))?;
        let mut bytes = [0_u8; 1024];
        let count = stream.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&bytes[..count]);
        if response.contains(&b'\n') {
            break;
        }
    }
    process_executable::check_deadline(deadline)?;
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("invalid cooperative shutdown HTTP response"))?;
    match status {
        200..=299 => Ok(true),
        409 | 410 => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cooperative shutdown endpoint does not own the recorded process incarnation",
        )),
        _ => Err(std::io::Error::other(format!(
            "cooperative shutdown endpoint returned HTTP {status}"
        ))),
    }
}

#[cfg(unix)]
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
    let token = worker_auth_token(kin_root);
    stop_identity_cooperatively(identity, wait, |expected, deadline| {
        cooperative_shutdown_request(port, token, expected, deadline)
    })
}

/// The bearer token a request to this repository's worker carries, if any.
fn worker_auth_token(kin_root: &Path) -> Option<String> {
    std::env::var("KIN_DAEMON_AUTH_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::fs::read_to_string(kin_root.join("daemon.token"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
}

/// How long a `--when-unused` stop waits for a daemon it asked to retire.
///
/// A retiring daemon checks every 100 milliseconds and flushes its graph
/// before it exits, so one that is free to go is gone well inside this. One
/// still needed after it is left running and named, which is the answer and
/// not a timeout.
const RETIRE_EXIT_WAIT: Duration = Duration::from_secs(10);

/// Ask a worker to exit as soon as nothing needs it, and report whether it has.
///
/// Never escalates, which is the whole difference from `stop_worker_at`: a
/// daemon still serving a client, running enrichment or embedding, or holding
/// a write it has not flushed stays up, says which, and exits by itself once
/// that ends.
async fn retire_worker_at(kin_root: &Path, pid: u32, deadline: Instant) -> Result<StopOutcome> {
    let Some(identity) = attributed_worker_identity(kin_root, pid)? else {
        return Ok(StopOutcome::NotRunning);
    };
    let (recorded_pid, recorded_port) = repo_daemon_recorded_endpoint(kin_root);
    if recorded_pid != Some(identity.pid()) {
        return Ok(StopOutcome::SignalFailed(format!(
            "worker endpoint changed before the retirement request for pid {pid}"
        )));
    }
    let Some(port) = recorded_port else {
        return Ok(StopOutcome::SignalFailed(format!(
            "worker pid {pid} has no recorded port to ask it to retire"
        )));
    };
    let blocked_by =
        match request_worker_retirement(port, worker_auth_token(kin_root), &identity, deadline)
            .await
        {
            Ok(blocked_by) => blocked_by,
            Err(error) => return Ok(StopOutcome::SignalFailed(error)),
        };
    // A daemon that named something it is waiting on is not going to be free
    // in seconds, so it gets one second to catch a request that was about to
    // finish; one that named nothing gets the time an exit and a flush take.
    let window = if blocked_by.is_empty() {
        RETIRE_EXIT_WAIT
    } else {
        Duration::from_secs(1)
    };
    let deadline = deadline.min(Instant::now() + window);
    loop {
        if matches!(process_identity_is_current(&identity), Ok(false)) {
            return Ok(StopOutcome::Stopped);
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(remaining_budget(deadline).min(Duration::from_millis(50))).await;
    }
    Ok(StopOutcome::InUse(if blocked_by.is_empty() {
        vec!["it has not finished exiting yet".to_string()]
    } else {
        blocked_by
    }))
}

/// Send `POST /retire` to a worker and return what it said it is waiting on.
async fn request_worker_retirement(
    port: u16,
    token: Option<String>,
    identity: &ProcessIdentity,
    deadline: Instant,
) -> std::result::Result<Vec<String>, String> {
    let remaining = remaining_budget(deadline);
    if remaining.is_zero() {
        return Err("retirement deadline exhausted before a request could be sent".to_string());
    }
    // Headers, body and exit observation share the caller's original budget.
    // In a sweep an exhausted worker must not receive a new per-request wait.
    let client = reqwest::Client::builder()
        .timeout(remaining.min(Duration::from_secs(5)))
        .connect_timeout(remaining.min(Duration::from_secs(2)))
        .build()
        .map_err(|error| format!("could not build the retirement request: {error}"))?;
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let mut request = client
            .post(format!("http://127.0.0.1:{port}/retire"))
            .json(identity);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("the retirement request did not reach the daemon: {error}"))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(
                "this daemon predates retirement requests; stop it with `kin daemon stop` instead"
                    .to_string(),
            );
        }
        if status == reqwest::StatusCode::CONFLICT || status == reqwest::StatusCode::GONE {
            return Err(
                "the retirement endpoint does not own the recorded process incarnation".to_string(),
            );
        }
        if !status.is_success() {
            return Err(format!("the retirement endpoint returned HTTP {status}"));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| format!("the retirement answer was not JSON: {error}"))?;
        Ok(body
            .get("blocked_by")
            .and_then(serde_json::Value::as_array)
            .map(|reasons| {
                reasons
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    })
    .await
    .map_err(|_| "retirement deadline exhausted before the answer completed".to_string())?
}

#[cfg(not(unix))]
fn stop_worker_identity(
    _kin_root: &Path,
    identity: &ProcessIdentity,
    wait: Duration,
) -> StopOutcome {
    stop_identity_graceful(identity, wait)
}

#[cfg(unix)]
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
    stop_identity_cooperatively(identity, wait, |expected, deadline| {
        cooperative_shutdown_request(port, token, expected, deadline)
    })
}

#[cfg(not(unix))]
fn stop_supervisor_identity(identity: &ProcessIdentity, wait: Duration) -> StopOutcome {
    stop_identity_graceful(identity, wait)
}

fn attributed_worker_identity(kin_root: &Path, pid: u32) -> Result<Option<AttributedStopTarget>> {
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
        Ok(true) => Ok(Some(AttributedStopTarget::published(owner))),
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

fn attributed_supervisor_identity(pid: u32) -> Result<Option<AttributedStopTarget>> {
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
        Ok(true) => Ok(Some(AttributedStopTarget::published(owner))),
        Ok(false) => Ok(None),
        Err(error) => Err(error).context("could not verify supervisor process incarnation"),
    }
}

// ── escalation ──────────────────────────────────────────────────────────────

/// How long the escalation waits after `SIGTERM` before reaching for
/// `SIGKILL`.
///
/// [`DAEMON_FORCE_EXIT_WORST_CASE`], because that is the daemon's own bound for
/// a shutdown it has begun. Its signal handler sets the shutdown flag, its
/// escalation watchdog force-exits about 25s later, and that watchdog flushes
/// the store on the way out. A shorter wait would `SIGKILL` a daemon that was
/// about to exit cleanly and throw the flush away. Measured on the recorded
/// wedge: a hand-sent `kill -TERM` took about twenty seconds to take effect,
/// inside this window, and the store was correct and complete afterwards.
#[cfg(unix)]
const ESCALATION_SIGTERM_WAIT: Duration = DAEMON_FORCE_EXIT_WORST_CASE;

/// How long the escalation waits after `SIGKILL` before reporting the pid as
/// surviving. `SIGKILL` can be neither handled nor ignored, so this covers only
/// the kernel tearing down an address space, which for a daemon holding a
/// multi-gigabyte graph is not instant.
const ESCALATION_SIGKILL_WAIT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for a signalled process to disappear. The same
/// 50ms the cooperative and graceful waits use.
#[cfg(unix)]
const ESCALATION_POLL: Duration = Duration::from_millis(50);

/// Whether the recorded incarnation is gone, polled until `window` expires.
#[cfg(unix)]
fn wait_for_recorded_exit(identity: &ProcessIdentity, window: Duration) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if matches!(process_identity_is_current(identity), Ok(false)) {
            return true;
        }
        if Instant::now() >= deadline {
            return matches!(process_identity_is_current(identity), Ok(false));
        }
        std::thread::sleep(ESCALATION_POLL);
    }
}

/// Escalate only with the executable evidence recorded at publication (or the
/// explicit uninstall-only installation proof). A name which happens to look
/// like Kin is not signal authority. Retain one Linux pidfd across both stages.
#[cfg(unix)]
fn escalate_to_recorded_pid(
    target: &AttributedStopTarget,
    sigterm_wait: Duration,
    sigkill_wait: Duration,
    steps: &mut Vec<String>,
) -> Option<StopOutcome> {
    let pid = target.pid();
    // Executable observation consumes this stage's existing budget, rather
    // than adding an unbounded read/hash before either wait. Preserve the full
    // TERM grace after delivery; observation reduces the final KILL wait.
    let deadline = Instant::now() + sigterm_wait.saturating_add(sigkill_wait);
    let signal_target = match UnixSignalTarget::open(target) {
        Ok(Some(target)) => target,
        Ok(None) => return Some(StopOutcome::NotRunning),
        Err(error) => {
            steps.push(format!("did not signal pid {pid}: {error}"));
            return None;
        }
    };
    let term_deadline = deadline.checked_sub(sigterm_wait).unwrap_or(deadline);
    match signal_target.send(libc::SIGTERM, term_deadline) {
        Ok(true) => steps.push(format!("sent SIGTERM to the recorded daemon pid {pid}")),
        Ok(false) => return Some(StopOutcome::NotRunning),
        Err(error) => {
            steps.push(format!(
                "did not signal pid {pid}: SIGTERM refused ({error})"
            ));
            return None;
        }
    }
    if wait_for_recorded_exit(target, sigterm_wait) {
        steps.push(format!("pid {pid} exited after SIGTERM"));
        return Some(StopOutcome::Stopped);
    }
    steps.push(format!(
        "pid {pid} was still alive {:.1}s after SIGTERM",
        sigterm_wait.as_secs_f64()
    ));
    // An exec may preserve PID and birth identity. Re-observe the actual image
    // as well as the incarnation before the non-cooperative final signal.
    match signal_target.send(libc::SIGKILL, deadline) {
        Ok(true) => steps.push(format!("sent SIGKILL to the recorded daemon pid {pid}")),
        Ok(false) => return Some(StopOutcome::Stopped),
        Err(error) => {
            steps.push(format!("did not send SIGKILL to pid {pid}: {error}"));
            return None;
        }
    }
    if wait_for_recorded_exit(target, remaining_budget(deadline)) {
        steps.push(format!("pid {pid} exited after SIGKILL"));
        Some(StopOutcome::Stopped)
    } else {
        steps.push(format!("pid {pid} survived the remaining SIGKILL wait"));
        Some(StopOutcome::Timeout)
    }
}

/// Escalate a stop the daemon's own endpoint could not complete, and say what
/// was done.
///
/// Windows has nothing to escalate to: its stop is already `TerminateProcess`
/// through a pinned handle.
fn escalate_if_unstopped(
    identity: &AttributedStopTarget,
    outcome: StopOutcome,
    steps: &mut Vec<String>,
) -> StopOutcome {
    // A daemon still in use was asked to retire, not to stop. Signalling it
    // would take it out from under the client the request just deferred to.
    if outcome.is_settled() {
        return outcome;
    }
    #[cfg(unix)]
    {
        match &outcome {
            StopOutcome::SignalFailed(error) => steps.push(format!(
                "the stop request did not reach the daemon: {error}"
            )),
            StopOutcome::Timeout => steps.push(format!(
                "the daemon took the stop request and did not exit within {}s",
                stop_timeout().as_secs()
            )),
            _ => {}
        }
        if let Some(escalated) = escalate_to_recorded_pid(
            identity,
            ESCALATION_SIGTERM_WAIT,
            ESCALATION_SIGKILL_WAIT,
            steps,
        ) {
            return escalated;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (identity, &steps);
    }
    outcome
}

/// Stop the supervisor and escalate to its recorded pid if the request fails.
fn stop_supervisor_attributed(
    identity: &AttributedStopTarget,
    wait: Duration,
    steps: &mut Vec<String>,
) -> StopOutcome {
    let outcome = stop_supervisor_identity(identity, wait);
    escalate_if_unstopped(identity, outcome, steps)
}

fn stop_worker_at(
    kin_root: &Path,
    pid: u32,
    wait: Duration,
    legacy_install_root: Option<&Path>,
    steps: &mut Vec<String>,
) -> Result<StopOutcome> {
    let deadline = Instant::now() + wait;
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
                deadline.min(Instant::now() + Duration::from_secs(5)),
            )
            .with_context(|| format!("legacy worker attribution failed after: {error:#}"))?
        }
        Err(error) => return Err(error),
    };
    Ok(match identity {
        Some(identity) => {
            #[cfg(unix)]
            let wait = remaining_budget(deadline);
            let outcome = stop_worker_identity(kin_root, &identity, wait);
            escalate_if_unstopped(&identity, outcome, steps)
        }
        None => StopOutcome::NotRunning,
    })
}

fn supervisor_identity_for_stop(
    pid: u32,
    legacy_install_root: Option<&Path>,
    deadline: Instant,
) -> Result<Option<AttributedStopTarget>> {
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
                deadline.min(Instant::now() + Duration::from_secs(5)),
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
    steps: &mut Vec<String>,
) -> Result<StopOutcome> {
    let deadline = Instant::now() + wait;
    let identity = supervisor_identity_for_stop(pid, legacy_install_root, deadline)?;
    #[cfg(unix)]
    let wait = remaining_budget(deadline);
    Ok(match identity {
        Some(identity) => stop_supervisor_attributed(&identity, wait, steps),
        None => StopOutcome::NotRunning,
    })
}

/// The supervisor URL if a live supervisor is recorded, without ever spawning
/// one. `status` and `stop` must observe the running topology, not create it.
fn supervisor_url_if_running() -> Option<String> {
    let (pid, port) = supervisor_recorded_endpoint();
    let (pid, port) = (pid?, port?);
    if is_process_alive(pid) && connect_loopback_port(port).is_open() {
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
    let sup_port_probe = probe_recorded_port(sup_port);
    let sup_state = classify_liveness(sup_pid, sup_alive, sup_port_probe);

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
    // Whether the supervisor's registry holds the current repository's daemon.
    // One started outside it is running all the same and is still reported.
    let supervised = current
        .as_ref()
        .and_then(|current| current.pid)
        .is_some_and(|pid| daemons.iter().any(|daemon| daemon.pid == pid));

    // The supervisor is machine-wide, so this listing can span managed homes.
    // Every entry is labelled with the home it belongs to and whether that is
    // the caller's, which is what makes a pinned session able to see which
    // daemons are its own.
    let caller_home = caller_home_id();

    if json {
        let daemons_json: Vec<_> = daemons
            .iter()
            .map(|d| {
                let alive = is_process_alive(d.pid);
                let state = classify_liveness(Some(d.pid), alive, probe_daemon_port(d.port));
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
                    "kin_home": d.kin_home,
                    "home_scope": home_scope_label(d.home_scope(&caller_home)),
                })
            })
            .collect();
        let payload = serde_json::json!({
            "schema": "kin.daemon-status.v1",
            "caller_kin_home": caller_home,
            "supervisor": {
                "state": sup_state.label(),
                "pid": sup_pid,
                "port": sup_port,
                "pid_file": supervisor_pid_path().display().to_string(),
                "port_file": supervisor_port_path().display().to_string(),
                "scope": "machine",
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
                "serving_since_unix": c.serving_since_unix,
                "supervised": supervised,
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
    println!("  scope:     machine-wide (one per machine, not per KIN_HOME)");
    if sup_state.is_stale() {
        println!("  note: supervisor endpoint files are stale; run `kin daemon stop --all` to clear them");
    }
    println!("  this KIN_HOME: {caller_home}");

    println!();
    if supervisor_url.is_none() {
        println!("Repo daemons: unavailable (supervisor not running)");
    } else if daemons.is_empty() {
        println!("Repo daemons: none registered");
    } else {
        println!("Repo daemons ({}):", daemons.len());
        for daemon in &daemons {
            let alive = is_process_alive(daemon.pid);
            let state = classify_liveness(Some(daemon.pid), alive, probe_daemon_port(daemon.port));
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
            println!(
                "    kin home:  {} ({})",
                daemon.home_label(),
                home_scope_label(daemon.home_scope(&caller_home))
            );
            if !daemon.last_heartbeat_at.trim().is_empty() {
                println!("    heartbeat: {}", daemon.last_heartbeat_at);
            }
        }
    }

    if let Some(current) = current {
        println!();
        println!("{}", current_repo_line(&current, supervised));
        if current.state.is_stale() {
            println!("  note: endpoint files are stale; `kin daemon stop` will clear them");
        }
        if current.state.is_wedged() {
            println!(
                "  note: the process is alive and still holds its socket but is not serving; \
                 `kin daemon stop` attempts shutdown and reports whether the recorded process could be stopped"
            );
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
    /// When the daemon began serving this store, from the serving record it
    /// publishes, and only when that record names the recorded pid.
    serving_since_unix: Option<u64>,
}

fn current_repo_status() -> Option<CurrentRepoStatus> {
    let cwd = std::env::current_dir().ok()?;
    let layout = kin_core::KinLayout::discover(&cwd)?;
    let kin_root = layout.root();
    let working_dir = kin_root.parent().unwrap_or(kin_root);
    let (pid, port) = repo_daemon_recorded_endpoint(kin_root);
    let alive = pid.map(is_process_alive).unwrap_or(false);
    let state = classify_liveness(pid, alive, probe_recorded_port(port));
    let serving_since_unix = kin_daemon_spawn::read_serving_daemon(kin_root)
        .filter(|serving| Some(serving.pid) == pid)
        .map(|serving| serving.at_unix);
    Some(CurrentRepoStatus {
        label: repo_label(working_dir),
        repo_root: canonical(working_dir),
        state,
        pid,
        port,
        pid_file: repo_daemon_pid_path(kin_root).display().to_string(),
        port_file: repo_daemon_port_path(kin_root).display().to_string(),
        serving_since_unix,
    })
}

/// The line naming this repository's own worker daemon.
///
/// The pid and port are the pair an operator checks by hand, and the serving
/// record says since when. A daemon started as `kin-daemon --repo <path>` is
/// in no registry the supervisor serves, so the listing above this line never
/// shows it and this line is the only place it appears. It says so, rather
/// than leave that listing to read as everything that is running.
fn current_repo_line(current: &CurrentRepoStatus, supervised: bool) -> String {
    let mut line = format!(
        "Current repo ({}): worker daemon {}",
        current.label,
        current.state.label()
    );
    if !matches!(
        current.state,
        DaemonLiveness::Running | DaemonLiveness::Unresponsive
    ) && !current.state.is_wedged()
    {
        return line;
    }
    let mut facts = Vec::new();
    if let Some(pid) = current.pid {
        facts.push(format!("pid {pid}"));
    }
    if let Some(port) = current.port {
        facts.push(format!("port {port}"));
    }
    if let Some(since) = current.serving_since_unix.and_then(utc_minute) {
        facts.push(format!("serving since {since}"));
    }
    if !facts.is_empty() {
        line.push_str(&format!(" ({})", facts.join(", ")));
    }
    if !supervised {
        line.push_str(
            "; it is not in the supervisor's registry, so the listing above does not show it",
        );
    }
    line
}

/// A unix time as the minute it names, with its date, in UTC.
fn utc_minute(unix: u64) -> Option<String> {
    let at = chrono::DateTime::from_timestamp(i64::try_from(unix).ok()?, 0)?;
    Some(at.format("%Y-%m-%d %H:%MZ").to_string())
}

// ── stop ────────────────────────────────────────────────────────────────────

/// Which daemons a `--all` sweep is entitled to stop.
///
/// The supervisor is a machine-level singleton: its directory comes from
/// `supervisor_root()`, which resolves from the real home, while `KIN_HOME`
/// moves store and install state, the cross-repo registry included. One
/// supervisor therefore holds daemons from several managed homes, and an
/// unscoped `--all` reaches every one of them.
/// That is how a pinned session stopped daemons it did not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopScope {
    /// Only daemons recording the caller's managed home. The default, because
    /// pinning `KIN_HOME` reads everywhere else as "bound to my own state".
    Home,
    /// Every daemon this supervisor knows about, whichever home it belongs to.
    /// The operator gesture, and it names what it is taking down.
    Machine,
}

impl StopScope {
    fn label(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Machine => "machine",
        }
    }
}

/// How a stop treats a daemon something still needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopMode {
    /// Stop it now, draining and flushing on the way out. What `kin daemon
    /// stop` has always done.
    Now,
    /// Ask it to exit as soon as nothing needs it, and leave it running, named,
    /// while an attached client, a request in flight, a pending write, or
    /// running enrichment or embedding still does. Never escalates to a signal.
    WhenUnused,
}

impl StopMode {
    fn keeps_supervisor_for(self, outcome: &StopOutcome) -> bool {
        match self {
            Self::WhenUnused => !outcome.is_success(),
            Self::Now => matches!(outcome, StopOutcome::InUse(_)),
        }
    }
}

/// `kin daemon stop` — gracefully stop the current repo's worker daemon, or with
/// `--all` every worker under this managed home plus the supervisor (supervisor
/// last). `--machine` widens the sweep to the whole box. `--when-unused` stops
/// only what nothing needs and names the rest.
pub async fn stop(all: bool, machine: bool, when_unused: bool, json: bool) -> Result<()> {
    let mode = if when_unused {
        StopMode::WhenUnused
    } else {
        StopMode::Now
    };
    if all {
        let scope = if machine {
            StopScope::Machine
        } else {
            StopScope::Home
        };
        stop_all(scope, json, false, mode).await
    } else {
        stop_current_repo(json, false, None, mode).await
    }
}

/// How long `kin daemon sweep` waits for a sweep before handing the repository
/// back anyway.
///
/// The same budget `kin init` gives its own sweep, for the same reason: a
/// language server can hang, and the sweep is resumable, so what this cuts
/// short the next daemon start continues.
const SWEEP_WAIT_BUDGET: Duration = Duration::from_secs(900);

/// How often the wait re-reads sweep progress.
const SWEEP_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Ask this repository's daemon for a language-server enrichment sweep, and by
/// default wait for it. This is `kin daemon sweep`.
///
/// `POST /lsp/sweep` has existed since enrichment did, and until now nothing on
/// the command line reached it. That mattered because the sweep is how a store
/// gets its cross-file reference, override and type-use edges, and every other
/// way of asking for one is implicit: `kin init` runs one, and a daemon queues
/// one when it starts. A store whose sweep died with its daemon, or whose
/// conversion ran before a language server was installed, therefore had a
/// recovery path that existed in the daemon and could not be asked for.
///
/// Loud when no daemon answers, rather than quietly doing nothing: a command
/// whose whole purpose is to make enrichment happen must never exit zero having
/// enriched nothing.
pub async fn sweep(no_wait: bool, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let base_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("daemon sweep", &layout))?;
    // FOR_LAYOUT, because the plain constructor resolves the bearer token from
    // the PROCESS working directory. This command is about the repository the
    // layout names, and its `.kin` is where that daemon's token lives.
    let client = crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, &layout)?;

    let queued = client
        .queue_lsp_sweep()
        .await
        .context("ask the daemon for a language-server sweep")?;

    // The daemon's own words, not a paraphrase. `status` distinguishes a sweep
    // this call queued from one that was already running, and
    // `enrichment_available` is false on a daemon that found no language
    // server, which is a different problem with a different fix.
    if json {
        println!("{}", serde_json::to_string_pretty(&queued)?);
    } else {
        println!("daemon: {queued}");
    }

    if queued.get("enrichment_available").and_then(|v| v.as_bool()) == Some(false) {
        bail!(
            "this daemon found no language server, so it can produce no cross-file reference \
             edges. Install one with `kin doctor --fix --install-language-servers`, then \
             `kin daemon stop` and run this again."
        );
    }

    if no_wait {
        return Ok(());
    }

    let baseline = queued
        .get("sweeps_completed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    wait_for_sweep(&client, baseline, json).await
}

/// Poll the sweep to completion, or to the budget, reporting progress.
async fn wait_for_sweep(
    client: &crate::daemon_client::DaemonClient,
    baseline: u64,
    json: bool,
) -> Result<()> {
    let deadline = Instant::now() + SWEEP_WAIT_BUDGET;
    let mut last_reported = 0u64;
    loop {
        tokio::time::sleep(SWEEP_POLL_INTERVAL).await;
        let status = client
            .lsp_sweep_status()
            .await
            .context("read language-server sweep progress")?;
        let done = status
            .get("files_done")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total = status
            .get("files_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if done > last_reported && !json {
            last_reported = done;
            println!("  enriched {done}/{total} files");
        }
        let completed = status
            .get("sweeps_completed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let running = status
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Both, not either. The counter says a sweep ended; `running` says none
        // is in flight now. Returning on the counter alone hands back a graph a
        // later sweep is still mutating.
        if completed > baseline && !running {
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                let blocked = status
                    .get("files_blocked")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                // The same claim `kin init` prints, from the same function, off
                // the same status object. This command held the whole payload
                // and read only two of its numbers, so it printed
                // "sweep complete (3/6 files)" while `languages_skipped` in its
                // own hand named rust, three files and the reason the daemon
                // observed. It is also the command the pending line from
                // `kin init` tells a reader to run next, so the two surfaces
                // disagreeing is the defect arriving at its own remedy.
                let skipped = super::init::skipped_languages_from_status(&status);
                let owed = super::init::owed_from_status(&status);
                let (line, _) = super::init::cross_file_enrichment_outcome(
                    done, total, blocked, &skipped, &owed,
                );
                // The leading indent belongs to the note block `kin init` prints
                // this under. Continuation lines keep their own.
                println!("{}", line.trim_start());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the sweep did not finish within {}s and was left running; it resumes from \
                 where it stopped on the next daemon start",
                SWEEP_WAIT_BUDGET.as_secs()
            );
        }
    }
}

/// A registered daemon that does not belong to the caller's managed home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForeignDaemon {
    label: String,
    pid: u32,
    /// The recorded home, or `unrecorded`.
    home: String,
    /// False when the daemon reported no home at all, which is a different
    /// answer from reporting one that does not match.
    recorded: bool,
}

impl ForeignDaemon {
    fn description(&self) -> String {
        if self.recorded {
            format!("{} (pid {}, home {})", self.label, self.pid, self.home)
        } else {
            format!("{} (pid {}, home unrecorded)", self.label, self.pid)
        }
    }
}

/// Split a supervisor's registry into what this sweep will stop and what does
/// not belong to the caller's home.
///
/// The second list is returned for both scopes and means different things:
/// under [`StopScope::Home`] it is what was skipped, under
/// [`StopScope::Machine`] it is what is being taken down on someone else's
/// behalf. Either way it gets named, because a sweep that silently omits or
/// silently includes a daemon is the failure this partition exists to end.
pub(crate) fn partition_by_home(
    daemons: Vec<RegisteredRepoDaemon>,
    caller_home: &str,
    scope: StopScope,
) -> (Vec<RegisteredRepoDaemon>, Vec<ForeignDaemon>) {
    let mut targets = Vec::new();
    let mut foreign = Vec::new();

    for daemon in daemons {
        let relation = daemon.home_scope(caller_home);
        if relation != DaemonHomeScope::Own {
            foreign.push(ForeignDaemon {
                label: daemon_label(&daemon),
                pid: daemon.pid,
                home: daemon.home_label().to_string(),
                recorded: relation == DaemonHomeScope::Foreign,
            });
        }
        if scope == StopScope::Machine || relation == DaemonHomeScope::Own {
            targets.push(daemon);
        }
    }

    (targets, foreign)
}

fn daemon_label(daemon: &RegisteredRepoDaemon) -> String {
    if daemon.display_name.trim().is_empty() {
        daemon.repo_id.clone()
    } else {
        daemon.display_name.clone()
    }
}

fn home_scope_label(scope: DaemonHomeScope) -> &'static str {
    match scope {
        DaemonHomeScope::Own => "this KIN_HOME",
        DaemonHomeScope::Foreign => "other KIN_HOME",
        DaemonHomeScope::Unrecorded => "home unrecorded",
    }
}

/// Stop every managed Kin daemon without writing a second command's report to
/// stdout. Full uninstall uses this before deleting the managed install root;
/// failures still propagate so it never removes binaries out from under a live
/// daemon.
pub(crate) async fn stop_all_quiet() -> Result<()> {
    // Machine scope on purpose: uninstall removes the binaries every daemon on
    // this box is running from, so leaving another home's daemon alive would
    // strand a live process on a deleted install.
    stop_all(StopScope::Machine, true, true, StopMode::Now).await
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
    stop_all_inner(
        StopScope::Machine,
        false,
        true,
        Some(install_root),
        StopMode::Now,
    )
    .await?;
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
    /// The endpoint this stop should have retired, when it survived the attempt.
    ///
    /// A stopped process whose `daemon.pid` is still published is not a stopped
    /// daemon as far as any later reader is concerned: `status`, autostart, and
    /// every other surface read that file to decide who owns the repo.
    preserved_endpoint: Option<PreservedDaemonEndpoint>,
    /// What the stop did beyond delivering the request, in order.
    ///
    /// Empty for a healthy stop, which needs no account of itself. It fills
    /// when the request could not end the daemon and the escalation took over,
    /// and then it is the only record of which signal ended the process and
    /// whether the endpoint was cleared, so it is reported rather than logged.
    steps: Vec<String>,
}

/// Retire the endpoint of a worker whose stop attempt is over, and hand back the
/// survivor for the report.
///
/// A worker that was never running keeps the old best-effort hygiene: there was
/// no teardown to wait out, and a record that outlives an unrelated process is
/// not this command's failure to report.
fn retire_worker_endpoint(
    kin_root: &Path,
    outcome: &StopOutcome,
    steps: &mut Vec<String>,
) -> Option<PreservedDaemonEndpoint> {
    let preserved = match outcome {
        StopOutcome::Stopped => retire_stopped_daemon_endpoint(kin_root)
            .preserved()
            .cloned(),
        StopOutcome::NotRunning => {
            let _ = remove_stale_daemon_files(kin_root);
            None
        }
        // Still running, whether it refused or is still in use: its endpoint
        // is still the truth, so it stays published.
        StopOutcome::Timeout | StopOutcome::SignalFailed(_) | StopOutcome::InUse(_) => return None,
    };
    // Only an escalated stop reports this. A healthy one needs no account of
    // itself, and a step line on every stop would bury the one case a reader
    // has to follow.
    if !steps.is_empty() {
        steps.push(match &preserved {
            None => "cleared the recorded pid and port".to_string(),
            Some(survivor) => format!("the recorded endpoint survived: {survivor}"),
        });
    }
    preserved
}

/// Stop this repository's worker daemon, and only this repository's.
///
/// `quiet` suppresses the report. `kin init`'s conversion phase uses it: that
/// phase ends by stopping the daemon it started, and a second command's report
/// on stdout there is not chatty output, it corrupts `kin init --json`. Never
/// widened to a machine-wide stop for that caller, which would take down other
/// lanes' daemons to tidy up after one conversion.
async fn stop_current_repo(
    json: bool,
    quiet: bool,
    kin_root: Option<&Path>,
    mode: StopMode,
) -> Result<()> {
    // The repository this stop is about, named by the caller when it has one.
    //
    // Discovering it from the process working directory is right for
    // `kin daemon stop`, typed inside a repo, and WRONG for a caller that was
    // handed a path: `kin init /elsewhere` runs with a working directory that is
    // not the new repository, so the discovery failed, the stop bailed, and the
    // daemon the conversion phase had started was left running. The next daemon
    // on that repository then refused to start because one already owned it.
    let layout = match kin_root {
        Some(root) => kin_core::KinLayout::discover(root),
        None => kin_core::KinLayout::discover(&std::env::current_dir()?),
    };
    let Some(layout) = layout else {
        bail!(
            "not inside a Kin repository; run `kin daemon stop` from a repo, or \
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
        let _ = remove_stale_daemon_files(&kin_root);
        if json {
            let payload = serde_json::json!({
                "schema": "kin.daemon-stop.v1",
                "scope": "current-repo",
                "repo": label,
                "stopped": [],
                "all_stopped": true,
            });
            if !quiet {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
        } else {
            if !quiet {
                println!("No worker daemon running for repo '{label}' (nothing to stop).");
            }
        }
        return Ok(());
    };

    let mut steps = Vec::new();
    let outcome = match mode {
        StopMode::Now => stop_worker_at(&kin_root, pid, stop_timeout(), None, &mut steps)?,
        StopMode::WhenUnused => {
            retire_worker_at(&kin_root, pid, Instant::now() + stop_timeout()).await?
        }
    };
    let preserved_endpoint = retire_worker_endpoint(&kin_root, &outcome, &mut steps);
    let report = vec![StopReport {
        kind: "repo-daemon",
        label: label.clone(),
        pid,
        outcome,
        preserved_endpoint,
        steps,
    }];
    if quiet {
        return Ok(());
    }
    finish_stop("current-repo", &report, json)
}

/// Stop this repository's worker daemon without writing a report to stdout.
pub(crate) async fn stop_current_repo_quiet(kin_root: &Path) -> Result<()> {
    stop_current_repo(false, true, Some(kin_root), StopMode::Now).await
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

async fn stop_all(scope: StopScope, json: bool, quiet: bool, mode: StopMode) -> Result<()> {
    stop_all_inner(scope, json, quiet, None, mode).await
}

/// Whether the current-repo fallback may stop `pid`. The fallback exists for a
/// worker no supervisor knows about, so a pid already covered by a stop report
/// is declined for the ordinary reason, and a pid the home partition skipped
/// must be declined too: stopping it would undo the partition the sweep just
/// disclosed, and the command's own output would contradict itself.
fn fallback_may_stop(
    pid: u32,
    reported: impl IntoIterator<Item = u32>,
    skipped: impl IntoIterator<Item = u32>,
) -> bool {
    !reported.into_iter().any(|p| p == pid) && !skipped.into_iter().any(|p| p == pid)
}

async fn stop_all_inner(
    scope: StopScope,
    json: bool,
    quiet: bool,
    uninstall_root: Option<&Path>,
    mode: StopMode,
) -> Result<()> {
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
        } else if let Some(identity) = supervisor_identity_for_stop(pid, uninstall_root, deadline)?
        {
            let port = require_supervisor_port_for_stop(
                pid,
                sup_port,
                sup_port.is_some_and(|port| connect_loopback_port(port).is_open()),
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
            let mut steps = Vec::new();
            let outcome =
                stop_supervisor_attributed(identity, remaining_budget(deadline), &mut steps);
            reports.push(StopReport {
                kind: "supervisor",
                label: "supervisor".to_string(),
                pid,
                outcome,
                preserved_endpoint: None,
                steps,
            });
        }
    }

    // Full uninstall is machine-wide by construction: it must leave no process
    // running before it removes the binaries, so it never partitions.
    let (daemons, foreign) = if uninstall_root.is_some() {
        (daemons, Vec::new())
    } else {
        partition_by_home(daemons, &caller_home_id(), scope)
    };

    for daemon in daemons {
        let label = daemon_label(&daemon);
        let kin_root = Path::new(&daemon.repo_root).join(".kin");
        let mut steps = Vec::new();
        let outcome = match mode {
            StopMode::Now => stop_worker_at(
                &kin_root,
                daemon.pid,
                remaining_budget(worker_deadline),
                uninstall_root,
                &mut steps,
            )?,
            StopMode::WhenUnused => {
                retire_worker_at(&kin_root, daemon.pid, worker_deadline).await?
            }
        };
        let preserved_endpoint = retire_worker_endpoint(&kin_root, &outcome, &mut steps);
        reports.push(StopReport {
            kind: "repo-daemon",
            label,
            pid: daemon.pid,
            outcome,
            preserved_endpoint,
            steps,
        });
    }

    // Also stop the current repo's worker if it is not registered with the
    // supervisor (e.g. supervisor down but a worker process lingering). The
    // repo-local pid file is home-agnostic, so this fallback is where a scoped
    // sweep could otherwise reach a daemon the partition skipped;
    // `fallback_may_stop` is what keeps the disclosure and the kill agreeing.
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(layout) = kin_core::KinLayout::discover(&cwd) {
            let kin_root = layout.root().to_path_buf();
            let (pid, _) = repo_daemon_recorded_endpoint(&kin_root);
            if let Some(pid) = pid {
                let may_stop = fallback_may_stop(
                    pid,
                    reports.iter().map(|r| r.pid),
                    foreign.iter().map(|skipped| skipped.pid),
                );
                if may_stop && is_process_alive(pid) {
                    let working_dir = kin_root.parent().unwrap_or(&kin_root).to_path_buf();
                    let mut steps = Vec::new();
                    let outcome = match mode {
                        StopMode::Now => stop_worker_at(
                            &kin_root,
                            pid,
                            remaining_budget(worker_deadline),
                            uninstall_root,
                            &mut steps,
                        )?,
                        StopMode::WhenUnused => {
                            retire_worker_at(&kin_root, pid, worker_deadline).await?
                        }
                    };
                    let preserved_endpoint =
                        retire_worker_endpoint(&kin_root, &outcome, &mut steps);
                    reports.push(StopReport {
                        kind: "repo-daemon",
                        label: repo_label(&working_dir),
                        pid,
                        outcome,
                        preserved_endpoint,
                        steps,
                    });
                }
            }
        }
    }

    // The supervisor is shared. Stopping it while daemons from other homes are
    // still registered would take away the routing they depend on, which is the
    // same boundary violation as stopping them outright. A home-scoped sweep
    // that left anything behind therefore retains it and says so.
    let supervisor_retained = scope == StopScope::Home && !foreign.is_empty();
    // Retirement may leave a worker in use or fail before its state is known.
    // Neither authorizes taking away its routing. Ordinary explicit stop keeps
    // its existing behavior, including supervisor escalation.
    let supervisor_kept_for_workers = reports
        .iter()
        .any(|report| mode.keeps_supervisor_for(&report.outcome));

    // The ordinary `kin daemon stop --all` path keeps the historical order:
    // workers first, supervisor last. Full uninstall already stopped it above.
    if uninstall_root.is_none() && !supervisor_retained && !supervisor_kept_for_workers {
        if let (Some(pid), Some(identity)) = (sup_pid, supervisor_identity.as_ref()) {
            let mut steps = Vec::new();
            let outcome =
                stop_supervisor_attributed(identity, remaining_budget(deadline), &mut steps);
            if outcome.is_success() {
                remove_stale_supervisor_files();
            }
            reports.push(StopReport {
                kind: "supervisor",
                label: "supervisor".to_string(),
                pid,
                outcome,
                preserved_endpoint: None,
                steps,
            });
        }
    }

    if let Some(install_root) = uninstall_root {
        stop_install_owned_daemons(install_root, deadline, &mut reports)?;
    }

    let disclosure = StopDisclosure {
        scope: Some(scope),
        foreign,
        supervisor_retained,
        supervisor_kept_for_workers,
    };

    if reports.is_empty() {
        if quiet {
            // The absence of managed daemons is a successful precondition for
            // full uninstall and needs no nested command output.
        } else if json {
            let mut payload = serde_json::json!({
                "schema": "kin.daemon-stop.v1",
                "scope": scope.label(),
                "stopped": [],
                "all_stopped": true,
            });
            disclosure.write_json(&mut payload);
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else if disclosure.foreign.is_empty() {
            println!("No Kin daemons running.");
        } else {
            // Never "no daemons running": daemons ARE running, and this scope
            // is simply not entitled to them. Collapsing the two is how a
            // scoped sweep would start reading as an empty machine.
            println!("No Kin daemons running under this KIN_HOME.");
            disclosure.write_text();
        }
        return Ok(());
    }

    finish_stop_with_output(scope.label(), &reports, json, quiet, &disclosure)
}

/// What a sweep must say about daemons outside its scope.
#[derive(Debug, Default)]
pub(crate) struct StopDisclosure {
    scope: Option<StopScope>,
    foreign: Vec<ForeignDaemon>,
    /// The supervisor was deliberately left running because other homes still
    /// depend on it.
    supervisor_retained: bool,
    /// The supervisor was left running because retirement did not establish
    /// that every repository daemon had stopped.
    supervisor_kept_for_workers: bool,
}

impl StopDisclosure {
    fn write_json(&self, payload: &mut serde_json::Value) {
        let Some(scope) = self.scope else {
            return;
        };
        let listed: Vec<_> = self
            .foreign
            .iter()
            .map(|d| {
                serde_json::json!({
                    "label": d.label,
                    "pid": d.pid,
                    "kin_home": d.home,
                    "home_recorded": d.recorded,
                })
            })
            .collect();
        let key = match scope {
            StopScope::Home => "skipped_other_homes",
            StopScope::Machine => "stopped_other_homes",
        };
        payload[key] = serde_json::Value::Array(listed);
        payload["supervisor_retained"] =
            serde_json::Value::Bool(self.supervisor_retained || self.supervisor_kept_for_workers);
    }

    fn write_text(&self) {
        let Some(scope) = self.scope else {
            return;
        };
        if self.supervisor_kept_for_workers {
            println!(
                "  Supervisor left running: a repository daemon above was not confirmed stopped. \
                 Its routing is retained."
            );
        }
        if self.foreign.is_empty() {
            return;
        }
        let lead = match scope {
            StopScope::Home => "Skipped (other KIN_HOME)",
            StopScope::Machine => "Also stopped (other KIN_HOME)",
        };
        println!("{lead}:");
        for daemon in &self.foreign {
            println!("  {}", daemon.description());
        }
        if scope == StopScope::Home {
            println!(
                "  KIN_HOME bounds store state; the supervisor is machine-wide. Use `kin daemon stop --all --machine` to stop these too."
            );
        }
        if self.supervisor_retained {
            println!("  Supervisor left running: it is shared with the daemons above.");
        }
    }
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

pub(crate) fn command_argument(args: &[String], flag: &str) -> Option<String> {
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
        // A thread carries its owning process's executable, so an unfiltered
        // scan finds one managed daemon once per thread. Here that is not only
        // a wrong count: the uninstall quiescence fence refuses on a non-empty
        // result, so a daemon's own threads would report it as "processes
        // appeared after shutdown" and block a clean uninstall (FIR-2823).
        if process.thread_kind().is_some() {
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
    deadline: Instant,
) -> Result<Option<AttributedStopTarget>> {
    // Capture the incarnation before inspecting its executable/arguments. The
    // old order scanned one process and then captured whatever later reused
    // its PID, accidentally lending the predecessor's provenance to a
    // successor.
    let Some(identity) = process_identity(pid)
        .with_context(|| format!("failed to capture legacy daemon process identity {pid}"))?
    else {
        return Ok(None);
    };
    #[cfg(unix)]
    let image_before = process_executable::observe(pid, deadline)?;
    #[cfg(not(unix))]
    let _ = deadline;
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
    #[cfg(unix)]
    let selected_install_image = {
        let image_after = process_executable::observe(pid, deadline)?;
        anyhow::ensure!(
            image_before == image_after,
            "legacy daemon pid {pid} changed executable during install attribution"
        );
        Some(image_after)
    };
    if process_identity_is_current(&identity)? {
        Ok(Some(AttributedStopTarget {
            owner: EndpointOwnerRecord::for_identity(identity),
            #[cfg(unix)]
            selected_install_image,
        }))
    } else {
        Ok(None)
    }
}

/// Stop only processes whose current executable belongs to the install being
/// replaced. The updater holds install authority across this call and commit,
/// so a cooperating launcher cannot start a new owned image in that interval.
/// A shared supervisor or worker running from another install is untouched.
pub(crate) fn stop_install_owned_daemons_for_update(install_root: &Path) -> Result<()> {
    let deadline = Instant::now() + stop_all_budget();
    let mut reports = Vec::new();
    let mut processes = managed_daemon_processes(install_root);
    // Keep routing available while owned workers drain; the supervisor exits
    // only after those workers. Foreign workers are never in this selection.
    processes.sort_by_key(|process| matches!(process.kind, ManagedDaemonKind::Supervisor));
    for process in processes {
        let expected_repo = match &process.kind {
            ManagedDaemonKind::Worker { repo_root } => Some(repo_root.as_path()),
            ManagedDaemonKind::Supervisor => None,
            ManagedDaemonKind::Unknown => bail!(
                "update found install-owned daemon pid {} without an attributable role",
                process.pid
            ),
        };
        let Some(target) =
            install_owned_stop_target(install_root, process.pid, expected_repo, deadline)?
        else {
            continue;
        };
        let mut steps = Vec::new();
        let (kind, label, outcome, preserved_endpoint) = match &process.kind {
            ManagedDaemonKind::Worker { repo_root } => {
                let kin_root = repo_root.join(".kin");
                let outcome = stop_worker_identity(&kin_root, &target, remaining_budget(deadline));
                let outcome = escalate_if_unstopped(&target, outcome, &mut steps);
                let preserved = retire_worker_endpoint(&kin_root, &outcome, &mut steps);
                ("repo-daemon", repo_label(repo_root), outcome, preserved)
            }
            ManagedDaemonKind::Supervisor => (
                "supervisor",
                "supervisor".to_string(),
                stop_supervisor_attributed(&target, remaining_budget(deadline), &mut steps),
                None,
            ),
            ManagedDaemonKind::Unknown => unreachable!(),
        };
        reports.push(StopReport {
            kind,
            label,
            pid: process.pid,
            outcome,
            preserved_endpoint,
            steps,
        });
    }
    finish_stop_with_output("install", &reports, true, true, &StopDisclosure::default())?;
    let remaining = managed_daemon_processes(install_root);
    anyhow::ensure!(
        remaining.is_empty(),
        "install-owned daemons remain after update shutdown: {}",
        remaining
            .iter()
            .map(ManagedDaemonProcess::description)
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

/// Installation ownership is additional evidence, never a replacement for a
/// present endpoint's published incarnation/image proof. Re-observe around the
/// install scan so PID reuse or exec cannot borrow its predecessor's scope.
fn install_owned_stop_target(
    install_root: &Path,
    pid: u32,
    repo_root: Option<&Path>,
    deadline: Instant,
) -> Result<Option<AttributedStopTarget>> {
    let Some(owned) = legacy_managed_identity(install_root, pid, repo_root, deadline)? else {
        return Ok(None);
    };
    let (published, owner_path) = match repo_root {
        Some(root) => {
            let kin_root = root.join(".kin");
            (
                attributed_worker_identity(&kin_root, pid),
                repo_daemon_owner_path(&kin_root),
            )
        }
        None => (attributed_supervisor_identity(pid), supervisor_owner_path()),
    };
    match published {
        Ok(Some(published)) => {
            anyhow::ensure!(
                *published == *owned,
                "daemon incarnation changed during install attribution"
            );
            #[cfg(unix)]
            anyhow::ensure!(
                published.expected_image()? == owned.expected_image()?,
                "published daemon executable differs from the install-owned image"
            );
            Ok(Some(published))
        }
        Ok(None) => Ok(None),
        Err(_)
            if matches!(std::fs::symlink_metadata(owner_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Some(owned))
        }
        Err(error) => Err(error),
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
                    let mut steps = Vec::new();
                    let outcome = stop_worker_at(
                        &kin_root,
                        process.pid,
                        remaining_budget(deadline),
                        Some(install_root),
                        &mut steps,
                    )?;
                    let preserved_endpoint =
                        retire_worker_endpoint(&kin_root, &outcome, &mut steps);
                    reports.push(StopReport {
                        kind: "repo-daemon",
                        label: repo_label(&repo_root),
                        pid: process.pid,
                        outcome,
                        preserved_endpoint,
                        steps,
                    });
                }
                ManagedDaemonKind::Supervisor => {
                    let mut steps = Vec::new();
                    let outcome = stop_supervisor_pid(
                        process.pid,
                        remaining_budget(deadline),
                        Some(install_root),
                        &mut steps,
                    )?;
                    reports.push(StopReport {
                        kind: "supervisor",
                        label: "supervisor".to_string(),
                        pid: process.pid,
                        outcome,
                        preserved_endpoint: None,
                        steps,
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
    finish_stop_with_output(scope, reports, json, false, &StopDisclosure::default())
}

fn finish_stop_with_output(
    scope: &str,
    reports: &[StopReport],
    json: bool,
    quiet: bool,
    disclosure: &StopDisclosure,
) -> Result<()> {
    let all_stopped = reports.iter().all(|r| r.outcome.is_success());
    // Reported separately from `all_stopped`, which stays a statement about
    // processes. A daemon can stop and still leave its endpoint published, and
    // collapsing the two would reintroduce the ambiguity: every later reader
    // treats `daemon.pid` as the live owner of the repo.
    let endpoints_retired = reports.iter().all(|r| r.preserved_endpoint.is_none());

    if quiet {
        // The caller owns user-facing output. We still evaluate every result
        // below and fail loud when a process survived the stop attempt.
    } else if json {
        let stopped: Vec<_> = reports
            .iter()
            .map(|r| {
                let mut entry = serde_json::json!({
                    "kind": r.kind,
                    "label": r.label,
                    "pid": r.pid,
                    "result": r.outcome.detail(),
                });
                if !r.steps.is_empty() {
                    entry["steps"] = serde_json::json!(r.steps);
                }
                if let Some(preserved) = &r.preserved_endpoint {
                    entry["preserved_endpoint"] = serde_json::json!({
                        "pid_path": preserved.pid_path().display().to_string(),
                        "reason": preserved.reason(),
                    });
                }
                if let StopOutcome::InUse(reasons) = &r.outcome {
                    entry["in_use"] = serde_json::json!(reasons);
                }
                entry
            })
            .collect();
        let mut payload = serde_json::json!({
            "schema": "kin.daemon-stop.v1",
            "scope": scope,
            "stopped": stopped,
            "all_stopped": all_stopped,
            "endpoints_retired": endpoints_retired,
        });
        disclosure.write_json(&mut payload);
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
                StopOutcome::InUse(reasons) => format!(
                    "{} (pid {}): left running because it is still in use ({}). It exits on \
                     its own as soon as that ends.",
                    r.label,
                    r.pid,
                    reasons.join("; ")
                ),
            };
            println!("  {line}");
            for step in &r.steps {
                println!("    step: {step}");
            }
        }
        for r in reports {
            if let Some(preserved) = &r.preserved_endpoint {
                println!(
                    "  {} (pid {}): endpoint NOT retired: {preserved}",
                    r.label, r.pid
                );
            }
        }
        disclosure.write_text();
        if all_stopped && endpoints_retired {
            // "Targeted" is load-bearing now that a sweep can be scoped: the
            // disclosure above names what was outside the target.
            println!("All targeted Kin daemons stopped.");
        }
    }

    // A daemon left running because it is still in use is what a
    // `--when-unused` stop promised, so only an outcome the stop was not
    // entitled to fails the command.
    let failed: Vec<String> = reports
        .iter()
        .filter(|r| !r.outcome.is_settled())
        .map(|r| format!("{} (pid {})", r.label, r.pid))
        .collect();
    if !failed.is_empty() {
        bail!(
            "one or more Kin daemons did not stop: {}",
            failed.join(", ")
        );
    }
    // Deliberately NOT raised on the quiet path. `quiet` is full uninstall's
    // nested stop, and uninstall's job is to leave no PROCESS running: it
    // re-verifies exactly that through its own quiescence fence, which reads
    // processes and not endpoint records. A leftover pid file inside some repo
    // does not keep an install alive, and refusing to uninstall over one would
    // turn a reporting improvement into a command the operator cannot complete.
    // A surviving process still fails uninstall, above, as it always has.
    if !quiet && !endpoints_retired {
        // The process died and its endpoint did not, so `status`, autostart, and
        // every other reader of `daemon.pid` still see a published owner for this
        // repo. Reporting success here is what made the failure invisible.
        let preserved: Vec<String> = reports
            .iter()
            .filter_map(|r| r.preserved_endpoint.as_ref())
            .map(PreservedDaemonEndpoint::to_string)
            .collect();
        bail!(
            "Kin daemons stopped but their endpoints were not retired: {}",
            preserved.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop_report(preserved: Option<PreservedDaemonEndpoint>) -> StopReport {
        StopReport {
            kind: "repo-daemon",
            label: "repo".to_string(),
            pid: 4242,
            outcome: StopOutcome::Stopped,
            preserved_endpoint: preserved,
            steps: Vec::new(),
        }
    }

    /// A stop whose endpoint survived must fail, and must name the survivor.
    #[test]
    fn a_surviving_endpoint_fails_the_stop_and_names_the_pid_file() {
        let preserved = crate::daemon_client::preserved_daemon_endpoint_for_test(
            Path::new("/repo/.kin/daemon.pid"),
            "recorded owner pid 4242 never became affirmatively dead",
        );
        let error = finish_stop_with_output(
            "current-repo",
            &[stop_report(Some(preserved))],
            false,
            false,
            &StopDisclosure::default(),
        )
        .expect_err("a published endpoint outliving a confirmed stop is a failure");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("/repo/.kin/daemon.pid"),
            "the operator needs the path, not just a verdict: {rendered}"
        );

        // The falsification: the identical report with nothing preserved passes,
        // so the assertion above is about the survivor and not about the shape
        // of the report.
        finish_stop_with_output(
            "current-repo",
            &[stop_report(None)],
            false,
            false,
            &StopDisclosure::default(),
        )
        .expect("a retired endpoint is a clean stop");
    }

    /// Full uninstall's nested stop must not be blocked by a leftover pid file.
    /// Uninstall's contract is that no PROCESS survives, which it re-verifies
    /// itself; refusing over an endpoint record would leave the operator unable
    /// to complete the command.
    #[test]
    fn the_uninstall_path_is_not_blocked_by_a_surviving_endpoint() {
        let preserved = crate::daemon_client::preserved_daemon_endpoint_for_test(
            Path::new("/repo/.kin/daemon.pid"),
            "recorded owner pid 4242 never became affirmatively dead",
        );
        finish_stop_with_output(
            "all",
            &[stop_report(Some(preserved))],
            false,
            true,
            &StopDisclosure::default(),
        )
        .expect("a leftover endpoint record does not keep an install alive");
    }

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
            classify_liveness(None, false, DaemonPortProbe::Closed),
            DaemonLiveness::NotRunning
        );
        assert_eq!(
            classify_liveness(None, true, DaemonPortProbe::Answering),
            DaemonLiveness::NotRunning
        );
        // Recorded pid, dead process → stale files.
        assert_eq!(
            classify_liveness(Some(4219), false, DaemonPortProbe::Closed),
            DaemonLiveness::Stale
        );
        // A dead process is stale even if some unrelated process holds the port.
        assert_eq!(
            classify_liveness(Some(4219), false, DaemonPortProbe::Answering),
            DaemonLiveness::Stale
        );
        // Alive and nothing on the port → unresponsive (starting up, or it
        // lost the socket).
        assert_eq!(
            classify_liveness(Some(4219), true, DaemonPortProbe::Closed),
            DaemonLiveness::Unresponsive
        );
        // Alive and serving → running.
        assert_eq!(
            classify_liveness(Some(4219), true, DaemonPortProbe::Answering),
            DaemonLiveness::Running
        );
    }

    /// The incident this split exists for: a daemon whose process is alive and
    /// whose socket `lsof` shows in LISTEN, reported as "port closed".
    ///
    /// Both wedge shapes are alive with the port held, and neither may collapse
    /// into the verdict that says nothing is there. `Unresponsive` keeps its own
    /// meaning: the connect was refused.
    ///
    /// Falsify by mapping either wedge arm back onto `Unresponsive`: the label
    /// assertions below go red because they would claim the port is not
    /// listening.
    #[test]
    fn a_listening_daemon_that_never_answers_is_not_reported_as_port_closed() {
        let not_accepting = classify_liveness(Some(99108), true, DaemonPortProbe::OpenNotAccepting);
        let not_answering =
            classify_liveness(Some(99108), true, DaemonPortProbe::AcceptedNotAnswering);

        assert_eq!(not_accepting, DaemonLiveness::NotAccepting);
        assert_eq!(not_answering, DaemonLiveness::NotAnswering);
        assert_ne!(not_accepting, DaemonLiveness::Unresponsive);
        assert_ne!(not_answering, DaemonLiveness::Unresponsive);

        for state in [not_accepting, not_answering] {
            let label = state.label();
            assert!(
                label.contains("socket open"),
                "a held socket must be reported as open: {label}"
            );
            assert!(
                !label.contains("port closed") && !label.contains("nothing listening"),
                "a held socket must never be reported as closed: {label}"
            );
            assert!(state.is_wedged(), "{label}");
        }

        // And the one state that does mean nothing holds the port still says so.
        let refused = classify_liveness(Some(99108), true, DaemonPortProbe::Closed);
        assert!(
            refused.label().contains("nothing listening on the port"),
            "{}",
            refused.label()
        );
        assert!(!refused.is_wedged(), "{}", refused.label());
    }

    /// A wedged daemon's line still names the pid and port, because those are
    /// what the operator acts on.
    #[test]
    fn a_wedged_daemon_line_names_the_pid_and_port_to_act_on() {
        let current = CurrentRepoStatus {
            label: "cli90".to_string(),
            repo_root: "/work/cli90".to_string(),
            state: DaemonLiveness::NotAccepting,
            pid: Some(99108),
            port: Some(63357),
            pid_file: "/work/cli90/.kin/daemon.pid".to_string(),
            port_file: "/work/cli90/.kin/daemon.port".to_string(),
            serving_since_unix: None,
        };
        let line = current_repo_line(&current, false);
        assert!(line.contains("pid 99108"), "{line}");
        assert!(line.contains("port 63357"), "{line}");
        assert!(line.contains("socket open"), "{line}");
    }

    /// A daemon the supervisor does not list is still named, with the pair an
    /// operator checks by hand and the time its serving record gives, and the
    /// line says why the listing above it does not show it.
    ///
    /// Breaking it: print the bare state word again, or drop the registry
    /// clause, and `kin daemon status` beside a standalone daemon reads as
    /// though nothing but a state word were known about it.
    #[test]
    fn a_daemon_the_supervisor_does_not_list_is_named_with_its_pid_and_port() {
        let current = CurrentRepoStatus {
            label: "kin".to_string(),
            repo_root: "/work/kin".to_string(),
            state: DaemonLiveness::Running,
            pid: Some(12538),
            port: Some(56698),
            pid_file: "/work/kin/.kin/daemon.pid".to_string(),
            port_file: "/work/kin/.kin/daemon.port".to_string(),
            // 2026-09-10T17:57:05Z.
            serving_since_unix: Some(1_789_063_025),
        };
        let standalone = current_repo_line(&current, false);
        assert!(standalone.contains("pid 12538"), "{standalone}");
        assert!(standalone.contains("port 56698"), "{standalone}");
        assert!(
            standalone.contains("serving since 2026-09-10 17:57Z"),
            "{standalone}"
        );
        assert!(
            standalone.contains("not in the supervisor's registry"),
            "{standalone}"
        );

        // The supervised twin names the same daemon and makes no registry claim.
        let supervised = current_repo_line(&current, true);
        assert!(supervised.contains("pid 12538"), "{supervised}");
        assert!(!supervised.contains("registry"), "{supervised}");

        // A repository with nothing running keeps its one-word state.
        let idle = CurrentRepoStatus {
            state: DaemonLiveness::NotRunning,
            pid: None,
            port: None,
            serving_since_unix: None,
            ..current
        };
        assert_eq!(
            current_repo_line(&idle, false),
            "Current repo (kin): worker daemon not running"
        );
    }

    #[test]
    fn liveness_labels_are_distinct_and_stable() {
        let states = [
            DaemonLiveness::Running,
            DaemonLiveness::NotAccepting,
            DaemonLiveness::NotAnswering,
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
    #[cfg(not(unix))]
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

    #[cfg(unix)]
    #[test]
    fn cooperative_incarnation_mismatch_never_authorizes_shutdown() {
        let identity = process_identity(std::process::id()).unwrap().unwrap();
        let delivered = std::cell::Cell::new(false);
        let outcome = stop_identity_cooperatively(&identity, Duration::from_millis(10), |_, _| {
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

    /// The reported outcome for a daemon whose parent never reaps it.
    ///
    /// This is the shape the install proof hit on every Unix leg: the MCP
    /// server starts a repo daemon and stays alive, so when the stop request is
    /// delivered and honoured, the exited daemon lingers as an unreaped corpse.
    /// `kill(pid, 0)` keeps answering for it, so the wait loop never concluded
    /// and every identity was reported `timeout` — a stop that worked, reported
    /// as a stop that failed.
    ///
    /// Asserts the outcome the user actually sees rather than the primitive
    /// beneath it. The wait is deliberately generous: without a corpse-aware
    /// liveness probe this returns `Timeout` after burning all of it, so the
    /// test fails on the verdict rather than on being slow.
    #[cfg(unix)]
    #[test]
    fn stopping_a_daemon_whose_parent_never_reaps_it_reports_stopped() {
        // `exec` so the signalled PID is the process that actually dies, rather
        // than a shell that leaves an orphan behind.
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 30")
            .spawn()
            .expect("spawn a stand-in daemon");
        let identity = process_identity(child.id())
            .expect("read the stand-in daemon's birth identity")
            .expect("a running stand-in daemon has an identity");

        let wait = Duration::from_secs(10);
        let outcome = stop_identity_cooperatively(&identity, wait, |expected, _| {
            // Model the cooperative `/shutdown` endpoint accepting the request:
            // on macOS the daemon is asked over HTTP rather than signalled.
            let killed = unsafe { libc::kill(expected.pid() as libc::pid_t, libc::SIGTERM) };
            assert_eq!(
                killed, 0,
                "the stand-in daemon must accept the stop request"
            );
            Ok(true)
        });

        // Nothing waited on the child before the outcome above was decided,
        // which is the condition under test. Reap afterwards so the corpse does
        // not outlive the test.
        let reaped = child.wait();
        assert_eq!(
            outcome,
            StopOutcome::Stopped,
            "a daemon that honoured the stop request must be reported stopped even when \
             its parent has not reaped it"
        );
        reaped.expect("reap the stand-in daemon");
    }

    #[cfg(unix)]
    const ESCALATION_STANDIN: &str = "KIN_TEST_ESCALATION_STANDIN";

    // These fixtures execute the debug test binary, which Linux hashes in full.
    // Grade identity and signal ordering with a fixture budget, independently of
    // the production daemon's lifecycle ceiling and concurrent CI disk pressure.
    #[cfg(unix)]
    const STANDIN_IMAGE_BUDGET: Duration = Duration::from_secs(60);

    #[cfg(unix)]
    const STANDIN_READY_BUDGET: Duration = Duration::from_secs(90);

    #[cfg(unix)]
    static STANDIN_TERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    #[cfg(unix)]
    extern "C" fn standin_term_handler(_: libc::c_int) {
        STANDIN_TERM.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The owned child publishes its own OS identity after installing its
    /// signal disposition. The pipe acknowledges that exact point, avoiding
    /// the parent observing a pre-exec test harness or guessing at readiness.
    #[cfg(unix)]
    #[test]
    fn escalation_standin_daemon_worker() {
        use std::io::{Read, Write};
        use std::os::unix::process::CommandExt;
        let Ok(raw) = std::env::var(ESCALATION_STANDIN) else {
            return;
        };
        let spec: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let mode = spec["mode"].as_str().unwrap();
        unsafe {
            libc::alarm(180);
        }
        if mode == "ignore-sigterm" {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
        } else if mode == "exec-on-term" {
            unsafe {
                libc::signal(
                    libc::SIGTERM,
                    standin_term_handler as *const () as libc::sighandler_t,
                );
            }
        }
        if mode == "foreign" {
            println!("KIN_EXEC_READY");
        } else {
            let started = Instant::now();
            let owner = EndpointOwnerRecord::current_with_deadline(started + STANDIN_IMAGE_BUDGET)
                .expect("the stand-in must observe its process incarnation");
            owner.executable_identity().unwrap_or_else(|error| {
                let image_bytes = std::env::current_exe()
                    .and_then(std::fs::metadata)
                    .map(|metadata| metadata.len());
                panic!(
                    "self-publication contains no executable evidence: {error}; \
                     elapsed={:?}, budget={STANDIN_IMAGE_BUDGET:?}, image_bytes={image_bytes:?}",
                    started.elapsed()
                );
            });
            println!("KIN_OWNER:{}", serde_json::to_string(&owner).unwrap());
        }
        std::io::stdout().flush().unwrap();
        if mode == "exec-on-term" {
            while !STANDIN_TERM.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
        } else {
            let mut byte = [0];
            if std::io::stdin().read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
        }
        if matches!(mode, "exec-on-command" | "exec-on-term") {
            let error = std::process::Command::new(spec["exec_path"].as_str().unwrap())
                .args([
                    "--exact",
                    "commands::daemon::tests::escalation_standin_daemon_worker",
                    "--nocapture",
                ])
                .env(ESCALATION_STANDIN, r#"{"mode":"foreign"}"#)
                .exec();
            panic!("owned stand-in exec failed: {error}");
        }
    }

    #[cfg(unix)]
    struct OwnedTestChild(std::process::Child);

    #[cfg(unix)]
    impl std::ops::Deref for OwnedTestChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(unix)]
    impl std::ops::DerefMut for OwnedTestChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[cfg(unix)]
    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    struct Standin {
        child: OwnedTestChild,
        target: AttributedStopTarget,
        stdout: std::process::ChildStdout,
        pending: Vec<u8>,
        executable: PathBuf,
        stderr: PathBuf,
        _directory: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl Standin {
        fn diagnostics(&self) -> String {
            std::fs::read_to_string(&self.stderr)
                .unwrap_or_else(|error| format!("could not read child stderr: {error}"))
        }

        fn event(&mut self, prefix: &str) -> String {
            use std::io::Read;
            let deadline = Instant::now() + STANDIN_READY_BUDGET;
            loop {
                while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<_> = self.pending.drain(..=end).collect();
                    let line = String::from_utf8(line).unwrap();
                    if let Some(value) = line.trim_end().strip_prefix(prefix) {
                        return value.to_owned();
                    }
                }
                let mut bytes = [0; 4096];
                match self.stdout.read(&mut bytes) {
                    Ok(0) => panic!(
                        "owned child exited before {prefix}: {:?}; stderr: {}",
                        self.child.try_wait(),
                        self.diagnostics()
                    ),
                    Ok(count) => self.pending.extend_from_slice(&bytes[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("owned child receipt failed: {error}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "owned child did not acknowledge {prefix} within {STANDIN_READY_BUDGET:?}; stderr: {}",
                    self.diagnostics()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn command(&mut self) {
            use std::io::Write;
            self.child.stdin.as_mut().unwrap().write_all(b"E").unwrap();
        }
    }

    #[cfg(unix)]
    fn spawn_escalation_standin(mode: &str) -> Standin {
        spawn_escalation_standin_at(mode, None)
    }

    #[cfg(unix)]
    fn spawn_escalation_standin_at(mode: &str, install: Option<(&Path, &Path)>) -> Standin {
        use std::os::fd::AsRawFd;
        let directory = tempfile::tempdir().unwrap();
        let current = std::env::current_exe().unwrap();
        let executable = install
            .map(|(root, _)| root.join("bin/kin-daemon"))
            .unwrap_or_else(|| directory.path().join("custom-worker"));
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::copy(&current, &executable).unwrap();
        let next_executable = directory.path().join("kin-foreign-process");
        if matches!(mode, "exec-on-command" | "exec-on-term") {
            // Only an image-transition case needs a second, distinct inode.
            std::fs::copy(&current, &next_executable).unwrap();
        }
        let stderr = directory.path().join("stderr.log");
        let spec = if mode == "exec-same-image" {
            serde_json::json!({"mode": "exec-on-command", "exec_path": executable})
        } else {
            serde_json::json!({"mode": mode, "exec_path": next_executable})
        };
        let mut child = OwnedTestChild(
            std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "commands::daemon::tests::escalation_standin_daemon_worker",
                    "--nocapture",
                ])
                .args(
                    install
                        .map(|(_, repo)| {
                            vec![
                                "--".to_string(),
                                "--repo".to_string(),
                                repo.display().to_string(),
                            ]
                        })
                        .unwrap_or_default(),
                )
                .env(ESCALATION_STANDIN, spec.to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::fs::File::create(&stderr).unwrap())
                .spawn()
                .unwrap(),
        );
        let stdout = child.stdout.take().unwrap();
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let placeholder =
            EndpointOwnerRecord::for_identity(process_identity(child.id()).unwrap().unwrap());
        let mut standin = Standin {
            child,
            target: AttributedStopTarget::published(placeholder),
            stdout,
            pending: Vec::new(),
            executable,
            stderr,
            _directory: directory,
        };
        let owner = serde_json::from_str(&standin.event("KIN_OWNER:")).unwrap();
        standin.target = AttributedStopTarget::published(owner);
        assert_eq!(standin.target.pid(), standin.child.id());
        assert!(process_identity_is_current(&standin.target).unwrap());
        standin
    }

    #[cfg(unix)]
    #[test]
    fn a_stop_request_that_never_arrives_still_ends_the_recorded_daemon() {
        let child = spawn_escalation_standin("plain");
        assert_eq!(child.executable.file_name().unwrap(), "custom-worker");
        let mut steps = Vec::new();
        // Linux hashes this large debug fixture before each signal. Keep the
        // production wrapper covered on platforms without that full-file read.
        #[cfg(target_os = "linux")]
        let outcome = escalate_to_recorded_pid(
            &child.target,
            ESCALATION_SIGTERM_WAIT,
            STANDIN_IMAGE_BUDGET,
            &mut steps,
        )
        .expect("the published fixture must authorize escalation");
        #[cfg(not(target_os = "linux"))]
        let outcome = escalate_if_unstopped(
            &child.target,
            StopOutcome::SignalFailed("connection timed out".to_owned()),
            &mut steps,
        );
        assert_eq!(outcome, StopOutcome::Stopped, "{steps:?}");
        assert!(
            steps.iter().any(|s| s.contains("sent SIGTERM")),
            "{steps:?}"
        );
        assert!(!process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_daemon_that_ignores_sigterm_is_ended_by_sigkill() {
        let child = spawn_escalation_standin("ignore-sigterm");
        let mut steps = Vec::new();
        let outcome = escalate_to_recorded_pid(
            &child.target,
            Duration::from_millis(200),
            STANDIN_IMAGE_BUDGET,
            &mut steps,
        );
        assert_eq!(outcome, Some(StopOutcome::Stopped), "{steps:?}");
        assert!(
            steps.iter().any(|s| s.contains("sent SIGKILL")),
            "{steps:?}"
        );
        assert!(!process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_escalation_never_signals_a_pid_that_is_not_a_kin_process() {
        // The record contains valid self-published evidence; the process then
        // execs a different owned executable whose basename starts with Kin.
        let mut child = spawn_escalation_standin("exec-on-command");
        child.command();
        child.event("KIN_EXEC_READY");
        assert!(process_identity_is_current(&child.target).unwrap());
        let mut steps = Vec::new();
        let original = StopOutcome::SignalFailed("connection timed out".to_owned());
        #[cfg(target_os = "linux")]
        let outcome = escalate_to_recorded_pid(
            &child.target,
            ESCALATION_SIGTERM_WAIT,
            STANDIN_IMAGE_BUDGET,
            &mut steps,
        )
        .unwrap_or_else(|| original.clone());
        #[cfg(not(target_os = "linux"))]
        let outcome = escalate_if_unstopped(&child.target, original.clone(), &mut steps);
        assert_eq!(outcome, original, "{steps:?}");
        assert!(
            process_identity_is_current(&child.target).unwrap(),
            "{steps:?}"
        );
        assert!(
            steps.iter().any(|s| s.contains("published image")),
            "{steps:?}"
        );
        assert!(
            !steps.iter().any(|s| s.contains("sent SIGTERM")),
            "{steps:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exec_after_sigterm_withdraws_sigkill_authority() {
        let mut child = spawn_escalation_standin("exec-on-term");
        let signal_target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        assert!(signal_target
            .send(libc::SIGTERM, Instant::now() + STANDIN_IMAGE_BUDGET)
            .unwrap());
        // This acknowledgment establishes the image change before the KILL
        // decision; elapsed time alone cannot prove that the child exec'd.
        child.event("KIN_EXEC_READY");
        let error = signal_target
            .send(libc::SIGKILL, Instant::now() + STANDIN_IMAGE_BUDGET)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    /// A recorded process that stops inside the window between the incarnation
    /// probe and the image read.
    ///
    /// That window is microseconds wide and a loaded host lands in it: SIGTERM
    /// delivered, the pid still alive at the grace boundary, and the kernel's
    /// executing-image reference already gone by the KILL stage, because Linux
    /// drops it the moment a process stops running. Reading that as a failure
    /// makes a stop that did end the daemon report no verdict at all, so the
    /// readers are injected here rather than waiting for the race.
    #[cfg(unix)]
    #[test]
    fn a_process_that_stops_during_image_observation_reads_as_gone() {
        let child = spawn_escalation_standin("plain");
        let signal_target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        let mut probes = [true, false].into_iter();
        let delivered = signal_target
            .send_with(
                libc::SIGKILL,
                Instant::now() + Duration::from_secs(5),
                |_| Ok(probes.next().expect("the incarnation is probed twice")),
                |_, _| Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            )
            .unwrap();
        assert!(!delivered);
        // The control: the classification alone answered, so nothing was
        // signalled and the live standin still holds its recorded incarnation.
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    /// The same read failing while the recorded incarnation is still running.
    ///
    /// An image this stop cannot read is not an image it may signal, and it is
    /// not an exit either. Answering `gone` here would report a stop that never
    /// happened.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_image_on_a_running_incarnation_still_refuses() {
        let child = spawn_escalation_standin("plain");
        let signal_target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        let error = signal_target
            .send_with(
                libc::SIGKILL,
                Instant::now() + Duration::from_secs(5),
                |_| Ok(true),
                |_, _| Err(std::io::Error::from_raw_os_error(libc::EACCES)),
            )
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn exhausted_publication_cannot_gain_signal_authority_from_its_live_process() {
        let owner = EndpointOwnerRecord::current_with_deadline(Instant::now())
            .expect("the expired capture retains a real live incarnation");
        let target = AttributedStopTarget::published(owner);
        assert!(process_identity_is_current(&target).unwrap());
        let result = UnixSignalTarget::open(&target);
        assert!(
            matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied),
            "a live process with no published image must not become a signal target"
        );
        assert!(process_identity_is_current(&target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn replacing_the_install_path_keeps_the_published_running_image_authority() {
        let child = spawn_escalation_standin("plain");
        std::fs::remove_file(&child.executable).unwrap();
        std::fs::write(
            &child.executable,
            b"a later installation is not the running executable",
        )
        .unwrap();
        let mut steps = Vec::new();
        let outcome = escalate_to_recorded_pid(
            &child.target,
            Duration::from_millis(200),
            STANDIN_IMAGE_BUDGET,
            &mut steps,
        );
        assert_eq!(outcome, Some(StopOutcome::Stopped), "{steps:?}");
        assert!(!process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_owner_can_cooperate_but_cannot_authorize_signals() {
        let mut child = spawn_escalation_standin("plain");
        let legacy = AttributedStopTarget::published(EndpointOwnerRecord::for_identity(
            child.target.owner.identity().clone(),
        ));
        let mut steps = Vec::new();
        assert_eq!(
            escalate_to_recorded_pid(
                &legacy,
                Duration::from_millis(10),
                Duration::from_secs(1),
                &mut steps
            ),
            None
        );
        assert!(process_identity_is_current(&legacy).unwrap());
        assert!(
            steps
                .iter()
                .any(|s| s.contains("only cooperative shutdown")),
            "{steps:?}"
        );
        let outcome =
            stop_identity_cooperatively(&legacy, Duration::from_secs(5), |expected, _| {
                assert_eq!(expected, legacy.owner.identity());
                // Model the daemon accepting the identity-bound request: its own
                // read loop exits cooperatively when its controller closes input.
                drop(child.child.stdin.take());
                Ok(true)
            });
        assert_eq!(outcome, StopOutcome::Stopped);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_execution_version_rejects_exec_of_the_same_image() {
        let mut child = spawn_escalation_standin("exec-same-image");
        child.command();
        child.event("KIN_EXEC_READY");
        assert!(process_identity_is_current(&child.target).unwrap());
        let signal_target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        let error = signal_target
            .send(libc::SIGTERM, Instant::now() + Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_and_unusable_evidence_workers_still_stop_through_the_recorded_socket() {
        use std::io::{BufRead, Read, Write};
        for executable in [
            None,
            Some(serde_json::json!({"algorithm":"future-v99"})),
            Some(serde_json::json!(["malformed"])),
        ] {
            let mut child = spawn_escalation_standin("plain");
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut owner = serde_json::to_value(EndpointOwnerRecord::for_identity(
                child.target.owner.identity().clone(),
            ))
            .unwrap();
            if let Some(evidence) = executable {
                owner["executable"] = evidence;
            }
            std::fs::write(
                repo_daemon_owner_path(root),
                serde_json::to_vec(&owner).unwrap(),
            )
            .unwrap();
            std::fs::write(repo_daemon_pid_path(root), child.child.id().to_string()).unwrap();
            std::fs::write(repo_daemon_port_path(root), port.to_string()).unwrap();
            let input = child.child.stdin.take().unwrap();
            let expected = child.target.owner.identity().clone();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("owned fixture accept: {error}"),
                    }
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(5));
                };
                // The listener polls for the connection, and a BSD accept
                // hands the accepted socket that flag while a Linux accept
                // does not. Say what this reader needs rather than inherit an
                // answer that differs by host: a read timeout does not make a
                // non-blocking socket wait, so the first read returns
                // WouldBlock on macOS whenever the request has not landed yet.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut line = String::new();
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "request ended before its status line"
                );
                assert!(line.starts_with("POST /shutdown HTTP/1.1"));
                let mut length = None;
                loop {
                    line.clear();
                    assert!(
                        reader.read_line(&mut line).unwrap() > 0,
                        "request ended before its headers"
                    );
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("Content-Length: ") {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.unwrap();
                assert!(length < 4096);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                assert_eq!(
                    serde_json::from_slice::<ProcessIdentity>(&body).unwrap(),
                    expected
                );
                drop(reader);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
                drop(input);
            });
            let mut steps = Vec::new();
            let outcome = stop_worker_at(
                root,
                child.child.id(),
                Duration::from_secs(5),
                None,
                &mut steps,
            )
            .unwrap();
            server.join().unwrap();
            assert_eq!(outcome, StopOutcome::Stopped, "{steps:?}");
            assert!(!steps.iter().any(|s| s.contains("sent SIG")), "{steps:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn exhausted_signal_budget_leaves_the_owned_process_alive() {
        let child = spawn_escalation_standin("plain");
        let signal_target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        let error = signal_target
            .send(libc::SIGTERM, Instant::now())
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_signal_target_keeps_its_pidfd_after_the_owned_child_exits() {
        use std::os::fd::AsRawFd;
        let mut child = spawn_escalation_standin("plain");
        let target = UnixSignalTarget::open(&child.target).unwrap().unwrap();
        drop(child.child.stdin.take());
        child.child.wait().unwrap();
        assert!(unsafe { libc::fcntl(target.pidfd.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(!target
            .send(libc::SIGTERM, Instant::now() + Duration::from_secs(1))
            .unwrap());
    }

    #[cfg(target_os = "linux")]
    fn pidfds_for_owned_child(pid: u32) -> Vec<PathBuf> {
        let wanted = format!("Pid:\t{pid}");
        std::fs::read_dir("/proc/self/fdinfo")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let body = std::fs::read_to_string(entry.path()).ok()?;
                body.lines()
                    .any(|line| line == wanted)
                    .then(|| entry.path())
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_post_pin_probe_error_closes_the_owned_pidfd() {
        let child = spawn_escalation_standin("plain");
        assert!(pidfds_for_owned_child(child.target.pid()).is_empty());
        let mut calls = 0;
        let result = UnixSignalTarget::open_with_probe(&child.target, |_| {
            calls += 1;
            if calls == 1 {
                return Ok(true);
            }
            assert_eq!(pidfds_for_owned_child(child.target.pid()).len(), 1);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected post-pin probe refusal",
            ))
        });
        assert!(
            matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied)
        );
        assert!(pidfds_for_owned_child(child.target.pid()).is_empty());
        assert!(process_identity_is_current(&child.target).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pidfd_open_error_survives_the_followup_identity_probe() {
        let mut value = serde_json::to_value(
            EndpointOwnerRecord::current_with_deadline(Instant::now() + STANDIN_IMAGE_BUDGET)
                .unwrap(),
        )
        .unwrap();
        // This is not a possible positive Linux pid_t and no process is
        // signalled. The second probe deliberately changes thread-local errno.
        value["identity"]["pid"] = serde_json::json!(u32::MAX);
        let target = AttributedStopTarget::published(serde_json::from_value(value).unwrap());
        let mut calls = 0;
        let result = UnixSignalTarget::open_with_probe(&target, |_| {
            calls += 1;
            if calls == 2 {
                unsafe {
                    libc::close(-1);
                }
            }
            Ok(true)
        });
        assert_eq!(calls, 2);
        assert!(matches!(result, Err(ref error) if error.raw_os_error() == Some(libc::EINVAL)));
    }

    #[test]
    fn a_successful_stop_is_never_escalated() {
        let target = AttributedStopTarget::published(EndpointOwnerRecord::for_identity(
            process_identity(std::process::id()).unwrap().unwrap(),
        ));
        for outcome in [StopOutcome::Stopped, StopOutcome::NotRunning] {
            let mut steps = Vec::new();
            assert_eq!(
                escalate_if_unstopped(&target, outcome.clone(), &mut steps),
                outcome
            );
            assert!(steps.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn update_stop_preserves_same_named_daemons_from_another_install() {
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("install");
        let foreign_install = fixture.path().join("foreign");
        let repo = fixture.path().join("repo");
        let foreign_repo = fixture.path().join("foreign-repo");
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        std::fs::create_dir_all(foreign_repo.join(".kin")).unwrap();
        let owned = spawn_escalation_standin_at("wait", Some((&install, &repo)));
        let mut foreign =
            spawn_escalation_standin_at("wait", Some((&foreign_install, &foreign_repo)));
        let kin_root = repo.join(".kin");
        std::fs::write(
            repo_daemon_pid_path(&kin_root),
            owned.child.id().to_string(),
        )
        .unwrap();
        std::fs::write(
            repo_daemon_owner_path(&kin_root),
            serde_json::to_vec(&owned.target.owner).unwrap(),
        )
        .unwrap();
        stop_install_owned_daemons_for_update(&install).unwrap();
        assert!(!process_identity_is_current(&owned.target).unwrap());
        assert!(
            foreign.child.try_wait().unwrap().is_none(),
            "foreign daemon was interrupted"
        );
        assert!(process_identity_is_current(&foreign.target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn update_stop_cannot_replace_malformed_publication_with_install_ownership() {
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("install");
        let repo = fixture.path().join("repo");
        let kin_root = repo.join(".kin");
        std::fs::create_dir_all(&kin_root).unwrap();
        let mut owned = spawn_escalation_standin_at("wait", Some((&install, &repo)));
        std::fs::write(
            repo_daemon_pid_path(&kin_root),
            owned.child.id().to_string(),
        )
        .unwrap();
        std::fs::write(repo_daemon_owner_path(&kin_root), b"not a valid owner").unwrap();
        assert!(stop_install_owned_daemons_for_update(&install).is_err());
        assert!(owned.child.try_wait().unwrap().is_none());
        assert!(process_identity_is_current(&owned.target).unwrap());
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

    fn registered(label: &str, pid: u32, kin_home: &str) -> RegisteredRepoDaemon {
        RegisteredRepoDaemon {
            repo_id: format!("local-{label}"),
            display_name: label.to_string(),
            instance_id: format!("pid-{pid}"),
            repo_root: format!("/repos/{label}"),
            pid,
            port: 49152,
            endpoint: "http://127.0.0.1:49152".to_string(),
            graph_entity_count: None,
            kin_home: kin_home.to_string(),
            registered_at: None,
            last_heartbeat_at: String::new(),
        }
    }

    fn two_homes() -> Vec<RegisteredRepoDaemon> {
        vec![
            registered("mine", 101, "/homes/a/.kin"),
            registered("theirs", 202, "/homes/b/.kin"),
        ]
    }

    /// The refusal that keeps a sweep inside one home: a pinned session
    /// sweeping `--all` reaches only its own daemons, and the neighbour's
    /// survives.
    #[test]
    fn a_home_scoped_sweep_stops_only_its_own_daemons() {
        let (targets, foreign) = partition_by_home(two_homes(), "/homes/a/.kin", StopScope::Home);

        assert_eq!(targets.iter().map(|d| d.pid).collect::<Vec<_>>(), vec![101]);
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign[0].pid, 202);
        assert_eq!(foreign[0].home, "/homes/b/.kin");
        assert!(foreign[0].recorded);
    }

    /// The same registry read from the other home reaches the other daemon.
    /// Without this, a partition that simply always kept the first entry would
    /// pass the test above.
    #[test]
    fn the_scoped_sweep_follows_the_callers_home() {
        let (targets, foreign) = partition_by_home(two_homes(), "/homes/b/.kin", StopScope::Home);

        assert_eq!(targets.iter().map(|d| d.pid).collect::<Vec<_>>(), vec![202]);
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign[0].pid, 101);
    }

    #[test]
    fn a_machine_sweep_stops_both_and_names_the_foreign_one() {
        let (targets, foreign) =
            partition_by_home(two_homes(), "/homes/a/.kin", StopScope::Machine);

        assert_eq!(
            targets.iter().map(|d| d.pid).collect::<Vec<_>>(),
            vec![101, 202]
        );
        assert_eq!(
            foreign.len(),
            1,
            "the sweep must disclose what it took down"
        );
        assert_eq!(foreign[0].pid, 202);
    }

    /// A daemon that recorded no home is excluded from a scoped sweep. Treating
    /// an unknown as a match is exactly the assumption that made `--all`
    /// machine-wide in the first place.
    #[test]
    fn an_unrecorded_home_is_not_treated_as_the_callers() {
        let daemons = vec![registered("legacy", 303, "")];
        let (targets, foreign) = partition_by_home(daemons, "/homes/a/.kin", StopScope::Home);

        assert!(targets.is_empty());
        assert_eq!(foreign.len(), 1);
        assert!(!foreign[0].recorded);
        assert!(foreign[0].description().contains("home unrecorded"));
    }

    #[test]
    fn a_machine_sweep_still_reaches_an_unrecorded_daemon() {
        let daemons = vec![registered("legacy", 303, "")];
        let (targets, _) = partition_by_home(daemons, "/homes/a/.kin", StopScope::Machine);
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn home_scope_distinguishes_own_foreign_and_unrecorded() {
        assert_eq!(
            registered("a", 1, "/homes/a/.kin").home_scope("/homes/a/.kin"),
            DaemonHomeScope::Own
        );
        assert_eq!(
            registered("b", 2, "/homes/b/.kin").home_scope("/homes/a/.kin"),
            DaemonHomeScope::Foreign
        );
        assert_eq!(
            registered("c", 3, "  ").home_scope("/homes/a/.kin"),
            DaemonHomeScope::Unrecorded
        );
        assert_eq!(registered("c", 3, "").home_label(), "unrecorded");
    }

    /// The census must be able to say which daemons are the caller's, which is
    /// the visibility half of the home-scoping contract the sweep enforces.
    #[test]
    fn the_census_labels_every_home() {
        let labels: Vec<_> = two_homes()
            .iter()
            .map(|d| home_scope_label(d.home_scope("/homes/a/.kin")))
            .collect();
        assert_eq!(labels, vec!["this KIN_HOME", "other KIN_HOME"]);
    }

    #[test]
    fn a_scoped_sweep_that_skips_nothing_may_stop_the_supervisor() {
        let daemons = vec![registered("mine", 101, "/homes/a/.kin")];
        let (_, foreign) = partition_by_home(daemons, "/homes/a/.kin", StopScope::Home);
        assert!(
            foreign.is_empty(),
            "nothing skipped, so the shared supervisor has no other dependant"
        );
    }

    /// The current-repo fallback must not undo the partition.
    ///
    /// That fallback exists for a worker no supervisor knows about, and it keys
    /// on "this pid is not already in the reports". A skipped daemon is not in
    /// the reports either, so keying on that alone would stop the daemon the
    /// sweep had just named as another home's and print both facts about it.
    #[test]
    fn the_current_repo_fallback_skips_a_daemon_the_partition_excluded() {
        let (targets, foreign) = partition_by_home(two_homes(), "/homes/a/.kin", StopScope::Home);
        let reported: Vec<u32> = targets.iter().map(|d| d.pid).collect();

        // The foreign daemon happens to serve the repository the caller stands
        // in, so the fallback would reach for it, and the reports cannot be
        // what protects it: the partition excluded it from them.
        let current_repo_pid = 202;
        assert!(!reported.contains(&current_repo_pid));
        assert!(
            !fallback_may_stop(
                current_repo_pid,
                reported.iter().copied(),
                foreign.iter().map(|skipped| skipped.pid),
            ),
            "a daemon named as skipped must not then be stopped by the fallback"
        );

        // The caller's own daemon is in the reports, so the fallback declines
        // it for the ordinary reason.
        assert!(
            !fallback_may_stop(
                101,
                reported.iter().copied(),
                foreign.iter().map(|skipped| skipped.pid),
            ),
            "an already-reported daemon is not the fallback's business"
        );

        // A worker neither reported nor skipped is exactly what the fallback
        // exists for, so the guard must not over-prune it.
        assert!(
            fallback_may_stop(
                999,
                reported.iter().copied(),
                foreign.iter().map(|skipped| skipped.pid),
            ),
            "an unknown lingering worker must remain stoppable"
        );
    }

    #[test]
    fn the_disclosure_json_separates_skipped_from_stopped() {
        let (_, foreign) = partition_by_home(two_homes(), "/homes/a/.kin", StopScope::Home);
        let skipped = StopDisclosure {
            scope: Some(StopScope::Home),
            foreign: foreign.clone(),
            supervisor_retained: true,
            supervisor_kept_for_workers: false,
        };
        let mut payload = serde_json::json!({});
        skipped.write_json(&mut payload);
        assert_eq!(payload["skipped_other_homes"][0]["pid"], 202);
        assert_eq!(payload["supervisor_retained"], true);
        assert!(payload.get("stopped_other_homes").is_none());

        let taken = StopDisclosure {
            scope: Some(StopScope::Machine),
            foreign,
            supervisor_retained: false,
            supervisor_kept_for_workers: false,
        };
        let mut payload = serde_json::json!({});
        taken.write_json(&mut payload);
        assert_eq!(payload["stopped_other_homes"][0]["pid"], 202);
        assert!(payload.get("skipped_other_homes").is_none());
    }

    /// A daemon a `--when-unused` stop left running is the answer that stop
    /// promised: it never escalates to a signal, never fails the command, and
    /// keeps its supervisor, which the disclosure says.
    #[test]
    fn an_in_use_daemon_is_a_settled_outcome_that_keeps_its_supervisor() {
        let in_use = StopOutcome::InUse(vec!["a client session is attached".to_string()]);
        assert!(in_use.is_settled());
        assert!(!in_use.is_success(), "an in-use daemon is still running");
        assert_eq!(in_use.detail(), "in-use");
        assert!(!StopOutcome::Timeout.is_settled());
        assert!(!StopOutcome::SignalFailed("x".to_string()).is_settled());

        let kept = StopDisclosure {
            scope: Some(StopScope::Home),
            foreign: Vec::new(),
            supervisor_retained: false,
            supervisor_kept_for_workers: true,
        };
        let mut payload = serde_json::json!({});
        kept.write_json(&mut payload);
        assert_eq!(payload["supervisor_retained"], true);
    }

    #[tokio::test]
    async fn retirement_failures_keep_routing_without_changing_explicit_stop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let identity = process_identity(std::process::id()).unwrap().unwrap();
        for response in [
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 202 Accepted\r\nContent-Length: 1\r\n\r\nx",
        ] {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = [0; 4096];
                let count = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut request))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(request[..count].starts_with(b"POST /retire "));
                socket.write_all(response.as_bytes()).await.unwrap();
            });
            let error = request_worker_retirement(
                port,
                None,
                &identity,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect_err("a failed retirement must not establish a stopped worker");
            server.await.unwrap();
            let outcome = StopOutcome::SignalFailed(error);
            assert!(StopMode::WhenUnused.keeps_supervisor_for(&outcome));
            assert!(
                !outcome.is_settled(),
                "routing retention must not hide failure"
            );
            assert!(
                !StopMode::Now.keeps_supervisor_for(&outcome),
                "ordinary explicit stop still reaches the supervisor"
            );

            let disclosure = StopDisclosure {
                scope: Some(StopScope::Home),
                supervisor_kept_for_workers: StopMode::WhenUnused.keeps_supervisor_for(&outcome),
                ..Default::default()
            };
            let mut payload = serde_json::json!({});
            disclosure.write_json(&mut payload);
            assert_eq!(payload["supervisor_retained"], true);
        }
        for outcome in [StopOutcome::Stopped, StopOutcome::NotRunning] {
            assert!(!StopMode::WhenUnused.keeps_supervisor_for(&outcome));
        }
        assert!(StopMode::WhenUnused.keeps_supervisor_for(&StopOutcome::Timeout));
        assert!(!StopMode::Now.keeps_supervisor_for(&StopOutcome::Timeout));
    }

    #[tokio::test]
    async fn retirement_deadline_covers_body_and_is_not_renewed_for_the_next_worker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let identity = process_identity(std::process::id()).unwrap().unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0; 4096];
            let count = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut request))
                .await
                .unwrap()
                .unwrap();
            assert!(request[..count].starts_with(b"POST /retire "));
            // Headers arrive promptly; the declared body never completes.
            socket
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\n\r\n{")
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), release_rx).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "an expired sweep must not contact another worker"
            );
        });
        let deadline = Instant::now() + Duration::from_millis(400);
        let first = tokio::time::timeout(
            Duration::from_secs(2),
            request_worker_retirement(port, None, &identity, deadline),
        )
        .await
        .expect("the response body must obey the original deadline");
        assert!(first.is_err());
        let second = request_worker_retirement(port, None, &identity, deadline)
            .await
            .unwrap_err();
        assert!(
            second.contains("before a request could be sent"),
            "{second}"
        );
        release_tx.send(()).unwrap();
        server.await.unwrap();
    }
}
