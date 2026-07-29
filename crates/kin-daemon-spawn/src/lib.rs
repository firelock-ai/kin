// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one definition of how a repo daemon is started and how its port is
//! learned.
//!
//! Two callers start daemons: the CLI autostart path and the MCP revival path.
//! They cannot share code through either of their own crates — `kin-cli`
//! depends on `kin-mcp`, and `kin-mcp` cannot depend on `kin-daemon` because
//! `kin-daemon` already depends on `kin-mcp`. So each grew its own copy of the
//! contract, and the MCP copy has now twice regressed to a weaker version of a
//! rule the CLI copy already enforced.
//!
//! This crate is the shared floor beneath both. It deliberately holds the
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

use std::path::{Path, PathBuf};
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

/// File the daemon writes its bound port into once it is listening.
pub const PORT_FILE_NAME: &str = "daemon.port";

/// File the daemon writes its PID into as part of endpoint publication.
pub const PID_FILE_NAME: &str = "daemon.pid";

#[cfg(unix)]
const TEST_RUNTIME_OWNER_ENV: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";

#[cfg(unix)]
const TEST_RUNTIME_PROCESS_GROUP_ENV: &str = "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP";

/// How long to wait between polls of the port file.
const PORT_POLL_INTERVAL: Duration = Duration::from_millis(200);

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
        detach_from_caller(&mut cmd);
        cmd
    }
}

/// Put the daemon in its own session so it outlives the process that started
/// it and never receives the caller's terminal signals.
///
/// A test runtime is the one exception. Its guardian puts the invoking process
/// in a stable process group and passes both an owner capability and the exact
/// group id. Keeping the daemon in that verified group lets the harness reap
/// the complete process tree even if graceful product cleanup fails. The owner
/// marker alone is never sufficient: a missing, malformed, non-positive, or
/// mismatched group keeps normal production detachment enabled.
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
    #[cfg(not(unix))]
    {
        let _ = cmd;
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
                return Err(PortWaitError::ChildExited(status))
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

/// Clear an orphaned port record so a fresh spawn is not read against a dead
/// predecessor's port. Returns whether anything was removed.
pub fn clear_orphaned_port_record(kin_root: &Path) -> bool {
    if !port_record_is_orphaned(kin_root) {
        return false;
    }
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
}

/// Resolve the supervisor endpoint through the installed seam, if there is one.
pub async fn supervisor_url_for_spawn() -> Option<String> {
    let registrar = registrar()?;
    registrar.supervisor_url().await
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
}
