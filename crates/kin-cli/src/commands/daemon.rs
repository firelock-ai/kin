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
//! Neither the worker daemon nor the supervisor exposes an HTTP shutdown route,
//! so a graceful stop is SIGTERM plus a bounded wait for the process to exit.
//! The daemon's own shutdown-escalation watchdog guarantees the process dies
//! within its grace window, so the wait is a ceiling, not a fixed delay.

use anyhow::{bail, Result};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::daemon_client::{
    fetch_registered_daemons, is_port_open, is_process_alive, remove_stale_daemon_files,
    remove_stale_supervisor_files, repo_daemon_pid_path, repo_daemon_port_path,
    repo_daemon_recorded_endpoint, supervisor_pid_path, supervisor_port_path,
    supervisor_recorded_endpoint, RegisteredRepoDaemon,
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

/// Outcome of a graceful stop request against one recorded pid.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StopOutcome {
    /// No live process was found for the pid — nothing to stop.
    NotRunning,
    /// SIGTERM delivered and the process exited within the wait window.
    Stopped,
    /// SIGTERM delivered but the process was still alive after the wait window.
    Timeout,
    /// Delivering SIGTERM failed for a reason other than the process being gone.
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

#[cfg(unix)]
fn send_sigterm(pid: u32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn send_sigterm(pid: u32) -> std::io::Result<()> {
    let _ = pid;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "signal-based daemon stop is only supported on unix platforms",
    ))
}

/// Send SIGTERM to `pid` and wait up to `wait` for the process to exit. Returns
/// the classified outcome; never kills a process we did not intend to (the pid
/// comes from Kin's own endpoint files).
fn stop_pid_graceful(pid: u32, wait: Duration) -> StopOutcome {
    if !is_process_alive(pid) {
        return StopOutcome::NotRunning;
    }
    if let Err(error) = send_sigterm(pid) {
        // A signal failure right after the alive check is almost always a race:
        // the process exited on its own between the two. Re-check before
        // reporting a hard failure.
        if !is_process_alive(pid) {
            return StopOutcome::NotRunning;
        }
        return StopOutcome::SignalFailed(error.to_string());
    }
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if !is_process_alive(pid) {
            return StopOutcome::Stopped;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if is_process_alive(pid) {
        StopOutcome::Timeout
    } else {
        StopOutcome::Stopped
    }
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

    let pid = resolve_repo_worker_pid(&kin_root, &working_dir).await;

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

    let outcome = stop_pid_graceful(pid, stop_timeout());
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
async fn resolve_repo_worker_pid(kin_root: &Path, working_dir: &Path) -> Option<u32> {
    let (local_pid, _) = repo_daemon_recorded_endpoint(kin_root);
    if let Some(pid) = local_pid {
        if is_process_alive(pid) {
            return Some(pid);
        }
    }
    // Local file missing or stale — ask the supervisor if it still routes a live
    // worker for this repo root.
    let url = supervisor_url_if_running()?;
    let daemons = fetch_registered_daemons(&url).await.ok()?;
    let target = canonical(working_dir);
    daemons
        .into_iter()
        .find(|d| canonical(Path::new(&d.repo_root)) == target && is_process_alive(d.pid))
        .map(|d| d.pid)
}

async fn stop_all(json: bool, quiet: bool) -> Result<()> {
    let wait = stop_timeout();
    let mut reports: Vec<StopReport> = Vec::new();

    // Stop every worker the supervisor knows about first, so the supervisor is
    // the last thing standing (it can prune its own routes as workers die).
    let supervisor_url = supervisor_url_if_running();
    if let Some(url) = &supervisor_url {
        let daemons = fetch_registered_daemons(url).await.unwrap_or_default();
        for daemon in daemons {
            let label = if daemon.display_name.trim().is_empty() {
                daemon.repo_id.clone()
            } else {
                daemon.display_name.clone()
            };
            let outcome = stop_pid_graceful(daemon.pid, wait);
            if outcome.is_success() {
                // Clear the worker's endpoint files too (repo_root/.kin/daemon.*).
                remove_stale_daemon_files(&Path::new(&daemon.repo_root).join(".kin"));
            }
            reports.push(StopReport {
                kind: "repo-daemon",
                label,
                pid: daemon.pid,
                outcome,
            });
        }
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
                    let outcome = stop_pid_graceful(pid, wait);
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

    // Supervisor last.
    let (sup_pid, _) = supervisor_recorded_endpoint();
    if let Some(pid) = sup_pid {
        if is_process_alive(pid) {
            let outcome = stop_pid_graceful(pid, wait);
            if outcome.is_success() {
                remove_stale_supervisor_files();
            }
            reports.push(StopReport {
                kind: "supervisor",
                label: "supervisor".to_string(),
                pid,
                outcome,
            });
        } else {
            // Recorded but dead — clear stale files.
            remove_stale_supervisor_files();
        }
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
                    "{} (pid {}): STILL ALIVE after SIGTERM + {}s wait",
                    r.label,
                    r.pid,
                    stop_timeout().as_secs()
                ),
                StopOutcome::SignalFailed(err) => {
                    format!("{} (pid {}): SIGTERM failed: {}", r.label, r.pid, err)
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
    fn stop_outcome_success_semantics() {
        assert!(StopOutcome::Stopped.is_success());
        assert!(StopOutcome::NotRunning.is_success());
        assert!(!StopOutcome::Timeout.is_success());
        assert!(!StopOutcome::SignalFailed("boom".to_string()).is_success());
    }

    #[test]
    fn stop_pid_graceful_reports_not_running_for_dead_pid() {
        // A pid that is essentially guaranteed not to exist must classify as
        // NotRunning without sending a signal anywhere.
        let outcome = stop_pid_graceful(u32::MAX - 1, Duration::from_millis(50));
        assert_eq!(outcome, StopOutcome::NotRunning);
    }

    #[cfg(unix)]
    #[test]
    fn stop_pid_graceful_stops_a_live_process() {
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
        assert!(is_process_alive(pid));

        let reaper = std::thread::spawn(move || {
            let _ = child.wait();
        });
        let outcome = stop_pid_graceful(pid, Duration::from_secs(10));
        let _ = reaper.join();

        assert_eq!(outcome, StopOutcome::Stopped);
    }
}
