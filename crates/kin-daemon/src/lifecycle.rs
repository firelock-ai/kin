// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon lifecycle management: PID file, auto-start, idle shutdown.
//!
//! The daemon IS the runtime — every CLI command routes through it.
//! This module ensures the daemon is always available by auto-starting
//! it when any `kin` command runs and there's no daemon serving the repo.
//!
//! Process safety guarantees:
//! - A lock file (`daemon.lock`) prevents concurrent CLI invocations from
//!   racing to start multiple daemon processes.
//! - Stale PID files are detected via `kill(pid, 0)` and cleaned up.
//! - If a PID file references a living but unresponsive process, we send
//!   SIGTERM and wait briefly before spawning a replacement.
//! - The daemon writes its PID atomically on startup and removes it on
//!   graceful shutdown.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tracing::{debug, info, warn};

// ── PID File Management ──────────────────────────────────────────────────

/// Write the current process PID to `.kin/daemon.pid`.
///
/// Called by the daemon on startup so CLI processes can discover it.
/// Writes atomically (write-to-tmp then rename) to prevent partial reads.
pub fn write_pid_file(kin_root: &Path) {
    let pid_path = kin_root.join("daemon.pid");
    let tmp_path = kin_root.join("daemon.pid.tmp");
    let pid = std::process::id();

    if let Err(e) = std::fs::write(&tmp_path, pid.to_string()) {
        warn!(error = %e, path = %pid_path.display(), "failed to write daemon PID file");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &pid_path) {
        warn!(error = %e, "failed to atomically install PID file");
        let _ = std::fs::remove_file(&tmp_path);
    } else {
        debug!(pid, path = %pid_path.display(), "wrote daemon PID file");
    }
}

/// Remove the PID file on graceful shutdown.
///
/// Only removes if the PID in the file matches our own process — prevents
/// a restarted daemon from accidentally deleting a successor's PID file.
pub fn remove_pid_file(kin_root: &Path) {
    let pid_path = kin_root.join("daemon.pid");
    if let Ok(content) = std::fs::read_to_string(&pid_path) {
        if let Ok(file_pid) = content.trim().parse::<u32>() {
            if file_pid == std::process::id() {
                let _ = std::fs::remove_file(&pid_path);
                debug!(path = %pid_path.display(), "removed daemon PID file");
            } else {
                debug!(
                    our_pid = std::process::id(),
                    file_pid,
                    "PID file belongs to another process, not removing"
                );
            }
        }
    }
}

/// Check if a process is alive (Unix: kill -0).
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true // conservative: assume alive on non-Unix
    }
}

/// Send SIGTERM to a process (Unix only). Returns true if the signal was sent.
#[cfg(unix)]
fn send_sigterm(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) == 0 }
}

/// Read the PID from `.kin/daemon.pid` and check if the process is alive.
///
/// Returns `Some(pid)` if the file exists and the process is running.
/// Cleans up stale PID files (dead process) automatically.
pub fn read_pid_if_alive(kin_root: &Path) -> Option<u32> {
    let pid_path = kin_root.join("daemon.pid");
    let content = std::fs::read_to_string(&pid_path).ok()?;
    let pid: u32 = content.trim().parse().ok()?;

    if is_process_alive(pid) {
        Some(pid)
    } else {
        // Stale PID file — clean it up.
        let _ = std::fs::remove_file(&pid_path);
        debug!(pid, "removed stale daemon PID file (process not running)");
        None
    }
}

// ── Lock File (Prevents Duplicate Starts) ────────────────────────────────

/// Acquire an exclusive lock file to prevent concurrent auto-start races.
///
/// Returns the lock guard. If another process holds the lock, blocks for
/// up to `timeout` then returns None.
fn try_acquire_start_lock(kin_root: &Path) -> Option<StartLock> {
    let lock_path = kin_root.join("daemon.lock");

    // Open or create the lock file.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .ok()?;

    // Try non-blocking exclusive lock.
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Some(StartLock { _file: file, path: lock_path }),
        Err(_) => {
            debug!("another process holds daemon.lock, skipping auto-start");
            None
        }
    }
}

/// RAII guard for the daemon start lock file.
struct StartLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl Drop for StartLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ── Daemon Binary Discovery ──────────────────────────────────────────────

/// Locate the `kin-daemon` binary.
///
/// Strategy: look next to the current executable first (same build target dir),
/// then fall back to PATH lookup.
fn find_daemon_binary() -> Option<PathBuf> {
    // Same directory as the running `kin` binary.
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    // Fall back to PATH.
    which::which("kin-daemon").ok()
}

// ── Auto-Start ───────────────────────────────────────────────────────────

/// Auto-start the daemon for a repo if it's not already running.
///
/// Returns the daemon's base URL on success. This is the core of the
/// daemon-as-runtime model: every CLI command calls this before doing
/// anything else.
///
/// Process safety:
/// 1. Health check existing daemon → already running? Return immediately.
/// 2. Acquire exclusive lock file → prevents multiple CLI processes from
///    spawning duplicate daemons.
/// 3. After lock, re-check health (another process may have started it
///    while we waited for the lock).
/// 4. Clean up stale processes: if PID alive but unresponsive, SIGTERM it
///    and wait for exit before spawning replacement.
/// 5. Spawn `kin-daemon --repo <path>` as a detached background process.
/// 6. Poll health endpoint with exponential backoff until ready.
pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String, AutoStartError> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

    // ── Fast path: daemon already healthy ────────────────────────────────
    if is_daemon_healthy(&daemon_url).await {
        debug!("daemon already running at {}", daemon_url);
        return Ok(daemon_url);
    }

    // ── Acquire start lock (prevents duplicate spawns) ──────────────────
    let _lock = match try_acquire_start_lock(kin_root) {
        Some(lock) => lock,
        None => {
            // Another CLI process is starting the daemon. Wait for it.
            debug!("waiting for another process to finish starting daemon...");
            if wait_for_health(&daemon_url, Duration::from_secs(30)).await {
                return Ok(daemon_url);
            }
            return Err(AutoStartError::StartupTimeout);
        }
    };

    // ── Re-check after acquiring lock (race window) ─────────────────────
    if is_daemon_healthy(&daemon_url).await {
        debug!("daemon became healthy while acquiring lock");
        return Ok(daemon_url);
    }

    // ── Handle stale processes ──────────────────────────────────────────
    if let Some(stale_pid) = read_pid_if_alive(kin_root) {
        warn!(pid = stale_pid, "daemon process alive but not responding to health check");

        // Give it a chance — maybe it's still starting up.
        if wait_for_health(&daemon_url, Duration::from_secs(5)).await {
            return Ok(daemon_url);
        }

        // Still unresponsive. SIGTERM it so we don't leave zombies.
        #[cfg(unix)]
        {
            info!(pid = stale_pid, "sending SIGTERM to unresponsive daemon");
            send_sigterm(stale_pid);
            // Wait up to 5s for it to exit.
            for _ in 0..50 {
                if !is_process_alive(stale_pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if is_process_alive(stale_pid) {
                warn!(pid = stale_pid, "daemon did not exit after SIGTERM, proceeding anyway");
            }
        }

        // Clean up PID file.
        let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
    }

    // ── Spawn the daemon ────────────────────────────────────────────────
    let daemon_bin = find_daemon_binary().ok_or(AutoStartError::BinaryNotFound)?;

    let working_dir = kin_root
        .parent()
        .ok_or_else(|| AutoStartError::InvalidLayout(".kin has no parent".into()))?;

    info!(
        binary = %daemon_bin.display(),
        repo = %working_dir.display(),
        "auto-starting kin daemon"
    );

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args(["--repo", &working_dir.display().to_string()]);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    // Detach on Unix so the daemon outlives the CLI process and doesn't
    // become a zombie when the CLI exits.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                // Create a new session so SIGINT from the terminal
                // doesn't propagate to the daemon.
                libc::setsid();
                Ok(())
            });
        }
    }

    let child = cmd
        .spawn()
        .map_err(|e| AutoStartError::SpawnFailed(e.to_string()))?;

    debug!(child_pid = child.id(), "spawned kin-daemon process");

    // Wait for the daemon to become healthy.
    if wait_for_health(&daemon_url, Duration::from_secs(30)).await {
        info!("daemon started and healthy at {}", daemon_url);
        Ok(daemon_url)
    } else {
        Err(AutoStartError::StartupTimeout)
    }
}

// ── Health Checking ──────────────────────────────────────────────────────

/// Check if the daemon health endpoint responds.
async fn is_daemon_healthy(base_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(300))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Wait for the daemon health endpoint with exponential backoff.
async fn wait_for_health(base_url: &str, max_wait: Duration) -> bool {
    let start = std::time::Instant::now();
    let mut delay = Duration::from_millis(50);

    while start.elapsed() < max_wait {
        if is_daemon_healthy(base_url).await {
            return true;
        }
        tokio::time::sleep(delay).await;
        delay = std::cmp::min(delay.saturating_mul(2), Duration::from_millis(500));
    }
    false
}

// ── Error Types ──────────────────────────────────────────────────────────

/// Errors that can occur during daemon auto-start.
#[derive(Debug, thiserror::Error)]
pub enum AutoStartError {
    #[error("kin-daemon binary not found (not in PATH or next to kin binary)")]
    BinaryNotFound,
    #[error("failed to spawn kin-daemon: {0}")]
    SpawnFailed(String),
    #[error("daemon failed to start within timeout")]
    StartupTimeout,
    #[error("invalid .kin layout: {0}")]
    InvalidLayout(String),
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pid_if_alive_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_pid_if_alive(dir.path()).is_none());
    }

    #[test]
    fn read_pid_if_alive_returns_none_for_stale_pid() {
        let dir = tempfile::tempdir().unwrap();
        // Write a PID that almost certainly doesn't exist.
        std::fs::write(dir.path().join("daemon.pid"), "999999999").unwrap();
        assert!(read_pid_if_alive(dir.path()).is_none());
        // Stale file should be cleaned up.
        assert!(!dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn write_and_read_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        write_pid_file(dir.path());
        let pid = read_pid_if_alive(dir.path());
        assert_eq!(pid, Some(std::process::id()));
    }

    #[test]
    fn remove_pid_file_only_removes_own_pid() {
        let dir = tempfile::tempdir().unwrap();
        // Write a PID that's not ours.
        std::fs::write(dir.path().join("daemon.pid"), "1").unwrap();
        remove_pid_file(dir.path());
        // Should NOT have been removed (PID 1 != our PID).
        assert!(dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn remove_pid_file_removes_own_pid() {
        let dir = tempfile::tempdir().unwrap();
        write_pid_file(dir.path());
        assert!(dir.path().join("daemon.pid").exists());
        remove_pid_file(dir.path());
        assert!(!dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn start_lock_prevents_double_acquire() {
        let dir = tempfile::tempdir().unwrap();
        let _lock1 = try_acquire_start_lock(dir.path());
        assert!(_lock1.is_some());
        // Second acquire should fail (non-blocking).
        let lock2 = try_acquire_start_lock(dir.path());
        assert!(lock2.is_none());
    }

    #[test]
    fn start_lock_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = try_acquire_start_lock(dir.path());
            assert!(_lock.is_some());
        }
        // After drop, should be acquirable again.
        let lock2 = try_acquire_start_lock(dir.path());
        assert!(lock2.is_some());
    }
}
