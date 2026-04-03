// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon lifecycle: if it's there, use it. If it's not, start it.
//!
//! The daemon writes `.kin/daemon.pid` and `.kin/daemon.port` on startup.
//! The CLI reads those files to connect. If the daemon isn't running, the
//! CLI spawns it and waits for the port to open.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tracing::info;

// ── Daemon State Files ──────────────────────────────────────────────────

/// Write PID file atomically (write tmp + rename).
pub fn write_pid_file(kin_root: &Path) {
    let pid = std::process::id();
    let tmp = kin_root.join("daemon.pid.tmp");
    let dst = kin_root.join("daemon.pid");
    if std::fs::write(&tmp, pid.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &dst);
    }
}

/// Write port file so the CLI knows where to connect.
pub fn write_port_file(kin_root: &Path, port: u16) {
    let _ = std::fs::write(kin_root.join("daemon.port"), port.to_string());
}

/// Read port from `.kin/daemon.port`.
pub fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Remove PID file, but only if it's ours (prevents removing a successor's).
pub fn remove_pid_file(kin_root: &Path) {
    let path = kin_root.join("daemon.pid");
    if let Ok(content) = std::fs::read_to_string(&path) {
        if content.trim().parse::<u32>().ok() == Some(std::process::id()) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Is the process with this PID alive?
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Is the daemon running for this repo? Checks PID file + port reachable.
pub fn daemon_is_up(kin_root: &Path) -> Option<u16> {
    let pid: u32 = std::fs::read_to_string(kin_root.join("daemon.pid"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if !is_process_alive(pid) {
        // Stale — clean up.
        let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
        let _ = std::fs::remove_file(kin_root.join("daemon.port"));
        return None;
    }
    let port = read_port_file(kin_root)?;
    if is_port_open(port) {
        Some(port)
    } else {
        None // PID alive but port not open — daemon still starting or wedged
    }
}

// ── Port Checking ───────────────────────────────────────────────────────

fn is_port_open(port: u16) -> bool {
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

fn find_free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

// ── Daemon Binary Discovery ─────────────────────────────────────────────

fn find_daemon_binary() -> Option<PathBuf> {
    // Next to the running kin binary.
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    which::which("kin-daemon").ok()
}

// ── The One Function ────────────────────────────────────────────────────

/// Ensure the daemon is running for this repo. Returns its base URL.
///
/// 1. If it's already up → return its URL. (~1ms)
/// 2. If not → start it, wait for the port to open, return URL. (~2-3s)
/// 3. If start fails → return Err (caller falls back to direct snapshot).
///
/// No timeouts, no escape hatches, no lock file dances. Simple.
pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String, AutoStartError> {
    // ── If it's there, use it ───────────────────────────────────────────
    if let Some(port) = daemon_is_up(kin_root) {
        return Ok(format!("http://127.0.0.1:{}", port));
    }

    // ── If it's not, start it ───────────────────────────────────────────
    let daemon_bin = find_daemon_binary().ok_or(AutoStartError::BinaryNotFound)?;
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| AutoStartError::InvalidLayout(".kin has no parent".into()))?;
    let port = find_free_port().unwrap_or(4219);

    info!(binary = %daemon_bin.display(), repo = %working_dir.display(), port, "starting daemon");

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args([
        "--repo",
        &working_dir.display().to_string(),
        "--port",
        &port.to_string(),
    ]);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    cmd.spawn()
        .map_err(|e| AutoStartError::SpawnFailed(e.to_string()))?;

    // Wait for the port to open. The daemon loads the snapshot and binds —
    // typically 2-3s. We check every 100ms, give up after 10s.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if is_port_open(port) {
            info!(port, "daemon is up");
            return Ok(format!("http://127.0.0.1:{}", port));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(AutoStartError::StartupTimeout)
}

// ── macOS Launch Agent (start on boot) ───────────────────────────────────

/// Register a launchd Launch Agent so the daemon starts on login.
///
/// Called by `kin init` after initializing a repo. Creates a per-repo
/// plist in ~/Library/LaunchAgents/ and loads it immediately.
///
/// Each repo gets its own agent with a unique label:
///   ai.firelock.kin-daemon.<repo_id>
#[cfg(target_os = "macos")]
pub fn register_launch_agent(kin_root: &Path) -> Result<(), String> {
    let working_dir = kin_root.parent().ok_or("no parent")?;
    let repo_id = working_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");

    let daemon_bin =
        find_daemon_binary().ok_or_else(|| "kin-daemon binary not found".to_string())?;

    let port = read_port_file(kin_root).unwrap_or_else(|| find_free_port().unwrap_or(4219));

    let label = format!("ai.firelock.kin-daemon.{}", repo_id);
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>--repo</string>
        <string>{repo}</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/tmp/kin-daemon-{id}.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/kin-daemon-{id}.stderr.log</string>
</dict>
</plist>"#,
        label = label,
        bin = daemon_bin.display(),
        repo = working_dir.display(),
        port = port,
        id = repo_id,
    );

    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let launch_agents = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&launch_agents).map_err(|e| format!("create LaunchAgents dir: {e}"))?;

    let plist_path = launch_agents.join(format!("{label}.plist"));

    // Unload old version if it exists (idempotent).
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap()])
            .output();
    }

    std::fs::write(&plist_path, &plist).map_err(|e| format!("write plist: {e}"))?;

    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .output()
        .map_err(|e| format!("launchctl load: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl load failed: {stderr}"));
    }

    info!(label = %label, "registered macOS Launch Agent");
    Ok(())
}

/// Unregister the Launch Agent for a repo.
///
/// Called by `kin eject` before removing `.kin/`.
#[cfg(target_os = "macos")]
pub fn unregister_launch_agent(kin_root: &Path) {
    let working_dir = match kin_root.parent() {
        Some(p) => p,
        None => return,
    };
    let repo_id = working_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");

    let label = format!("ai.firelock.kin-daemon.{}", repo_id);
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        let plist_path = home
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", plist_path.to_str().unwrap()])
                .output();
            let _ = std::fs::remove_file(&plist_path);
            info!(label = %label, "unregistered macOS Launch Agent");
        }
    }
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn register_launch_agent(_kin_root: &Path) -> Result<(), String> {
    Ok(()) // Linux: TODO systemd user unit
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn unregister_launch_agent(_kin_root: &Path) {}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AutoStartError {
    #[error("kin-daemon binary not found (not in PATH or next to kin binary)")]
    BinaryNotFound,
    #[error("failed to spawn kin-daemon: {0}")]
    SpawnFailed(String),
    #[error("daemon failed to start within 10s")]
    StartupTimeout,
    #[error("invalid .kin layout: {0}")]
    InvalidLayout(String),
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_pid_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "999999999").unwrap();
        std::fs::write(dir.path().join("daemon.port"), "4219").unwrap();
        assert!(daemon_is_up(dir.path()).is_none());
        assert!(!dir.path().join("daemon.pid").exists());
        assert!(!dir.path().join("daemon.port").exists());
    }

    #[test]
    fn missing_files_means_not_up() {
        let dir = tempfile::tempdir().unwrap();
        assert!(daemon_is_up(dir.path()).is_none());
    }

    #[test]
    fn write_and_remove_pid() {
        let dir = tempfile::tempdir().unwrap();
        write_pid_file(dir.path());
        assert!(dir.path().join("daemon.pid").exists());
        remove_pid_file(dir.path());
        assert!(!dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn remove_pid_wont_delete_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "1").unwrap();
        remove_pid_file(dir.path()); // PID 1 != ours
        assert!(dir.path().join("daemon.pid").exists());
    }
}
