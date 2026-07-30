// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof of `kin daemon status` / `kin daemon stop`.
//!
//! Brings a real worker daemon up through a normal daemon-backed command, then
//! drives the new command group against it: `status` reports the running
//! topology, `stop` gracefully terminates the current repo's worker (clean exit
//! 0, process actually gone), and `stop --all` reaps the supervisor.
//!
//! Hermetic: `KIN_REGISTRY_PATH` points the supervisor/registry state at a
//! scratch dir so the test never touches the user's real `~/.kin` supervisor or
//! any daemon serving another repo. The scratch repo has no source files, so the
//! daemon's background embedding worker has nothing to embed and never loads a
//! model — the test needs no GPU.

use kin_cli::daemon_client::is_process_alive;
use serde_json::Value;
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

mod common;

/// Run `kin <args>` in `repo` with a fully isolated daemon/supervisor
/// environment. The long idle timeouts keep the daemon from self-stopping mid
/// test; the fresh daemon binary matches this CLI's graph schema.
fn kin(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .args(args)
        .current_dir(repo)
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "120")
        .env("KIN_SUPERVISOR_IDLE_TIMEOUT_SECS", "120")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "60")
        .output()
        .expect("run kin")
}

fn stdout_json(output: &Output, context: &str) -> Value {
    assert!(
        output.status.success(),
        "{context} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{context} stdout is not valid JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn wait_until_dead(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while is_process_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn daemon_status_and_stop_lifecycle() {
    let root = tempfile::tempdir().expect("temp root");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo dir");

    kin_core::init(&repo).expect("init scratch repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let runtime_root = runtime
        .registry_path()
        .parent()
        .expect("isolated registry parent")
        .to_path_buf();

    // ── status with nothing running: must NOT autostart a supervisor ──────────
    let status = stdout_json(
        &kin(&runtime, &repo, &["daemon", "status", "--json"]),
        "kin daemon status (idle)",
    );
    assert_eq!(status["schema"], "kin.daemon-status.v1");
    assert_eq!(status["supervisor"]["state"], "not running");
    assert!(
        !runtime_root.join("supervisor.pid").exists(),
        "status must not spawn a supervisor"
    );

    // ── bring the worker daemon up through a normal daemon-backed command ─────
    let up = kin(&runtime, &repo, &["support", "--json"]);
    assert!(
        up.status.success(),
        "kin support (autostart) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );

    let pid_path = repo.join(".kin/daemon.pid");
    let worker_pid = read_pid(&pid_path).expect("worker daemon.pid after autostart");
    assert!(
        is_process_alive(worker_pid),
        "worker daemon pid {worker_pid} should be alive after autostart"
    );

    // ── status with the worker up: current repo reports running, pid matches ──
    let status = stdout_json(
        &kin(&runtime, &repo, &["daemon", "status", "--json"]),
        "kin daemon status (running)",
    );
    assert_eq!(status["supervisor"]["state"], "running");
    assert_eq!(status["current_repo"]["state"], "running");
    assert_eq!(
        status["current_repo"]["pid"].as_u64(),
        Some(worker_pid as u64)
    );

    // ── stop the current repo's worker: clean exit 0, process gone ────────────
    let stop = kin(&runtime, &repo, &["daemon", "stop"]);
    assert!(
        stop.status.success(),
        "kin daemon stop exited nonzero: stdout={} stderr={}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stop.stdout).contains("stopped"),
        "stop report should say stopped: {}",
        String::from_utf8_lossy(&stop.stdout)
    );

    wait_until_dead(worker_pid, Duration::from_secs(5));
    assert!(
        !is_process_alive(worker_pid),
        "worker daemon pid {worker_pid} still alive after `kin daemon stop`"
    );
    assert!(
        !pid_path.exists(),
        "daemon.pid must be cleared after a confirmed stop"
    );

    // ── status after stop: current repo no longer running ─────────────────────
    let status = stdout_json(
        &kin(&runtime, &repo, &["daemon", "status", "--json"]),
        "kin daemon status (after stop)",
    );
    assert_eq!(status["current_repo"]["state"], "not running");

    // ── stop --all: reaps the supervisor (supervisor last), clean exit 0 ──────
    let sup_pid = read_pid(&runtime_root.join("supervisor.pid"));
    let stop_all = kin(&runtime, &repo, &["daemon", "stop", "--all"]);
    assert!(
        stop_all.status.success(),
        "kin daemon stop --all exited nonzero: stdout={} stderr={}",
        String::from_utf8_lossy(&stop_all.stdout),
        String::from_utf8_lossy(&stop_all.stderr)
    );
    if let Some(sup_pid) = sup_pid {
        wait_until_dead(sup_pid, Duration::from_secs(5));
        assert!(
            !is_process_alive(sup_pid),
            "supervisor pid {sup_pid} still alive after `kin daemon stop --all`"
        );
    }
}
