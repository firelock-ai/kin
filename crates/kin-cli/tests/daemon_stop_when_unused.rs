// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin daemon stop --all --when-unused` leaves a daemon a client is using.
//!
//! Real processes throughout: a worker brought up by an ordinary command, and a
//! stand-in client, a live process whose session the worker holds the way a
//! `kin with` launcher or an editor holds one. With the client attached, the
//! stop leaves the worker and its supervisor running and names why, and it
//! exits 0, because that is the answer it promised. Once the client's process
//! is gone, the worker it asked to retire goes by itself, and the same stop
//! then takes the supervisor.
//!
//! Hermetic in the way `daemon_stop.rs` is: the isolated runtime points the
//! registry and supervisor at a scratch directory, and the scratch repository
//! has no source files, so nothing is embedded.

#![cfg(unix)]

use kin_cli::daemon_client::is_process_alive;
use serde_json::Value;
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

mod common;

fn kin(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .args(args)
        .current_dir(repo)
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
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
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{context} stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn read_number(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
}

fn wait_until_dead(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while is_process_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A live process standing in for a client, killed on drop so a failed
/// assertion never leaks it.
struct StandInClient(std::process::Child);

impl Drop for StandInClient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_stop_when_unused_leaves_a_daemon_its_client_still_needs() {
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

    let up = kin(&runtime, &repo, &["support", "--json"]);
    assert!(
        up.status.success(),
        "autostart failed: stdout={} stderr={}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );
    let kin_root = repo.join(".kin");
    let worker_pid = read_number(&kin_root.join("daemon.pid")).expect("worker pid");
    let port = read_number(&kin_root.join("daemon.port")).expect("worker port") as u16;
    let supervisor_pid = read_number(&runtime_root.join("supervisor.pid"));

    // Attach a client: a live process, and a session naming it.
    let client = StandInClient(
        std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("spawn the stand-in client"),
    );
    let mut attach = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{port}/session"))
        .json(&serde_json::json!({
            "vendor": "claude-code",
            "client_name": "stand-in-client",
            "transport": "mcp",
            "pid": client.0.id(),
            "cwd": repo.display().to_string(),
        }));
    if let Ok(token) = std::fs::read_to_string(kin_root.join("daemon.token")) {
        attach = attach.bearer_auth(token.trim());
    }
    let attached = attach.send().expect("register the client's session");
    assert!(
        attached.status().is_success(),
        "session registration failed: {}",
        attached.status()
    );

    // The client is attached, so the stop leaves the worker and says why.
    let kept = stdout_json(
        &kin(
            &runtime,
            &repo,
            &["daemon", "stop", "--all", "--when-unused", "--json"],
        ),
        "kin daemon stop --all --when-unused (client attached)",
    );
    let worker = kept["stopped"]
        .as_array()
        .expect("stopped is a list")
        .iter()
        .find(|entry| entry["kind"] == "repo-daemon")
        .unwrap_or_else(|| panic!("the stop reported no repository daemon: {kept}"))
        .clone();
    assert_eq!(worker["result"], "in-use", "{kept}");
    assert!(
        worker["in_use"].as_array().is_some_and(|reasons| reasons
            .iter()
            .any(|reason| reason == "a client session is attached")),
        "the stop must name the attached client: {kept}"
    );
    assert_eq!(kept["supervisor_retained"], true, "{kept}");
    assert!(
        is_process_alive(worker_pid),
        "a daemon a client was attached to was stopped"
    );
    if let Some(pid) = supervisor_pid {
        assert!(
            is_process_alive(pid),
            "the supervisor of an in-use daemon was stopped"
        );
    }

    // The client goes. The worker was asked to retire, so once the session
    // sweeper reaps the dead client's session it exits by itself.
    drop(client);
    wait_until_dead(worker_pid, Duration::from_secs(90));
    assert!(
        !is_process_alive(worker_pid),
        "a retiring daemon outlived its last client"
    );

    // Nothing is left to keep the supervisor.
    let done = kin(
        &runtime,
        &repo,
        &["daemon", "stop", "--all", "--when-unused"],
    );
    assert!(
        done.status.success(),
        "the final stop failed: stdout={} stderr={}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    );
    if let Some(pid) = supervisor_pid {
        wait_until_dead(pid, Duration::from_secs(10));
        assert!(
            !is_process_alive(pid),
            "the supervisor outlived its last daemon's stop"
        );
    }
}
