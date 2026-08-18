// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof of the daemon-owned port handshake.
//!
//! The daemon binds an OS-assigned ephemeral port (`--port 0`) and publishes the
//! *actual* bound port to `.kin/daemon.port`. The CLI reads the port from that
//! file instead of reserving a port and releasing it before the daemon re-binds
//! — the reserve-release-rebind window a sibling process could steal, killing
//! the daemon during startup under parallel load.
//!
//! Because the daemon owns port selection, this test needs no `#[serial]` and no
//! reserved port to collide on: it spins up its own daemon against a scratch
//! tempdir store on an ephemeral port and never touches the shared runtime or
//! `~/.kin`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessStatus, System};
use tokio::process::Command;

mod common;

use common::{
    isolate_daemon_test_command, spawn_daemon_test_command, terminate_daemon, DaemonChild,
};

/// Readiness budget for the daemon to bind and serve. Generous so two CI runs
/// sharing a runner can both come up under load without a false timeout; a
/// daemon that dies during startup is detected eagerly via its child handle, so
/// this only ever bounds a slow-but-live startup, never a dead one.
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);
const CONTAINMENT_TREE_PARENT: &str = "KIN_TEST_DAEMON_CONTAINMENT_TREE_PARENT";
const CONTAINMENT_TREE_DESCENDANT: &str = "KIN_TEST_DAEMON_CONTAINMENT_TREE_DESCENDANT";
#[cfg(unix)]
const CONTAINMENT_HARD_PARENT: &str = "KIN_TEST_DAEMON_CONTAINMENT_HARD_PARENT";

fn publish_marker_atomically(marker: &Path, contents: &[u8], context: &str) {
    let mut staged_name = marker.as_os_str().to_os_string();
    staged_name.push(".staged");
    let staged = PathBuf::from(staged_name);
    std::fs::write(&staged, contents)
        .unwrap_or_else(|error| panic!("{context}: write staged marker: {error}"));
    std::fs::rename(&staged, marker)
        .unwrap_or_else(|error| panic!("{context}: publish staged marker: {error}"));
}

#[test]
fn direct_containment_tree_worker() {
    if let Some(marker) = std::env::var_os(CONTAINMENT_TREE_DESCENDANT) {
        publish_marker_atomically(
            &PathBuf::from(marker),
            std::process::id().to_string().as_bytes(),
            "publish direct-containment descendant pid",
        );
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let Some(marker) = std::env::var_os(CONTAINMENT_TREE_PARENT) else {
        return;
    };
    let mut descendant = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "direct_containment_tree_worker", "--nocapture"])
        .env(CONTAINMENT_TREE_DESCENDANT, marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn direct-containment descendant");
    let _ = descendant.wait();
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn direct_containment_hard_parent_worker() {
    let Some(root) = std::env::var_os(CONTAINMENT_HARD_PARENT) else {
        return;
    };
    let root = PathBuf::from(root);
    let descendant_marker = root.join("hard-parent-descendant.pid");
    let ready = root.join("hard-parent.ready");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    isolate_daemon_test_command(&mut command);
    command
        .args(["--exact", "direct_containment_tree_worker", "--nocapture"])
        .env(CONTAINMENT_TREE_PARENT, &descendant_marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut tree = spawn_daemon_test_command(command, "hard-parent containment tree")
        .expect("spawn hard-parent containment tree");
    let direct_pid = tree.id().expect("hard-parent direct child pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !descendant_marker.is_file() && Instant::now() < deadline {
        assert!(
            tree.try_wait()
                .expect("poll hard-parent containment tree")
                .is_none(),
            "hard-parent containment tree exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let descendant_pid =
        std::fs::read_to_string(&descendant_marker).expect("read hard-parent descendant pid");
    publish_marker_atomically(
        &ready,
        format!("{direct_pid}\n{descendant_pid}").as_bytes(),
        "publish hard-parent containment readiness",
    );
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn spawn_daemon_ephemeral(repo_root: &Path) -> DaemonChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin-daemon"));
    isolate_daemon_test_command(&mut command);
    command
        .arg("--repo")
        .arg(repo_root)
        // The feature under test: the daemon, not the launcher, picks the port.
        .arg("--port")
        .arg("0")
        // Keep the test hermetic and light: no LSP discovery on the host.
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        // Startup pins sibling repository authority from the registry. Keep
        // that read inside this scratch repository rather than ~/.kin.
        .env(
            "KIN_REGISTRY_PATH",
            repo_root.join(".kin/test-runtime/registry.toml"),
        )
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    spawn_daemon_test_command(command, "ephemeral-port daemon")
        .expect("failed to spawn contained kin-daemon")
}

fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

fn live_process_start_time(pid: u32) -> Option<u64> {
    let system = System::new_all();
    let process = system.process(Pid::from_u32(pid))?;
    (process.status() != ProcessStatus::Zombie).then_some(process.start_time())
}

/// Fail loudly the instant the daemon child exits before it is ready, instead of
/// polling a dead process until the deadline.
fn assert_child_alive(child: &mut DaemonChild, what: &str) {
    if let Ok(Some(status)) = child.try_wait() {
        panic!("daemon exited before it became {what}: {status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_binds_ephemeral_port_and_publishes_it() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    kin_core::init(repo.path()).expect("init scratch repo");
    let kin_root = repo.path().join(".kin");

    let mut child = spawn_daemon_ephemeral(repo.path());
    let deadline = Instant::now() + READINESS_TIMEOUT;

    // Handshake half 1: the daemon must publish a real, non-zero bound port —
    // never the sentinel 0 we passed on the command line.
    let port = loop {
        assert_child_alive(&mut child, "bound");
        if let Some(port) = read_port_file(&kin_root) {
            assert_ne!(port, 0, "daemon must publish its real bound port, not 0");
            break port;
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_daemon(&mut child, "ephemeral-port daemon").await;
            panic!("daemon never wrote its bound port to daemon.port; cleanup={cleanup:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Handshake half 2: the published port must actually serve — /health
    // responds on exactly the port the daemon reported.
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    let mut healthy = false;
    while Instant::now() < deadline {
        assert_child_alive(&mut child, "healthy");
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                healthy = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Shut the daemon down before asserting so a failure never leaks a process.
    terminate_daemon(&mut child, "ephemeral-port daemon")
        .await
        .expect("terminate and reap ephemeral-port daemon");

    assert!(
        healthy,
        "daemon did not serve /health on its published port {port}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_direct_daemon_child_terminates_its_containment() {
    #[cfg(windows)]
    {
        // Windows repository initialization currently fails closed before it
        // can publish a capability-owned config replacement. This test owns
        // only the independent DaemonChild containment contract, so exercise
        // that contract with the same native test executable instead of
        // weakening repository initialization for a lifecycle fixture.
        let root = tempfile::TempDir::new().expect("tempdir");
        let marker = root.path().join("direct-contained-child.pid");
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        isolate_daemon_test_command(&mut command);
        command
            .args(["--exact", "direct_containment_tree_worker", "--nocapture"])
            .env(CONTAINMENT_TREE_DESCENDANT, &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = spawn_daemon_test_command(command, "direct contained child")
            .expect("spawn direct contained child");
        let pid = child.id().expect("spawned contained child pid");
        let deadline = Instant::now() + READINESS_TIMEOUT;
        while !marker.is_file() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(marker.is_file(), "direct contained child was never ready");
        let start_time = live_process_start_time(pid).expect("live contained child identity");

        drop(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        while live_process_start_time(pid) == Some(start_time) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_ne!(
            live_process_start_time(pid),
            Some(start_time),
            "contained Drop left direct child pid {pid} alive"
        );
    }

    #[cfg(not(windows))]
    {
        let repo = tempfile::TempDir::new().expect("tempdir");
        kin_core::init(repo.path()).expect("init scratch repo");
        let mut child = spawn_daemon_ephemeral(repo.path());
        let pid = child.id().expect("spawned daemon pid");
        let deadline = Instant::now() + READINESS_TIMEOUT;
        while read_port_file(&repo.path().join(".kin")).is_none() {
            assert_child_alive(&mut child, "bound");
            assert!(
                Instant::now() < deadline,
                "daemon never published its port before the Drop check"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let start_time = live_process_start_time(pid).expect("live daemon process identity");

        drop(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        while live_process_start_time(pid) == Some(start_time) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_ne!(
            live_process_start_time(pid),
            Some(start_time),
            "contained Drop left direct daemon pid {pid} alive"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_containment_terminates_a_late_descendant() {
    let root = tempfile::TempDir::new().expect("tempdir");
    let descendant_marker = root.path().join("descendant.pid");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    isolate_daemon_test_command(&mut command);
    command
        .args(["--exact", "direct_containment_tree_worker", "--nocapture"])
        .env(CONTAINMENT_TREE_PARENT, &descendant_marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = spawn_daemon_test_command(command, "direct-containment tree")
        .expect("spawn direct-containment tree");
    let parent_pid = child.id().expect("contained parent pid");
    let deadline = Instant::now() + READINESS_TIMEOUT;
    while !descendant_marker.is_file() && Instant::now() < deadline {
        assert!(
            child
                .try_wait()
                .expect("poll direct-containment tree")
                .is_none(),
            "direct-containment tree exited before descendant readiness"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        descendant_marker.is_file(),
        "contained descendant did not publish readiness"
    );
    let descendant_pid = std::fs::read_to_string(&descendant_marker)
        .expect("read descendant pid")
        .trim()
        .parse::<u32>()
        .expect("parse descendant pid");
    let parent_start = live_process_start_time(parent_pid).expect("live contained parent");
    let descendant_start =
        live_process_start_time(descendant_pid).expect("live contained descendant");

    drop(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && (live_process_start_time(parent_pid) == Some(parent_start)
            || live_process_start_time(descendant_pid) == Some(descendant_start))
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(
        live_process_start_time(parent_pid),
        Some(parent_start),
        "contained parent pid {parent_pid} survived Drop"
    );
    assert_ne!(
        live_process_start_time(descendant_pid),
        Some(descendant_start),
        "contained descendant pid {descendant_pid} survived Drop"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_cleanup_proves_quiescence_before_releasing_containment() {
    let root = tempfile::TempDir::new().expect("tempdir");
    let descendant_marker = root.path().join("explicit-cleanup-descendant.pid");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    isolate_daemon_test_command(&mut command);
    command
        .args(["--exact", "direct_containment_tree_worker", "--nocapture"])
        .env(CONTAINMENT_TREE_PARENT, &descendant_marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = spawn_daemon_test_command(command, "explicit-cleanup tree")
        .expect("spawn explicit-cleanup tree");
    let parent_pid = child.id().expect("contained parent pid");
    let deadline = Instant::now() + READINESS_TIMEOUT;
    while !descendant_marker.is_file() && Instant::now() < deadline {
        assert!(
            child
                .try_wait()
                .expect("poll explicit-cleanup parent")
                .is_none(),
            "explicit-cleanup parent exited before descendant readiness"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let descendant_pid = std::fs::read_to_string(&descendant_marker)
        .expect("read explicit-cleanup descendant pid")
        .trim()
        .parse::<u32>()
        .expect("parse explicit-cleanup descendant pid");
    let parent_start = live_process_start_time(parent_pid).expect("live contained parent");
    let descendant_start =
        live_process_start_time(descendant_pid).expect("live contained descendant");

    terminate_daemon(&mut child, "explicit-cleanup tree")
        .await
        .expect("terminate, prove, and reap explicit-cleanup tree");

    assert_ne!(
        live_process_start_time(parent_pid),
        Some(parent_start),
        "explicit cleanup left parent pid {parent_pid} alive"
    );
    assert_ne!(
        live_process_start_time(descendant_pid),
        Some(descendant_start),
        "explicit cleanup left descendant pid {descendant_pid} alive"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn guardian_terminates_the_tree_after_hard_parent_death() {
    let root = tempfile::TempDir::new().expect("tempdir");
    let ready = root.path().join("hard-parent.ready");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    isolate_daemon_test_command(&mut command);
    command
        .kill_on_drop(true)
        .args([
            "--exact",
            "direct_containment_hard_parent_worker",
            "--nocapture",
        ])
        .env(CONTAINMENT_HARD_PARENT, root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut hard_parent = command.spawn().expect("spawn hard-parent worker");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() && Instant::now() < deadline {
        assert!(
            hard_parent
                .try_wait()
                .expect("poll hard-parent worker")
                .is_none(),
            "hard-parent worker exited before readiness"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pids = std::fs::read_to_string(&ready)
        .expect("read hard-parent readiness")
        .lines()
        .map(|line| line.trim().parse::<u32>().expect("parse contained pid"))
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 2, "hard-parent readiness must contain two pids");
    let direct_start = live_process_start_time(pids[0]).expect("live contained direct child");
    let descendant_start = live_process_start_time(pids[1]).expect("live contained descendant");

    hard_parent
        .start_kill()
        .expect("kill hard-parent worker without Drop");
    tokio::time::timeout(Duration::from_secs(5), hard_parent.wait())
        .await
        .expect("hard-parent worker reap timed out")
        .expect("reap hard-parent worker");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && (live_process_start_time(pids[0]) == Some(direct_start)
            || live_process_start_time(pids[1]) == Some(descendant_start))
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(
        live_process_start_time(pids[0]),
        Some(direct_start),
        "guardian left direct child pid {} alive after hard parent death",
        pids[0]
    );
    assert_ne!(
        live_process_start_time(pids[1]),
        Some(descendant_start),
        "guardian left descendant pid {} alive after hard parent death",
        pids[1]
    );
}
