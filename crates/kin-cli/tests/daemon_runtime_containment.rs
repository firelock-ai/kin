// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(any(unix, windows))]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessStatus, System};

mod common;

const TREE_PARENT: &str = "KIN_TEST_RUNTIME_TREE_PARENT";
const TREE_DESCENDANT: &str = "KIN_TEST_RUNTIME_TREE_DESCENDANT";
const TREE_STOP: &str = "KIN_TEST_RUNTIME_TREE_STOP";

/// Ceiling on the descendant fixture's own lifetime.
///
/// It must strictly exceed readiness plus the entire `Drop` budget, or the
/// descendant expires while the test is still measuring and every liveness
/// check reads as containment on a process that died of old age. The expiry
/// marker makes that outcome loud rather than silent, and this number is what
/// keeps it from happening in the first place.
const DESCENDANT_LIFETIME_CAP: Duration = Duration::from_secs(300);

/// How long the test waits for the descendant to publish its pid. The
/// descendant publishes as its first action, so this stays near its original
/// value; whatever it becomes must satisfy readiness plus `Drop` under
/// [`DESCENDANT_LIFETIME_CAP`].
const DESCENDANT_READY_BUDGET: Duration = Duration::from_secs(10);

#[test]
fn bounded_capture_deadline_cannot_be_bypassed_by_continuous_output() {
    common::bounded_capture_deadline_cannot_be_bypassed_by_continuous_output();
}

fn publish_marker_atomically(marker: &std::path::Path, contents: impl AsRef<[u8]>) {
    let mut staged_name = marker.as_os_str().to_os_string();
    staged_name.push(".staged");
    let staged = PathBuf::from(staged_name);
    std::fs::write(&staged, contents).expect("write staged runtime marker");
    std::fs::rename(staged, marker).expect("publish runtime marker");
}

fn read_pid_marker(marker: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(marker)
        .ok()
        .and_then(|contents| contents.trim().parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}

struct KillAndReapChild {
    child: common::RuntimeOwnedChild,
}

impl KillAndReapChild {
    fn new(child: common::RuntimeOwnedChild) -> Self {
        Self { child }
    }

    fn terminate_and_reap(&mut self) -> Result<(), String> {
        let probe_error = match self.child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        let kill_error = self.child.kill().err();
        let deadline = Instant::now() + Duration::from_secs(5);
        let reap_result = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => break Err("guarded child was not reaped within 5s".to_string()),
                Err(error) => break Err(format!("reap guarded child: {error}")),
            }
        };
        if probe_error.is_none() && kill_error.is_none() && reap_result.is_ok() {
            Ok(())
        } else {
            Err(format!(
                "guarded-child cleanup failed: initial probe={probe_error:?}; \
                 kill={kill_error:?}; reap={reap_result:?}"
            ))
        }
    }
}

impl std::ops::Deref for KillAndReapChild {
    type Target = common::RuntimeOwnedChild;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for KillAndReapChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for KillAndReapChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

#[test]
fn isolated_runtime_tree_worker() {
    if let Some(marker) = std::env::var_os(TREE_DESCENDANT) {
        let marker = PathBuf::from(marker);
        publish_marker_atomically(&marker, std::process::id().to_string());
        let stop = PathBuf::from(std::env::var_os(TREE_STOP).expect("tree stop marker"));
        let deadline = Instant::now() + DESCENDANT_LIFETIME_CAP;
        while !stop.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // Returning of old age and being terminated by containment are the same
        // observation from outside: the pid stops being live either way. Only a
        // descendant that outlived its own cap can publish this, so its absence
        // is what makes the assertions below statements about containment
        // rather than about how long the machine took.
        if !stop.is_file() {
            publish_marker_atomically(&marker.with_extension("expired"), "expired");
        }
        return;
    }

    let Some(marker) = std::env::var_os(TREE_PARENT) else {
        return;
    };
    let mut descendant =
        std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", "isolated_runtime_tree_worker", "--nocapture"])
            .env_remove(TREE_PARENT)
            .env(TREE_DESCENDANT, marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn isolated-runtime descendant");
    let _ = descendant.wait();
}

fn live_process_start_time(pid: u32) -> Option<u64> {
    let system = System::new_all();
    let process = system.process(Pid::from_u32(pid))?;
    (!matches!(
        process.status(),
        ProcessStatus::Dead | ProcessStatus::Zombie
    ))
    .then_some(process.start_time())
}

#[test]
fn dropping_isolated_runtime_terminates_a_late_descendant() {
    let root = tempfile::TempDir::new().expect("tempdir");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(&repository).expect("create repository");
    let descendant_marker = root.path().join("descendant.pid");
    let expiry_marker = root.path().join("descendant.expired");
    let stop_marker = root.path().join("stop");
    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            "--exact".into(),
            "isolated_runtime_tree_worker".into(),
            "--nocapture".into(),
        ],
        Vec::new(),
        Duration::from_secs(15),
    );
    let mut command =
        runtime.process_command_for_test(std::env::current_exe().expect("current test executable"));
    let mut parent = KillAndReapChild::new(
        command
            .args(["--exact", "isolated_runtime_tree_worker", "--nocapture"])
            .env(TREE_PARENT, &descendant_marker)
            .env(TREE_STOP, &stop_marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_owned()
            .expect("spawn runtime-owned process tree"),
    );
    let parent_pid = parent.id();
    let deadline = Instant::now() + DESCENDANT_READY_BUDGET;
    let descendant_pid = loop {
        if let Some(pid) = read_pid_marker(&descendant_marker) {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "runtime-owned descendant did not publish a parseable pid"
        );
        assert!(
            parent
                .try_wait()
                .expect("poll runtime-owned parent")
                .is_none(),
            "runtime-owned parent exited before descendant readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let parent_start = live_process_start_time(parent_pid).expect("live runtime-owned parent");
    let descendant_start =
        live_process_start_time(descendant_pid).expect("live runtime-owned descendant");

    let runtime_drop = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runtime)));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut parent_reaped = false;
    while Instant::now() < deadline {
        parent_reaped = parent
            .try_wait()
            .expect("poll contained parent after runtime Drop")
            .is_some();
        if parent_reaped
            && live_process_start_time(parent_pid) != Some(parent_start)
            && live_process_start_time(descendant_pid) != Some(descendant_start)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let parent_survived = live_process_start_time(parent_pid) == Some(parent_start);
    let descendant_survived = live_process_start_time(descendant_pid) == Some(descendant_start);

    if !parent_reaped || parent_survived || descendant_survived {
        let _ = std::fs::write(&stop_marker, b"stop");
        let _ = parent.kill();
        let fallback_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < fallback_deadline {
            if parent.try_wait().ok().flatten().is_some()
                && live_process_start_time(descendant_pid) != Some(descendant_start)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    assert!(
        !expiry_marker.exists(),
        "the descendant returned at its own lifetime cap rather than being terminated, so \
         every liveness check below would read as containment on a process that died of old age"
    );
    assert!(
        runtime_drop.is_ok(),
        "IsolatedDaemonRuntime Drop reported containment failure"
    );
    assert!(parent_reaped, "runtime Drop did not reap its direct child");
    assert!(
        !parent_survived,
        "runtime-owned parent pid {parent_pid} survived runtime Drop"
    );
    assert!(
        !descendant_survived,
        "runtime-owned descendant pid {descendant_pid} survived runtime Drop"
    );
}
