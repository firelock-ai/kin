// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof that a stop request terminates a daemon whose async runtime
//! is saturated.
//!
//! The shipped daemon documents a hard bound: shutdown is signalled, a grace
//! period covers the drain plus final flush, and a force-exit watchdog ends the
//! process if the graceful path does not. That watchdog runs on a plain OS
//! thread, but every flag that armed it was written from inside the async
//! runtime — the SIGTERM arm of `select_with_signals` sets the cancel channel,
//! and a spawned task writes `is_shutdown`. A reconciliation batch doing
//! synchronous admission work over a large observation set occupies the runtime
//! and starves both, so the bound did not hold in the one case it exists for:
//! `kin daemon stop` delivered its request, waited, and reported a timeout
//! against a daemon that was still running.
//!
//! The worker below is that daemon in miniature: real signal wiring, real
//! watchdog, real grace config, and a runtime with no thread left to poll
//! anything. If arming depends on the runtime, the worker never exits.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Names the scratch directory the worker publishes readiness into. Its
/// presence is also what selects worker mode, so the same `#[test]` is inert
/// during an ordinary suite run.
const SATURATED_WORKER_ROOT: &str = "KIN_TEST_SATURATED_SHUTDOWN_ROOT";

/// Same, for the healthy-runtime worker that proves the graceful path still
/// wins the race on a daemon that is not starved.
const GRACEFUL_WORKER_ROOT: &str = "KIN_TEST_GRACEFUL_SHUTDOWN_ROOT";

/// Grace the graceful worker is given before its force-exit backstop fires.
const GRACEFUL_WORKER_GRACE_SECS: u64 = 30;

/// How long the parent waits for the healthy worker to exit after SIGTERM.
///
/// This must stay ABOVE [`GRACEFUL_WORKER_GRACE_SECS`], which is the opposite
/// of the ordering an exit-code test would want. Both paths exit 0, so the exit
/// code discriminates nothing and the marker the worker writes on the tokio
/// signal path is what separates them. A displaced signal path leaves only the
/// backstop, which exits inside this window, and the marker assertion is what
/// then fails, with its own message, rather than a timeout blaming a slow
/// machine. Restoring the old ordering would make the marker unreachable and
/// silently retire the discrimination. It also stays below
/// [`WORKER_WALL_CLOCK_CAP`], so a cap firing can never be mistaken for a pass.
const GRACEFUL_EXIT_BUDGET: Duration = Duration::from_secs(45);

/// Grace the worker grants before force-exiting, fed through the same
/// `KIN_DAEMON_SHUTDOWN_GRACE_SECS` knob production reads. Short so the test is
/// quick; the shipped default is 25s.
const WORKER_GRACE_SECS: u64 = 2;

/// How long the parent waits for the worker to actually exit after SIGTERM.
/// Comfortably above the grace plus the watchdog's poll interval, and well
/// under the wall-clock cap the worker holds itself to, so a cap firing can
/// never be mistaken for a pass.
const EXIT_BUDGET: Duration = Duration::from_secs(20);

/// Budget for the worker to reach a saturated runtime.
const READY_BUDGET: Duration = Duration::from_secs(30);

/// Last-resort cap on the worker's lifetime. A spin loop that escaped its test
/// would peg a core for as long as the machine stayed up.
const WORKER_WALL_CLOCK_CAP: Duration = Duration::from_secs(60);

/// Worker exit code when the parent died first.
const EXIT_ORPHANED: i32 = 70;

/// Worker exit code when the wall-clock cap fired.
const EXIT_CAPPED: i32 = 71;

/// Kills the worker however this test ends, including on an assertion unwind.
struct WorkerGuard(Child);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn stop_terminates_a_daemon_whose_runtime_is_saturated() {
    let root = tempfile::tempdir().expect("scratch root for the saturated worker");
    let ready = root.path().join("saturated.ready");

    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args(["--exact", "saturated_daemon_shutdown_worker", "--nocapture"])
        .env(SATURATED_WORKER_ROOT, root.path())
        .env(
            "KIN_DAEMON_SHUTDOWN_GRACE_SECS",
            WORKER_GRACE_SECS.to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut worker = WorkerGuard(command.spawn().expect("spawn saturated daemon worker"));

    // Readiness is published from inside the task that consumes the runtime's
    // only worker thread, so observing the marker proves the runtime is already
    // wedged rather than merely busy. Signalling before that point would test
    // an idle daemon and pass with or without a working backstop.
    let deadline = Instant::now() + READY_BUDGET;
    while !ready.is_file() {
        assert!(
            worker.0.try_wait().expect("poll worker").is_none(),
            "worker exited before it reported a saturated runtime"
        );
        assert!(
            Instant::now() < deadline,
            "worker never saturated its runtime"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let pid = i32::try_from(worker.0.id()).expect("worker pid fits a pid_t");
    // SAFETY: `pid` is this test's own direct child, which has not been reaped.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "deliver SIGTERM to the saturated worker"
    );

    let deadline = Instant::now() + EXIT_BUDGET;
    loop {
        if let Some(status) = worker.0.try_wait().expect("poll worker") {
            assert_ne!(
                status.code(),
                Some(EXIT_ORPHANED),
                "worker exited because it was orphaned, not because the stop request landed"
            );
            assert_ne!(
                status.code(),
                Some(EXIT_CAPPED),
                "worker exited on its wall-clock cap, not because the stop request landed"
            );
            assert_eq!(
                status.code(),
                Some(0),
                "the force-exit backstop exits 0; any other code means something else ended the worker"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "a SIGTERM'd daemon whose runtime is saturated never exited within {}s. \
             The force-exit backstop is armed only by flags written from inside \
             that runtime, so a starved runtime leaves nothing to arm it and \
             `kin daemon stop` has no bound at all.",
            EXIT_BUDGET.as_secs()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The backstop must not become the ordinary way daemons stop.
///
/// Chaining a handler onto SIGTERM is only safe if tokio's own registration
/// still fires: tokio registers through the same `signal-hook-registry`, and
/// handlers chain rather than replace. If that were ever untrue, the graceful
/// path would go silent and every stop would degrade to a force-exit that skips
/// the final flush, the derived-CAS barrier, and endpoint retirement. The
/// saturated test above cannot catch that, because a force-exit also satisfies
/// "the process exited".
///
/// This one distinguishes them by evidence rather than by clock: the worker
/// writes a marker from inside the tokio SIGTERM arm, which only that path can
/// reach, so a pass means the graceful path observed the signal rather than the
/// backstop rescuing a broken one. The budget deliberately exceeds the grace so
/// that a displaced signal path still exits inside the window and is caught by
/// the missing marker.
///
/// Nothing about the daemon's own SIGKILL-based test helpers covers this: they
/// reap daemons with `start_kill`, so no existing test sends SIGTERM at all.
#[test]
fn a_healthy_daemon_still_stops_through_the_graceful_path() {
    let root = tempfile::tempdir().expect("scratch root for the graceful worker");
    let ready = root.path().join("graceful.ready");
    let observed = root.path().join("graceful.observed");

    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args(["--exact", "graceful_daemon_shutdown_worker", "--nocapture"])
        .env(GRACEFUL_WORKER_ROOT, root.path())
        .env(
            "KIN_DAEMON_SHUTDOWN_GRACE_SECS",
            GRACEFUL_WORKER_GRACE_SECS.to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut worker = WorkerGuard(command.spawn().expect("spawn graceful daemon worker"));

    let deadline = Instant::now() + READY_BUDGET;
    while !ready.is_file() {
        assert!(
            worker.0.try_wait().expect("poll worker").is_none(),
            "worker exited before it was listening for a signal"
        );
        assert!(Instant::now() < deadline, "worker never reported readiness");
        std::thread::sleep(Duration::from_millis(20));
    }

    let pid = i32::try_from(worker.0.id()).expect("worker pid fits a pid_t");
    // SAFETY: `pid` is this test's own direct child, which has not been reaped.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "deliver SIGTERM to the healthy worker"
    );

    let deadline = Instant::now() + GRACEFUL_EXIT_BUDGET;
    loop {
        if let Some(status) = worker.0.try_wait().expect("poll worker") {
            assert_eq!(
                status.code(),
                Some(0),
                "the graceful path exits 0 of its own accord"
            );
            assert!(
                observed.is_file(),
                "the worker exited 0 without ever reaching tokio's SIGTERM arm, so the \
                 force-exit backstop ended it. Chaining the runtime-independent handler \
                 onto SIGTERM must not displace tokio's own registration, or every stop \
                 silently degrades to a force-exit that skips the final flush, the \
                 derived-CAS barrier and endpoint retirement."
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "a healthy daemon did not stop at all within {}s, which is past its own {}s \
             force-exit grace, so neither the graceful path nor the backstop ended it",
            GRACEFUL_EXIT_BUDGET.as_secs(),
            GRACEFUL_WORKER_GRACE_SECS
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Exact worker entrypoint: the daemon's shutdown wiring on a healthy runtime.
/// Inert unless [`GRACEFUL_WORKER_ROOT`] is set.
#[test]
fn graceful_daemon_shutdown_worker() {
    let Some(root) = std::env::var_os(GRACEFUL_WORKER_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let ready = root.join("graceful.ready");
    let observed = root.join("graceful.observed");

    spawn_parent_death_watchdog();
    spawn_wall_clock_cap();

    kin_daemon::daemon::install_shutdown_signal_handler();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    kin_daemon::daemon::spawn_shutdown_escalation_watchdog(
        || false,
        cancel_rx,
        kin_daemon::daemon::shutdown_escalation_grace(),
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build the healthy runtime");
    runtime.block_on(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register the tokio SIGTERM listener");
        // Published after registration, so a signal arriving immediately after
        // is still latched by tokio and delivered to `recv`.
        std::fs::write(&ready, b"listening").expect("publish readiness");
        sigterm.recv().await;
        // Only tokio's own SIGTERM registration can reach this line. The
        // backstop ends the process from an OS thread and never runs it, which
        // is what lets the parent tell the two exit-0 paths apart.
        std::fs::write(&observed, b"sigterm").expect("publish the observed marker");
        let _ = cancel_tx.send(true);
    });
}

/// Exact worker entrypoint: the daemon's shutdown wiring on a runtime with no
/// thread left to poll it. Inert unless [`SATURATED_WORKER_ROOT`] is set.
#[test]
fn saturated_daemon_shutdown_worker() {
    let Some(root) = std::env::var_os(SATURATED_WORKER_ROOT) else {
        return;
    };
    let ready = PathBuf::from(root).join("saturated.ready");

    // Both guards run on plain OS threads, so a saturated runtime cannot
    // disable the things that stop this process from outliving its test.
    spawn_parent_death_watchdog();
    spawn_wall_clock_cap();

    // The daemon's production wiring, called as the daemon calls it.
    kin_daemon::daemon::install_shutdown_signal_handler();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    kin_daemon::daemon::spawn_shutdown_escalation_watchdog(
        // `is_shutdown` is written by a spawned task and nothing else, so on a
        // saturated runtime it is never written at all. Model that honestly
        // rather than handing the watchdog a flag the real daemon would not
        // have set.
        || false,
        cancel_rx,
        kin_daemon::daemon::shutdown_escalation_grace(),
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("build the saturated runtime");
    runtime.block_on(async move {
        // Construct the listener first: tokio registers its own SIGTERM handler
        // here, so the graceful path is genuinely wired and merely starved,
        // which is the daemon's real state and not a weaker one.
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register the tokio SIGTERM listener");
        tokio::spawn(async move {
            sigterm.recv().await;
            let _ = cancel_tx.send(true);
        });
        // Let the worker thread poll that listener once so it is parked on the
        // signal before anything saturates the runtime.
        tokio::task::yield_now().await;

        let marker = ready.clone();
        tokio::spawn(async move {
            // Publishing from inside the saturating task is what makes the
            // marker mean "the runtime is wedged" rather than "the worker
            // started".
            std::fs::write(&marker, b"saturated").expect("publish readiness");
            loop {
                std::hint::spin_loop();
            }
        });

        // Consume this thread too, once the worker thread is provably gone.
        // Leaving it parked would let the runtime drive its signal driver here
        // instead, and the wedge under test would not be a wedge.
        while !ready.is_file() {
            std::thread::sleep(Duration::from_millis(10));
        }
        loop {
            std::hint::spin_loop();
        }
    });
}

fn spawn_parent_death_watchdog() {
    std::thread::spawn(|| loop {
        // SAFETY: `getppid` takes no arguments and cannot fail.
        if unsafe { libc::getppid() } == 1 {
            std::process::exit(EXIT_ORPHANED);
        }
        std::thread::sleep(Duration::from_millis(200));
    });
}

fn spawn_wall_clock_cap() {
    std::thread::spawn(|| {
        std::thread::sleep(WORKER_WALL_CLOCK_CAP);
        std::process::exit(EXIT_CAPPED);
    });
}
