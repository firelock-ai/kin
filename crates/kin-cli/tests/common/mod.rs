// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared bounded-subprocess support for the CLI integration tests.
//!
//! Every process an integration test drives — `kin`, `kin-daemon`, `cargo`,
//! `rustc` — waits on something the machine may not be able to supply: a daemon
//! that never becomes ready, a cargo build-directory lock another checkout
//! holds, a model that is not downloaded. `Command::output()` waits on all of
//! them without a deadline and with this process's stdin attached, so the
//! default test suite can block forever while printing nothing. Every spawn
//! here closes stdin and carries a wall-clock cap, so the suite always reaches
//! a verdict and names the process that did not finish.

// Each integration test binary includes this module and uses a different
// subset of it.
#![allow(dead_code)]

use serde_json::Value;
use std::ffi::OsStr;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static BUILD_DAEMON: OnceLock<()> = OnceLock::new();

/// Wall-clock cap for a single test-driven subprocess.
///
/// Generous enough that a cold daemon start on a loaded machine still passes,
/// short enough that a wait which is never going to end fails the run instead
/// of pinning the machine.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);

/// Wall-clock cap for the in-test `cargo build` fallback, which competes for
/// the same build-directory lock as the `cargo test` invocation that is running
/// this suite.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A drop-in replacement for `std::process::Command` whose `output()` cannot
/// block forever.
///
/// Two differences from the standard type, both load-bearing:
///
/// - Output is captured into regular files rather than pipes. `kin` detaches a
///   `kin-daemon` that inherits the caller's stdout and stderr, and a pipe stays
///   open for as long as any descendant holds its write end — so
///   `std::process::Command::output()` keeps reading long after the `kin`
///   process it launched has exited, for as long as the daemon lives.
/// - The wait carries a wall-clock deadline. At the deadline the child is
///   killed and the test fails naming the command, instead of leaving a silent,
///   idle process the developer has to notice and kill by hand.
pub struct Command(std::process::Command);

impl Command {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self(std::process::Command::new(program))
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.0.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.0.args(args);
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        self.0.env(key, value);
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.0.envs(vars);
        self
    }

    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.0.env_remove(key);
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.0.current_dir(dir);
        self
    }

    /// Run to completion under [`COMMAND_TIMEOUT`] with stdin closed.
    pub fn output(&mut self) -> std::io::Result<Output> {
        self.output_within(COMMAND_TIMEOUT)
    }

    pub fn output_within(&mut self, timeout: Duration) -> std::io::Result<Output> {
        let label = self.0.get_program().to_string_lossy().into_owned();
        run_bounded_within(&mut self.0, &label, timeout)
    }
}

fn run_bounded_within(
    command: &mut std::process::Command,
    label: &str,
    timeout: Duration,
) -> std::io::Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));

    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout: read_capture(stdout)?,
                    stderr: read_capture(stderr)?,
                });
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{label} did not exit within {timeout:?}; stdout={} stderr={}",
                    String::from_utf8_lossy(&read_capture(stdout).unwrap_or_default()),
                    String::from_utf8_lossy(&read_capture(stderr).unwrap_or_default())
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    }
}

fn read_capture(mut file: std::fs::File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn daemon_compat_ok(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(output) = Command::new(path).arg("--compat-json").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    payload["graph_snapshot_version"].as_u64()
        == Some(kin_db::GraphSnapshot::CURRENT_VERSION as u64)
}

pub fn fresh_daemon_bin() -> PathBuf {
    let kin_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"));
    let daemon_bin = kin_bin.with_file_name("kin-daemon");
    if daemon_compat_ok(&daemon_bin) {
        return daemon_bin;
    }

    BUILD_DAEMON.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.ancestors().nth(2).expect("kin workspace root");
        // This shells out to cargo from inside a cargo-driven test run, so it
        // contends for the build-directory lock with whatever else is building
        // this checkout. Cargo waits on that lock forever and prints only to
        // the stderr this call captures, so the wait is bounded here.
        let output = Command::new(env!("CARGO"))
            .args(["build", "-p", "kin-daemon", "--bin", "kin-daemon"])
            .current_dir(workspace_root)
            .output_within(BUILD_TIMEOUT)
            .expect("run cargo build -p kin-daemon");
        assert!(
            output.status.success(),
            "cargo build -p kin-daemon failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    });

    assert!(
        daemon_compat_ok(&daemon_bin),
        "kin-daemon at {} is missing or incompatible after rebuild",
        daemon_bin.display()
    );
    daemon_bin
}
