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

/// The build identity this test binary carries, in the exact form the daemon
/// stamps persisted vector sidecars with.
///
/// A test that seeds prepared state writes this stamp; the daemon that later
/// reopens the repository demands its own. The two only agree when both
/// binaries came out of one build of `kin-buildinfo`.
pub fn expected_build_stamp() -> String {
    kin_buildinfo::sha_with_dirty(kin_buildinfo::get())
}

/// Recompose a `--compat-json` `build.sha` / `build.dirty` pair into the stamp
/// `kin_buildinfo::sha_with_dirty` would produce for the same build.
///
/// The daemon reports the two fields separately, so the harness has to join
/// them the way the authority does rather than comparing the pair directly:
/// when the commit is unknown the dirty flag is not part of the identity, and
/// a raw pair comparison would reject a daemon whose embedder identity
/// actually matches.
fn build_stamp(sha: &str, dirty: bool) -> String {
    if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.to_string()
    }
}

/// Why a candidate `kin-daemon` may not be reused by this test binary, or
/// `None` when it may be.
///
/// Two independent reasons, and the second is the one that used to be missed.
/// A daemon whose graph snapshot version differs cannot read the repository at
/// all. A daemon that is merely built from a *different commit or working
/// tree* reads it fine, but stamps and demands a different embedder identity —
/// so a sidecar seeded by this test binary is rejected on load,
/// `indexed_embedding_count` reads 0, and the suite reports a product defect
/// that only exists because two binaries in one target directory were built at
/// different times.
pub fn daemon_compat_mismatch(
    payload: &Value,
    expected_snapshot_version: u64,
    expected_stamp: &str,
) -> Option<String> {
    match payload["graph_snapshot_version"].as_u64() {
        Some(version) if version == expected_snapshot_version => {}
        Some(version) => {
            return Some(format!(
                "graph snapshot version {version} does not match this test binary's {expected_snapshot_version}"
            ));
        }
        None => return Some("compat payload has no graph_snapshot_version".to_string()),
    }

    let Some(sha) = payload["build"]["sha"].as_str() else {
        return Some("compat payload has no build.sha".to_string());
    };
    let Some(dirty) = payload["build"]["dirty"].as_bool() else {
        return Some("compat payload has no build.dirty".to_string());
    };

    let daemon_stamp = build_stamp(sha, dirty);
    if daemon_stamp != expected_stamp {
        return Some(format!(
            "daemon build identity {daemon_stamp} does not match this test binary's {expected_stamp}"
        ));
    }
    None
}

fn daemon_compat(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    let output = Command::new(path)
        .arg("--compat-json")
        .output()
        .map_err(|error| format!("could not run {} --compat-json: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --compat-json exited with {}",
            path.display(),
            output.status
        ));
    }
    let payload = serde_json::from_slice::<Value>(&output.stdout).map_err(|error| {
        format!(
            "{} --compat-json did not emit JSON: {error}",
            path.display()
        )
    })?;
    match daemon_compat_mismatch(
        &payload,
        kin_db::GraphSnapshot::CURRENT_VERSION as u64,
        &expected_build_stamp(),
    ) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

pub fn fresh_daemon_bin() -> PathBuf {
    let kin_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"));
    let daemon_bin = kin_bin.with_file_name("kin-daemon");
    if daemon_compat(&daemon_bin).is_ok() {
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

    if let Err(reason) = daemon_compat(&daemon_bin) {
        panic!(
            "kin-daemon at {} is unusable after rebuild: {reason}.\n\
             This test binary carries build identity {}. A daemon built from a \
             different commit or working tree stamps persisted vector sidecars \
             with a different embedder identity, so state this suite seeds is \
             rejected on reopen and indexed_embedding_count reads 0 — a harness \
             fault that reads as a product defect. Build both from one tree: \
             cargo build --all-targets",
            daemon_bin.display(),
            expected_build_stamp()
        );
    }
    daemon_bin
}
