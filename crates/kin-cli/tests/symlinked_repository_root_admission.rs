// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Ambient admission through a repository root reached by a symbolic link.
//!
//! A repository is reached through symlinked paths far more often than it looks.
//! On macOS `/tmp` and `/var` are themselves symbolic links, so a repository
//! under either is already in this case before anyone chooses it, and people
//! routinely keep work directories behind links of their own.
//!
//! The daemon binds one spelling of that root and its watcher backend reports
//! another. When the two were compared lexically the events lost, silently: the
//! repository below took nothing from ambient admission for as long as the
//! daemon ran, while every surface still reported a healthy daemon (FIR-2442).

use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

mod common;

use common::Command;

/// How long ambient admission has to take the write.
///
/// Generous against a loaded machine and still far short of the failure it
/// guards: the defect admitted nothing at all, for the whole life of the
/// daemon, so no bound distinguishes it from a slow one.
const ADMISSION_BOUND: Duration = Duration::from_secs(60);

struct IsolatedDaemon {
    child: Option<common::RuntimeOwnedChild>,
}

impl IsolatedDaemon {
    fn spawn(repo: &Path, runtime: &common::IsolatedDaemonRuntime) -> Self {
        let mut command = runtime.daemon_command();
        let child = command
            .arg("--repo")
            .arg(repo)
            .arg("--port")
            .arg("0")
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_DAEMON_AUTO_EMBED", "0")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_owned()
            .expect("spawn isolated kin-daemon");
        Self { child: Some(child) }
    }

    fn wait_until_serving(&mut self, kin_root: &Path) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let child = self.child.as_mut().expect("daemon child exists");
            if let Some(status) = child.try_wait().expect("inspect daemon child") {
                panic!("isolated daemon exited before readiness: {status}");
            }
            if let Some(port) = fs::read_to_string(kin_root.join("daemon.port"))
                .ok()
                .and_then(|value| value.trim().parse::<u16>().ok())
            {
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                    return port;
                }
            }
            assert!(
                Instant::now() < deadline,
                "isolated daemon did not become ready"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(mut self) {
        let mut child = self.child.take().expect("daemon child exists");
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for IsolatedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seed_repository(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn helper() -> u32 {\n    7\n}\n",
    )
    .expect("write entity source");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "seed"]);
}

/// How long a reading waits for the daemon's two-phase admission to settle.
///
/// Only how long a reading that is going to fail spends proving it: the wait
/// returns on the first healthy answer, so a quiet host never spends this.
const STATUS_SETTLE_BOUND: Duration = Duration::from_secs(60);

/// One `kin graph status`, run through the production route.
fn graph_status(repo: &Path, home: &Path, port: u16) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["graph", "status"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .current_dir(repo)
        .output()
        .expect("run production kin graph status route")
}

/// Entities the live query graph reports, once it can report them.
///
/// `kin graph status` exits non-zero on a critical graph health issue, and one
/// of those issues is transient by construction: "derived graph tree has N
/// artifacts but repository authority has M"
/// (`crates/kin-cli/src/commands/graph_health.rs:481`), which the same output
/// explains on the same run as authority admission binding the entity layer
/// while facets are written per file after it. A single point-in-time read
/// therefore samples a two-phase process and fails on the gap between its
/// halves. That is not a product fault and no assertion here is about it, but
/// it failed this case at 15.6 seconds on a host at load 100 while the same
/// file passed in 5.99 seconds at load 17.87 (FIR-2566).
///
/// So wait for a reading rather than take the first one. A graph that is
/// genuinely unhealthy still fails, at the bound, printing the last thing the
/// command said.
fn live_entity_count(repo: &Path, home: &Path, port: u16) -> u64 {
    let deadline = Instant::now() + STATUS_SETTLE_BOUND;
    loop {
        let output = graph_status(repo, home, port);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            return stdout
                .lines()
                .find(|line| line.starts_with("Entities: "))
                .and_then(|line| {
                    line.trim_start_matches("Entities: ")
                        .split_whitespace()
                        .next()
                })
                .and_then(|count| count.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("graph status names an entity count: {stdout}"));
        }
        assert!(
            Instant::now() < deadline,
            "graph status never reported a healthy graph in {}s: stdout={stdout} stderr={}",
            STATUS_SETTLE_BOUND.as_secs(),
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(250));
    }
}

/// FIR-2442. A repository reached through a symbolic link admits host writes
/// ambiently, exactly as the same repository reached directly does.
#[cfg(unix)]
#[test]
fn a_repository_bound_through_a_symlinked_root_admits_a_host_write() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let real = root.path().join("real-repo");
    let linked = root.path().join("linked-repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&real).expect("create repo");
    std::os::unix::fs::symlink(&real, &linked).expect("link the repository root");

    // Every path from here on is the symlinked spelling, which is what a person
    // with a linked work directory types and what their editor and agent
    // inherit. Nothing in the test resolves it, because nothing they run would.
    seed_repository(&linked);

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", ".", "--json"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .current_dir(&linked)
        .output()
        .expect("run production kin init route");
    assert!(
        init.status.success(),
        "init stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let runtime = common::IsolatedDaemonRuntime::new(&linked);
    let mut daemon = IsolatedDaemon::spawn(&linked, &runtime);
    let port = daemon.wait_until_serving(&linked.join(".kin"));

    let before = live_entity_count(&linked, &home, port);

    // The write a person makes: a new file, through the linked root, with no
    // command run afterwards. Ambient admission is what makes it queryable.
    fs::write(
        linked.join("src/added.rs"),
        b"pub fn ambiently_admitted() -> u32 {\n    41\n}\n",
    )
    .expect("write a new source file through the symlinked root");

    let deadline = Instant::now() + ADMISSION_BOUND;
    let mut latest = before;
    while Instant::now() < deadline {
        latest = live_entity_count(&linked, &home, port);
        if latest > before {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    daemon.stop();

    assert!(
        latest > before,
        "a file written through the symlinked repository root {} was never admitted: the live \
         query graph held {before} entities before the write and {latest} after {}s. The \
         repository resolves to {}, and a watcher that cannot place its own events reports \
         nothing at all",
        linked.display(),
        ADMISSION_BOUND.as_secs(),
        real.canonicalize()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| real.display().to_string()),
    );
}
