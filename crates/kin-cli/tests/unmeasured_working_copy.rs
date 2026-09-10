// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A working copy nothing admitted must not read as a clean one.
//!
//! FIR-3420. With no daemon holding the repository, `kin diff HEAD WORKSPACE`
//! printed `Artifacts: +0 ~0 -0` over a tree that had just been edited, at exit
//! 0, and `kin status` over three brand-new untracked files printed output
//! byte-identical to the same command on the empty repository, also at exit 0.
//! Both answers are correct about the graph: with nothing admitting the working
//! copy, the workspace side of every comparison is whatever the last admission
//! left. Both read as a statement about the files on disk.
//!
//! Two earlier fixes put that gap into words. FIR-2961 added the basis to the
//! `Tree:` verdict and the `Semantic scope:` line to a workspace diff, and
//! FIR-2820 added `Untracked host content:`. All three sentences are accurate
//! and all three arrive AFTER the number they qualify, which is why a stranger
//! running the everyday loop read `0 artifacts` as "nothing to commit" over a
//! repository holding three modules the graph had never met. So this suite
//! grades the two things prose cannot carry: whether the gap is above the count
//! a reader meets first, and whether the exit code says anything at all.
//!
//! Every case forces the daemon-absent state through the product's own surface
//! and then PROVES it reached that state with `kin daemon status`, because a
//! fixture that quietly had a daemon would satisfy these assertions for the
//! wrong reason. The all-clear cases are not decoration either: a build that
//! returned 9 from every read, or printed the banner unconditionally, would
//! pass every negative assertion here and be worse than what it replaced.

// The fixture drives the retained no-follow projection, which only Unix
// implements, so the whole binary is scoped to that platform, exactly as its
// sibling `repository_status.rs` is.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

/// The exit code `kin status` and `kin diff <base> WORKSPACE` return when no
/// pass took the working copy.
///
/// Written as a literal rather than imported from `kin_cli`, on purpose. The
/// constant is a published contract that scripts and CI steps branch on, and a
/// test that reads it from the same crate would follow the value silently if
/// someone changed it. This is the number, and changing it has to break here.
const EXIT_WORKING_COPY_UNMEASURED: i32 = 9;

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

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> Output {
    run_kin_with(repo, home, args, None)
}

/// Like [`run_kin`], but pointed at a daemon this test is holding open.
///
/// Only the all-clear control uses it, and it needs it. Measured while writing
/// this suite: `kin admit` starts a daemon, takes the tree, ends its session,
/// and that daemon can be gone before the very next process starts, at which
/// point the read after it is unmeasured again and correctly says so. That is
/// the product behaving, and it has its own case below. A control that means "a
/// pass ran AND a daemon is still serving" has to hold that state rather than
/// hope for it, so it spawns its own daemon the way the sibling suites do and
/// names it explicitly.
fn run_kin_served_by(repo: &Path, home: &Path, args: &[&str], port: u16) -> Output {
    run_kin_with(repo, home, args, Some(port))
}

fn run_kin_with(repo: &Path, home: &Path, args: &[&str], daemon_port: Option<u16>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // Embedding is not what any case here is about, and a first embed pass
        // fetches a model this test must never depend on.
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo);
    match daemon_port {
        Some(port) => {
            command.env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"));
        }
        None => {
            command.env_remove("KIN_DAEMON_URL");
        }
    }
    command.output().expect("run kin")
}

/// A daemon this test owns, started and stopped explicitly.
///
/// Copied in shape from `graph_status_after_admission.rs`, which needs the same
/// thing for the same reason: a daemon whose lifetime is bounded by evidence
/// rather than by an idle clock the test would be racing.
struct HeldDaemon {
    child: Option<common::RuntimeOwnedChild>,
}

impl HeldDaemon {
    fn spawn(repo: &Path, runtime: &common::IsolatedDaemonRuntime) -> Self {
        let child = runtime
            .daemon_command()
            .arg("--repo")
            .arg(repo)
            .arg("--port")
            .arg("0")
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_owned()
            .expect("spawn the held kin-daemon");
        Self { child: Some(child) }
    }

    fn wait_until_serving(&mut self, kin_root: &Path) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let child = self.child.as_mut().expect("daemon child exists");
            if let Some(status) = child.try_wait().expect("inspect daemon child") {
                panic!("the held daemon exited before readiness: {status}");
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
                "the held daemon did not become ready"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for HeldDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("kin should exit rather than die on a signal")
}

/// Bring the repository to the state every case here is about, and prove it got
/// there.
///
/// The proof is the point. `kin daemon stop` reports success whether or not one
/// was running, so a fixture that believed it had stopped a daemon it had not
/// would satisfy every assertion below for a reason unrelated to the defect.
/// `kin daemon status` names this repository's worker directly, and that
/// sentence is what the cases stand on.
fn require_no_daemon(repo: &Path, home: &Path) {
    run_kin(repo, home, &["daemon", "stop"]);
    let status = run_kin(repo, home, &["daemon", "status"]);
    let text = stdout_of(&status) + &String::from_utf8_lossy(&status.stderr);
    assert!(
        text.contains("worker daemon not running"),
        "the fixture still has a daemon for this repository, so nothing below is about the \
         daemon-absent shape: {text}"
    );
}

/// A repository with one commit behind it, and no daemon.
fn seeded_repo(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = root.join("home");
    let repo = root.join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("storage.py"),
        b"def append(entry, path):\n    open(path, 'a').write(repr(entry))\n",
    )
    .expect("write module");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "seed"]);
    let init = run_kin(&repo, &home, &["init", "."]);
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        stdout_of(&init),
        String::from_utf8_lossy(&init.stderr)
    );
    (repo, home)
}

/// The index of a line starting with `prefix`, or a failure naming the page.
fn line_index(text: &str, prefix: &str) -> usize {
    text.lines()
        .position(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting {prefix:?} in:\n{text}"))
}

const BANNER: &str = "Working copy: NOT MEASURED";

#[test]
fn workspace_diff_with_no_daemon_exits_unmeasured_with_the_gap_above_the_count() {
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());

    // Dirty the tree the way the stranger did: a one-line docstring into a
    // tracked function, which moves the artifact and nothing else.
    fs::write(
        repo.join("storage.py"),
        b"def append(entry, path):\n    \"\"\"Append one entry.\"\"\"\n    open(path, 'a').write(repr(entry))\n",
    )
    .expect("edit module");
    require_no_daemon(&repo, &home);

    let diff = run_kin(&repo, &home, &["diff", "HEAD", "WORKSPACE"]);
    let text = stdout_of(&diff);

    assert_eq!(
        code_of(&diff),
        EXIT_WORKING_COPY_UNMEASURED,
        "a workspace diff that measured nothing exited as though it had answered:\n{text}"
    );
    assert!(
        text.contains(BANNER),
        "a workspace diff that measured nothing printed no headline gap:\n{text}"
    );
    // The whole finding in one assertion. `Artifacts: +0 ~0 -0` is where a
    // reader stops, so the gap has to be above it rather than in the footer
    // that already carried this sentence correctly and was read past.
    assert!(
        line_index(&text, BANNER) < line_index(&text, "Artifacts:"),
        "the gap is printed BELOW the count it qualifies, which is the defect:\n{text}"
    );
}

#[test]
fn status_over_untracked_work_with_no_daemon_exits_unmeasured_with_the_gap_above_the_tree_line() {
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());

    // Three brand-new untracked modules, the shape that produced output
    // byte-identical to the empty repository.
    fs::write(
        repo.join("parsing.py"),
        b"def parse_line(line):\n    return line\n",
    )
    .expect("write parsing");
    fs::write(
        repo.join("reporting.py"),
        b"def totals_by(entries):\n    return {}\n",
    )
    .expect("write reporting");
    fs::write(repo.join("cli.py"), b"def main():\n    return 0\n").expect("write cli");
    require_no_daemon(&repo, &home);

    let status = run_kin(&repo, &home, &["status"]);
    let text = stdout_of(&status);

    assert_eq!(
        code_of(&status),
        EXIT_WORKING_COPY_UNMEASURED,
        "status over an unmeasured working copy exited as though it had measured it:\n{text}"
    );
    assert!(
        line_index(&text, BANNER) < line_index(&text, "Tree:"),
        "the gap is printed below the Tree: verdict a reader takes for the answer:\n{text}"
    );
}

#[test]
fn the_json_arm_carries_the_gap_in_its_exit_code_and_still_parses() {
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());
    fs::write(repo.join("untracked.py"), b"VALUE = 1\n").expect("write untracked");
    require_no_daemon(&repo, &home);

    // The arm with no other channel. `StatusReportWire` denies unknown fields,
    // so the gap cannot be a key in this payload, and the text banner is not
    // rendered here at all. If the exit code does not carry it, nothing does.
    let status = run_kin(&repo, &home, &["status", "--json"]);
    let text = stdout_of(&status);
    assert_eq!(
        code_of(&status),
        EXIT_WORKING_COPY_UNMEASURED,
        "the JSON arm gave a machine consumer no signal at all:\n{text}"
    );
    let report: Value =
        serde_json::from_str(&text).expect("the JSON arm must still print a parseable report");
    assert_eq!(
        report["authority"], "repository-v6",
        "the report itself must be unchanged by the exit code: {report}"
    );

    let diff = run_kin(&repo, &home, &["diff", "HEAD", "WORKSPACE", "--json"]);
    let diff_text = stdout_of(&diff);
    assert_eq!(
        code_of(&diff),
        EXIT_WORKING_COPY_UNMEASURED,
        "the JSON diff arm gave a machine consumer no signal at all:\n{diff_text}"
    );
    serde_json::from_str::<Value>(&diff_text)
        .expect("the JSON diff arm must still print a parseable report");
}

#[test]
fn a_diff_between_two_changes_needs_no_admission_and_still_exits_zero() {
    // The control that stops this fix from being "return 9 everywhere". A diff
    // whose endpoints are both durable authority is about exactly what it says
    // it is about, with or without a daemon, so it must keep its clean exit and
    // must not carry the banner.
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());
    require_no_daemon(&repo, &home);

    let diff = run_kin(&repo, &home, &["diff", "HEAD", "HEAD"]);
    let text = stdout_of(&diff);
    assert_eq!(
        code_of(&diff),
        0,
        "a change-to-change diff was refused for a working copy it never claimed to read:\n{text}"
    );
    assert!(
        !text.contains(BANNER),
        "a change-to-change diff printed a working-copy gap it does not have:\n{text}"
    );
}

/// Edit the seeded module, so the tree is one artifact ahead of its base.
fn dirty_the_tracked_module(repo: &Path) {
    fs::write(
        repo.join("storage.py"),
        b"def append(entry, path):\n    \"\"\"Append one entry.\"\"\"\n    open(path, 'a').write(repr(entry))\n",
    )
    .expect("edit module");
}

#[test]
fn a_measured_working_copy_still_gets_its_clean_exit_and_no_banner() {
    // The control that stops this fix from being "hedge every answer", and the
    // one that would catch a build that simply stopped admitting. With a daemon
    // serving, both commands admit the tree themselves, so the answer IS about
    // the working copy and has to say so by being silent and exiting 0.
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());
    dirty_the_tracked_module(&repo);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let mut daemon = HeldDaemon::spawn(&repo, &runtime);
    let port = daemon.wait_until_serving(&repo.join(".kin"));

    let diff = run_kin_served_by(&repo, &home, &["diff", "HEAD", "WORKSPACE"], port);
    let text = stdout_of(&diff);
    assert_eq!(
        code_of(&diff),
        0,
        "a working copy this command admitted was reported as unmeasured:\n{text}"
    );
    assert!(
        !text.contains(BANNER),
        "a measured working copy carried the unmeasured banner:\n{text}"
    );
    // And the answer is the one the stranger only got after running `kin admit`
    // by hand: the edit, not a zero.
    assert!(
        text.contains("Artifacts: +0 ~1 -0"),
        "the measured diff did not report the one edited artifact:\n{text}"
    );

    let status = run_kin_served_by(&repo, &home, &["status"], port);
    let status_text = stdout_of(&status);
    assert_eq!(
        code_of(&status),
        0,
        "a working copy this status admitted was reported as unmeasured:\n{status_text}"
    );
    assert!(
        !status_text.contains(BANNER),
        "a measured status carried the unmeasured banner:\n{status_text}"
    );
}

#[test]
fn a_correct_answer_from_a_stale_graph_is_still_reported_as_unmeasured() {
    // The subtle arm, and the reason the predicate is "did a pass run here"
    // rather than "does the answer look right". Measured while writing this
    // suite: `kin admit` takes the tree and its daemon can be gone before the
    // next process starts. The diff that follows then prints the exact edit,
    // because durable authority now holds it, while nothing has looked at the
    // working copy since. The number is right by luck and Kin cannot know that:
    // any edit made in between is invisible to it.
    //
    // This is FIR-2961's lesson in exit-code form. A verdict with nothing
    // behind it is not a verdict about the working copy, however well it reads,
    // and a build that decided to trust a fresh-looking answer would put the
    // whole defect back one layer down.
    let root = tempdir().expect("temp root");
    let (repo, home) = seeded_repo(root.path());
    dirty_the_tracked_module(&repo);

    let admit = run_kin(&repo, &home, &["admit"]);
    assert!(
        admit.status.success(),
        "kin admit failed, so this case never reached the state it is about: stdout={} stderr={}",
        stdout_of(&admit),
        String::from_utf8_lossy(&admit.stderr)
    );
    require_no_daemon(&repo, &home);

    let diff = run_kin(&repo, &home, &["diff", "HEAD", "WORKSPACE"]);
    let text = stdout_of(&diff);
    // The positive control for the state: without this the case is satisfied by
    // a fixture whose admission never landed, which is the ordinary arm again.
    assert!(
        text.contains("Artifacts: +0 ~1 -0"),
        "the graph does not hold the admitted edit, so this fixture is the ordinary \
         daemon-absent case rather than the stale-but-correct one:\n{text}"
    );
    assert_eq!(
        code_of(&diff),
        EXIT_WORKING_COPY_UNMEASURED,
        "a right-looking answer from a graph nothing has refreshed exited as measured:\n{text}"
    );
    assert!(
        text.contains(BANNER),
        "a right-looking answer from a stale graph printed no headline gap:\n{text}"
    );
}
