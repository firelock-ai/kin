// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin init --json` reports what its cross-file enrichment did as a field, and
//! decides at once where no daemon can run the sweep.
//!
//! The matched-pair proof run is where this came from. Its Kin role ran
//! `kin init` under a seccomp filter that let the process bind and listen on
//! loopback and refused every connect() with EACCES. Init admitted the
//! repository in 36.7 seconds, started a supervisor for the cross-file sweep,
//! polled a port it was not permitted to connect to until that supervisor
//! exited at its own 60-second idle timeout, and finished with a stderr note
//! that no daemon could be started. The JSON it printed said nothing about any
//! of it, so the harness had no field to read.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

/// How long the enrichment decision may take where no daemon can run the
/// sweep. It is one environment read, or one connect against a listener the
/// process opened itself, so seconds is generous; the wait this replaces was a
/// minute.
const DECISION_BUDGET: Duration = Duration::from_secs(5);

/// A bound on the whole command, measured from outside it, so the wait is
/// caught even if the field under test misreported it. Admission of the
/// fixture takes seconds; the supervisor's idle timeout alone was sixty.
const COMMAND_BUDGET: Duration = Duration::from_secs(45);

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    kin_home: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    /// A fresh HOME, a fresh KIN_HOME and a two-file repository with one
    /// commit, so nothing on the host can supply a supervisor or a daemon.
    fn new() -> Self {
        Self::with_files(&[
            (
                "app.py",
                "def helper():\n    return 7\n\n\ndef caller():\n    return helper() + 1\n",
            ),
            ("main.py", "from app import caller\n\nprint(caller())\n"),
        ])
    }

    /// The same, holding `files` instead.
    fn with_files(files: &[(&str, &str)]) -> Self {
        let root = tempdir().expect("temp root");
        let home = root.path().join("home");
        let kin_home = root.path().join("kin-home");
        let repo = root.path().join("repo");
        fs::create_dir_all(&home).expect("create home");
        fs::create_dir_all(&kin_home).expect("create kin home");
        fs::create_dir_all(&repo).expect("create repo");
        run_git(&repo, &["init", "--initial-branch=main"]);
        run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
        run_git(&repo, &["config", "user.name", "Kin"]);
        for (name, body) in files {
            fs::write(repo.join(name), body)
                .unwrap_or_else(|error| panic!("write {name}: {error}"));
        }
        run_git(&repo, &["add", "--all"]);
        run_git(&repo, &["commit", "-m", "Add the fixture"]);
        Self {
            _root: root,
            home,
            kin_home,
            repo,
        }
    }

    /// `kin init <repo> --json` in this fixture's environment, with whatever
    /// the caller has already put in front of it.
    fn init_json(&self, command: &mut Command<'_>, extra: &[&str]) -> (Output, Duration) {
        command
            .arg("init")
            .arg(&self.repo)
            .arg("--json")
            .args(extra)
            .env("HOME", &self.home)
            .env("KIN_HOME", &self.kin_home)
            .env("KIN_EMBED_BACKEND", "cpu")
            .env("KIN_DAEMON_AUTO_EMBED", "0");
        let started = Instant::now();
        let output = command.output().expect("run kin init");
        (output, started.elapsed())
    }

    fn supervisor_pid_file(&self) -> PathBuf {
        self.home.join(".kin").join("supervisor.pid")
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

/// The `cross_file_enrichment` object of a successful `kin init --json`.
fn enrichment_field(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "kin init must still succeed when the sweep cannot run: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("kin init --json stdout is JSON");
    assert_eq!(payload["schema"], "kin.init-result.v6");
    payload
        .get("cross_file_enrichment")
        .unwrap_or_else(|| {
            panic!(
                "kin init --json carries no cross_file_enrichment field, so a script cannot \
                 tell this run from one whose sweep finished; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .clone()
}

/// The decision was made at once, by the field's own account and by the clock
/// outside the command.
fn assert_decided_quickly(field: &Value, output: &Output, waited: Duration) {
    let elapsed_ms = field["elapsed_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("elapsed_ms is a whole number of milliseconds: {field}"));
    assert!(
        Duration::from_millis(elapsed_ms) < DECISION_BUDGET,
        "the enrichment decision took {elapsed_ms} ms: {field}"
    );
    assert!(
        waited < COMMAND_BUDGET,
        "kin init took {waited:?}, which is the supervisor idle wait this test exists to catch; \
         stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `KIN_NO_DAEMON` forbids the daemon the sweep runs in, so the phase is
/// decided before anything is started, and the JSON says the edges are owed
/// and why.
#[test]
fn kin_no_daemon_reports_the_sweep_owed_at_once() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command.env("KIN_NO_DAEMON", "1");
    let (output, waited) = fixture.init_json(&mut command, &[]);

    let field = enrichment_field(&output);
    assert_eq!(field["state"], "owed", "{field}");
    assert_eq!(field["reason"], "daemon_spawn_disabled", "{field}");
    assert!(
        field["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("KIN_NO_DAEMON")),
        "the detail names what kept the sweep from running: {field}"
    );
    assert_decided_quickly(&field, &output, waited);
    assert!(
        !fixture.supervisor_pid_file().exists(),
        "a run that may not start a daemon must not have started a supervisor"
    );
}

/// `--no-enrich` is the caller asking for no sweep, and the field says that
/// rather than leaving the caller to remember it.
#[test]
fn no_enrich_reports_the_sweep_owed_as_not_requested() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    let (output, waited) = fixture.init_json(&mut command, &["--no-enrich"]);

    let field = enrichment_field(&output);
    assert_eq!(field["state"], "owed", "{field}");
    assert_eq!(field["reason"], "not_requested", "{field}");
    assert_decided_quickly(&field, &output, waited);
}

/// The proof container's condition itself: a process that may bind and listen
/// on loopback and may not connect there.
///
/// The main build measured on this fixture under the macOS profile below took
/// 61 seconds and printed no field: its supervisor logged "kin supervisor
/// listening", sat through its 60-second idle timeout, and exited 0 into the
/// same note the proof run carried.
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[test]
fn a_process_that_may_not_connect_to_loopback_reports_the_sweep_owed_at_once() {
    let fixture = Fixture::new();
    let mut command = no_connect::command(env!("CARGO_BIN_EXE_kin"));
    let (output, waited) = fixture.init_json(&mut command, &[]);

    let field = enrichment_field(&output);
    assert_eq!(field["state"], "owed", "{field}");
    assert_eq!(
        field["reason"],
        "loopback_blocked",
        "the restriction must be what the field names; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        field["cause"]
            .as_str()
            .is_some_and(|cause| cause.contains("os error")),
        "the operating system's own error travels with the reason: {field}"
    );
    assert_decided_quickly(&field, &output, waited);
    assert!(
        !fixture.supervisor_pid_file().exists(),
        "no supervisor may be started where nothing could reach it"
    );
}

/// Loopback connects refused with EPERM, and bind, listen and accept left
/// alone, by a sandbox profile around the command.
#[cfg(target_os = "macos")]
mod no_connect {
    use super::Command;

    const PROFILE: &str =
        r#"(version 1)(allow default)(deny network-outbound (remote ip "localhost:*"))"#;

    pub fn command(program: &str) -> Command<'static> {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", PROFILE]).arg(program);
        command
    }
}

/// Every connect() refused with EACCES, and bind, listen and accept left
/// alone, by a seccomp filter the command and its children inherit. This is
/// the proof container's own restriction, reduced to the one syscall it is
/// about.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod no_connect {
    use super::Command;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xC000_00B7;

    /// Allow everything except connect() on this architecture, which fails
    /// with EACCES. A syscall made under another architecture's numbering is
    /// allowed, because this filter is about one call and not a sandbox.
    fn filter() -> Vec<libc::sock_filter> {
        let load = |offset: u32| libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: offset,
        };
        let skip_unless_equal = |value: u32, skip: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: skip,
            k: value,
        };
        let give = |verdict: u32| libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: verdict,
        };
        vec![
            // seccomp_data.arch
            load(4),
            skip_unless_equal(AUDIT_ARCH, 3),
            // seccomp_data.nr
            load(0),
            skip_unless_equal(libc::SYS_connect as u32, 1),
            give(libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
            give(libc::SECCOMP_RET_ALLOW),
        ]
    }

    pub fn command(program: &str) -> Command<'static> {
        let filter = filter();
        let mut command = Command::new(program);
        // SAFETY: the hook makes two prctl calls, which are async-signal-safe,
        // against a filter that was built before the fork, and allocates
        // nothing.
        unsafe {
            command.pre_exec(move || {
                let program = libc::sock_fprog {
                    len: filter.len() as libc::c_ushort,
                    filter: filter.as_ptr() as *mut libc::sock_filter,
                };
                let one: libc::c_ulong = 1;
                let zero: libc::c_ulong = 0;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
                let program = &program as *const libc::sock_fprog as libc::c_ulong;
                if libc::prctl(libc::PR_SET_SECCOMP, mode, program, zero, zero) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
}

/// A language server that dies partway through the sweep leaves the edges
/// owed, and says why in the server's own words.
///
/// The pilot's Kin arm is where this came from. Its `gopls` finished the
/// handshake, loaded packages for about three seconds and exited before the
/// sweep asked its first question. The sweep asked every one of 546 files
/// anyway, each query landed on a dead connection, and `kin init --json`
/// reported `produced` with "cross-file enrichment complete (546/546 files)"
/// over a graph holding no language-server edge at all. Nothing recorded why
/// the server exited.
///
/// A fake `gopls` ahead of the host's on PATH plays each part. It completes
/// the handshake and the readiness poll as a real one does, and then either
/// keeps answering, or writes a last line to stderr and exits with code 3.
#[cfg(unix)]
mod language_server_death {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// What the fake writes to stderr as it exits, so a test can tell the
    /// server's own words from anything Kin says about them.
    const LAST_WORDS: &str = "fatal error: runtime: failed to create new OS thread (fixture)";

    /// When the fake stops answering.
    #[derive(Clone, Copy)]
    enum Death {
        /// Never: every request gets a null result, as a server with nothing
        /// to say about a position answers.
        Never,
        /// On the first document the sweep opens, before it asks anything.
        OnFirstOpen,
        /// On the first question about a document, leaving that question
        /// unanswered.
        OnFirstQuery,
    }

    impl Death {
        fn mode(self) -> &'static str {
            match self {
                Self::Never => "never",
                Self::OnFirstOpen => "open",
                Self::OnFirstQuery => "query",
            }
        }
    }

    const FAKE_GOPLS: &str = r#"#!/usr/bin/env python3
import json, sys

MODE = "@MODE@"
LAST_WORDS = "@LAST_WORDS@"

if any(arg in ("version", "--version", "-version") for arg in sys.argv[1:]):
    print("golang.org/x/tools/gopls (kin test fixture)")
    sys.exit(0)

def die():
    sys.stderr.write(LAST_WORDS + "\n")
    sys.stderr.flush()
    sys.exit(3)

def send(message):
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    sys.stdout.buffer.flush()

while True:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            sys.exit(0)
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode().split(":", 1)
        headers[name.strip().lower()] = value.strip()
    message = json.loads(sys.stdin.buffer.read(int(headers["content-length"])))
    method = message.get("method", "")
    if MODE == "open" and method == "textDocument/didOpen":
        die()
    if "id" not in message:
        if method == "exit":
            sys.exit(0)
        continue
    if MODE == "query" and method.startswith("textDocument/"):
        die()
    if method == "initialize":
        result = {"capabilities": {"definitionProvider": True, "referencesProvider": True}}
    else:
        result = None
    send({"jsonrpc": "2.0", "id": message["id"], "result": result})
"#;

    /// A two-file Go module whose second file calls into the first, and a
    /// directory holding the fake `gopls`.
    fn go_fixture(death: Death) -> (Fixture, tempfile::TempDir) {
        let fixture = Fixture::with_files(&[
            ("go.mod", "module example.com/fixture\n\ngo 1.22\n"),
            (
                "greet.go",
                "package fixture\n\nfunc Greet() string {\n\treturn \"hi\"\n}\n",
            ),
            (
                "use.go",
                "package fixture\n\nfunc Use() string {\n\treturn Greet()\n}\n",
            ),
        ]);
        let bin = tempdir().expect("fake gopls directory");
        let path = bin.path().join("gopls");
        fs::write(
            &path,
            FAKE_GOPLS
                .replace("@MODE@", death.mode())
                .replace("@LAST_WORDS@", LAST_WORDS),
        )
        .expect("write the fake gopls");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make the fake gopls executable");
        (fixture, bin)
    }

    fn init_with(death: Death) -> (Value, Output) {
        let (fixture, bin) = go_fixture(death);
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.fixture_path_prefix(bin.path());
        let (output, _) = fixture.init_json(&mut command, &[]);
        (enrichment_field(&output), output)
    }

    /// Everything a reader of the field is told, in one string to search.
    fn told(field: &Value) -> String {
        format!(
            "{} {}",
            field["detail"].as_str().unwrap_or_default(),
            field["cause"].as_str().unwrap_or_default()
        )
    }

    /// The pilot's shape: the server dies after the handshake and before the
    /// sweep's first question. No file was asked anything, so none is
    /// enriched, and the field carries the exit and the server's last words.
    #[test]
    fn a_server_that_dies_before_its_first_answer_leaves_the_sweep_owed() {
        let (field, output) = init_with(Death::OnFirstOpen);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            field["state"], "owed",
            "a sweep whose server died before answering anything must not read as produced: \
             {field}; stderr={stderr}"
        );
        assert_eq!(field["reason"], "sweep_enriched_nothing", "{field}");
        let told = told(&field);
        assert!(
            told.contains(LAST_WORDS),
            "the server's own last words travel with the reason: {field}"
        );
        assert!(
            told.contains("exited with code 3"),
            "the server's exit travels with the reason: {field}"
        );
        assert!(
            !stderr.contains("enrichment complete"),
            "the summary must not call this sweep complete: {stderr}"
        );
    }

    /// The server dies in the middle of a file, with a question about it
    /// unanswered. That file got part of a pass, so it is owed rather than
    /// enriched, the file after it is never asked, and no file is claimed.
    #[test]
    fn a_server_that_dies_mid_question_leaves_the_file_owed_and_claims_none() {
        let (field, output) = init_with(Death::OnFirstQuery);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            field["state"], "owed",
            "a sweep whose server died mid-question must not read as produced: {field}; \
             stderr={stderr}"
        );
        assert_eq!(
            field["reason"], "sweep_enriched_nothing",
            "neither file completed its passes, so neither may be counted as enriched: {field}"
        );
        let told = told(&field);
        assert!(
            told.contains(LAST_WORDS),
            "the server's own last words travel with the reason: {field}"
        );
        assert!(
            told.contains("exited with code 3"),
            "the server's exit travels with the reason: {field}"
        );
        assert!(
            told.contains("owed"),
            "the file whose question went unanswered is named as owed: {field}"
        );
        assert!(
            !stderr.contains("enrichment complete"),
            "the summary must not call this sweep complete: {stderr}"
        );
    }

    /// The control. The same fixture and the same harness, with a server that
    /// answers every question with nothing to report. That is a finished sweep
    /// that found no edges, and zero edges is not a failure, so the field says
    /// produced. Without this, the tests above could pass on a verdict that
    /// reported owed for everything.
    #[test]
    fn a_server_that_answers_every_question_with_nothing_leaves_the_sweep_produced() {
        let (field, output) = init_with(Death::Never);
        assert_eq!(
            field["state"],
            "produced",
            "a server that answered every question is a finished sweep, even with no edges: \
             {field}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(field.get("reason").is_none_or(Value::is_null), "{field}");
    }
}

/// The language server a cold sweep started is stopped before the sweep
/// publishes, so the server's memory is not held while the daemon grows to
/// write the enrichment.
///
/// On a large Go tree, a traced setup run showed the sweep's gopls resident and
/// idle through the whole publication, at the largest size it reached, while
/// the daemon grew to write it. An earlier, untraced run on the same tree and
/// memory limit lost its daemon to the kernel inside that window.
///
/// A fake `gopls` ahead of the host's on PATH answers one reference and its
/// definition, so the sweep has relations to publish. When the sweep's server,
/// the one that had documents opened on it, is asked to shut down, it reads the
/// daemon's log and records whether the publication is already there, and which
/// process asked, which is the daemon.
#[cfg(unix)]
mod sweep_server_release {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// What the daemon logs once a sweep's enrichment is published.
    const PUBLISHED: &str = "published language-server enrichment into workspace authority";

    const FAKE_GOPLS: &str = r#"#!/usr/bin/env python3
import json, os, signal, sys, urllib.parse

RECORD = "@RECORD@"
PUBLISHED = "@PUBLISHED@"
MODE = "@MODE@"
STALLED = RECORD + ".stalled"

if any(arg in ("version", "--version", "-version") for arg in sys.argv[1:]):
    print("golang.org/x/tools/gopls (kin test fixture)")
    sys.exit(0)

opened = []

def send(message):
    body = json.dumps(message).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    sys.stdout.buffer.flush()

def sibling(uri, name):
    return uri.rsplit("/", 1)[0] + "/" + name

def at(uri, line, start, end):
    return {"uri": uri, "range": {"start": {"line": line, "character": start},
                                  "end": {"line": line, "character": end}}}

def published_yet():
    if not opened:
        return None
    root = urllib.parse.unquote(urllib.parse.urlparse(opened[0]).path).rsplit("/", 1)[0]
    try:
        with open(os.path.join(root, ".kin", "daemon.log"), errors="replace") as log:
            return PUBLISHED in log.read()
    except OSError:
        return None

while True:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            sys.exit(0)
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode().split(":", 1)
        headers[name.strip().lower()] = value.strip()
    message = json.loads(sys.stdin.buffer.read(int(headers["content-length"])))
    method = message.get("method", "")
    params = message.get("params") or {}
    if method == "textDocument/didOpen":
        opened.append(params["textDocument"]["uri"])
    if "id" not in message:
        if method == "exit":
            sys.exit(0)
        continue
    uri = (params.get("textDocument") or {}).get("uri", "")
    line_no = (params.get("position") or {}).get("line")
    result = None
    if method == "initialize":
        result = {"capabilities": {"definitionProvider": True, "referencesProvider": True}}
    elif os.path.exists(STALLED):
        # After the stall, a server started by any later sweep finds nothing,
        # so only the stalled sweep can publish relations.
        result = None
    elif method == "textDocument/references" and uri.endswith("/greet.go"):
        # `Greet()` in use.go: line 3, after the tab and `return `.
        result = [at(sibling(uri, "use.go"), 3, 8, 13)]
    elif method == "textDocument/definition" and uri.endswith("/use.go") and line_no == 3:
        result = [at(sibling(uri, "greet.go"), 2, 5, 10)]
    elif method == "shutdown" and opened:
        with open(RECORD, "a") as out:
            out.write(json.dumps({"opened": len(opened), "published_before_shutdown": published_yet(),
                                  "daemon": os.getppid()}) + "\n")
        if MODE == "stall":
            # Shut the daemon down while it waits on this reply, and never
            # give one, so a stop that waits for this server outlasts the
            # daemon's shutdown budget.
            open(STALLED, "w").close()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.kill(os.getppid(), signal.SIGTERM)
            continue
    send({"jsonrpc": "2.0", "id": message["id"], "result": result})
"#;

    /// The Go module both tests run the sweep over, and a directory holding
    /// the fake `gopls` in `mode`, recording to the returned path.
    fn go_fixture(mode: &str) -> (Fixture, tempfile::TempDir, PathBuf) {
        let fixture = Fixture::with_files(&[
            ("go.mod", "module example.com/fixture\n\ngo 1.22\n"),
            (
                "greet.go",
                "package fixture\n\nfunc Greet() string {\n\treturn \"hi\"\n}\n",
            ),
            (
                "use.go",
                "package fixture\n\nfunc Use() string {\n\treturn Greet()\n}\n",
            ),
        ]);
        let bin = tempdir().expect("fake gopls directory");
        let record = bin.path().join("sweep-server-shutdown.jsonl");
        let gopls = bin.path().join("gopls");
        fs::write(
            &gopls,
            FAKE_GOPLS
                .replace("@RECORD@", &record.display().to_string())
                .replace("@PUBLISHED@", PUBLISHED)
                .replace("@MODE@", mode),
        )
        .expect("write the fake gopls");
        fs::set_permissions(&gopls, fs::Permissions::from_mode(0o755))
            .expect("make the fake gopls executable");
        (fixture, bin, record)
    }

    /// The daemon's log without its terminal colouring, which wraps each
    /// field's name and value in escape sequences.
    fn daemon_log(fixture: &Fixture) -> String {
        let raw = fs::read_to_string(fixture.repo.join(".kin").join("daemon.log"))
            .expect("the daemon's log");
        let mut plain = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // CSI: ESC [ parameters, ended by a byte in @..~.
                if chars.next() == Some('[') {
                    for end in chars.by_ref() {
                        if ('@'..='~').contains(&end) {
                            break;
                        }
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    }

    /// The grace the stall test gives its daemon before the shutdown watchdog
    /// forces an exit. Half of it is the sweep's drain budget.
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

    /// Wait for the daemon the fake signalled to end on its own.
    ///
    /// `kin init` returns within one progress poll of the signal, because the
    /// daemon stops accepting requests at once while its sweep goes on to
    /// publish and finish. Its log describes what the shutdown did only once
    /// the process has ended. The watchdog force-exits it when the grace runs
    /// out, so one still running well past that has outlived its own backstop.
    fn wait_for_daemon_exit(pid: u32, fixture: &Fixture) {
        let bound = SHUTDOWN_GRACE * 3;
        let deadline = Instant::now() + bound;
        while kin_daemon_spawn::process_is_alive(pid) {
            assert!(
                Instant::now() < deadline,
                "the signalled daemon (pid {pid}) was still running {bound:?} after `kin init` \
                 returned, past its own shutdown watchdog; daemon.log:\n{}",
                daemon_log(fixture)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The shutdown requests the sweep's server received, as it recorded them.
    fn shutdowns(record: &Path, log: &str) -> Vec<Value> {
        fs::read_to_string(record)
            .unwrap_or_else(|error| {
                panic!(
                    "the sweep's server was never asked to shut down ({error}); daemon.log:\n{log}"
                )
            })
            .lines()
            .map(|line| serde_json::from_str(line).expect("a shutdown record"))
            .collect()
    }

    #[test]
    fn the_sweep_stops_its_server_before_it_publishes() {
        let (fixture, bin, record) = go_fixture("record");
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.fixture_path_prefix(bin.path());
        let (output, _) = fixture.init_json(&mut command, &[]);
        let field = enrichment_field(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Durability and completion are unchanged: the sweep still publishes
        // what it found, and only then reads as produced.
        assert_eq!(
            field["state"], "produced",
            "the sweep still finishes and publishes: {field}; stderr={stderr}"
        );
        let log = daemon_log(&fixture);
        assert!(
            log.contains(PUBLISHED),
            "the fixture must give the sweep relations to publish, or the order it publishes \
             in is not observed at all; daemon.log:\n{log}"
        );

        let shutdowns = shutdowns(&record, &log);
        assert_eq!(
            shutdowns.len(),
            1,
            "one server had documents opened on it, and it is shut down once: {shutdowns:?}"
        );
        assert_eq!(
            shutdowns[0]["published_before_shutdown"],
            Value::Bool(false),
            "the sweep's server must be stopped before the sweep publishes, so its memory is \
             released first: {shutdowns:?}; daemon.log:\n{log}"
        );
    }

    /// The result reports the generation the store ended at, not the one
    /// admission left. The sweep publishes after admission, and a result that
    /// printed admission's values disagreed with `kin status` a second later:
    /// on fastapi it said generation 1 over a store at generation 7.
    #[test]
    fn the_result_reports_the_generation_its_sweep_published() {
        let (fixture, bin, _record) = go_fixture("record");
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.fixture_path_prefix(bin.path());
        let (output, _) = fixture.init_json(&mut command, &[]);
        let field = enrichment_field(&output);
        assert_eq!(
            field["state"],
            "produced",
            "the sweep must finish for its publication to be reported: {field}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let log = daemon_log(&fixture);
        assert!(
            log.contains(PUBLISHED),
            "the fixture must give the sweep relations to publish; daemon.log:\n{log}"
        );
        let payload: Value =
            serde_json::from_slice(&output.stdout).expect("kin init --json stdout is JSON");
        assert_eq!(payload["authority_as_of"], "enrichment_end", "{payload}");
        assert!(
            payload["authority_generation"]
                .as_u64()
                .is_some_and(|generation| generation > 1),
            "the sweep published past admission's generation 1, and the result says so: {payload}"
        );

        let status = Command::new(env!("CARGO_BIN_EXE_kin"))
            .args(["status", "--json"])
            .env("HOME", &fixture.home)
            .env("KIN_HOME", &fixture.kin_home)
            .env_remove("KIN_DAEMON_URL")
            .current_dir(&fixture.repo)
            .output()
            .expect("run kin status");
        // No daemon holds the store once init returns, so status may answer 9
        // beside a report that is complete about durable authority.
        assert!(
            matches!(status.status.code(), Some(0) | Some(9)),
            "status answered {:?}: stdout={} stderr={}",
            status.status.code(),
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
        let reported: Value =
            serde_json::from_slice(&status.stdout).expect("kin status --json stdout is JSON");
        assert_eq!(
            payload["authority_generation"], reported["repository"]["generation"],
            "init and status name the same authority generation"
        );
        assert_eq!(
            payload["workspace_generation"],
            reported["workspace"]["generation"]
        );
        assert_eq!(payload["roots"], reported["repository"]["roots"]);
        assert_eq!(
            payload["semantic_enrichment"],
            reported["semantic_enrichment"]
        );
    }

    /// A daemon told to shut down while the sweep waits for its server to stop
    /// still publishes the sweep's work and finishes the pass, instead of
    /// spending its shutdown budget on the stop.
    ///
    /// The fake shuts the daemon down the moment it is asked to shut down, and
    /// never answers. A stop that waited for it would take the whole shutdown
    /// reply wait and termination grace, longer than the daemon's shutdown
    /// budget here, and the daemon would exit before publishing.
    #[test]
    fn a_shutdown_during_the_servers_stop_still_publishes_the_sweep() {
        let (fixture, bin, record) = go_fixture("stall");
        // Under the runtime rather than a command's own containment, which
        // ends every process `kin init` started the moment it returns. The
        // daemon under test is one of them, part way through the shutdown this
        // test is about, and its log would end wherever that kill found it.
        let runtime = common::IsolatedDaemonRuntime::new(&fixture.repo);
        let mut command = runtime.kin_command();
        command.fixture_path_prefix(bin.path());
        // Eight seconds before the shutdown watchdog forces an exit, four of
        // them for the sweep to drain: less than a stop that waits out an
        // unanswered shutdown request, and ample for publishing two files.
        command.env(
            "KIN_DAEMON_SHUTDOWN_GRACE_SECS",
            SHUTDOWN_GRACE.as_secs().to_string(),
        );
        let (output, _) = fixture.init_json(&mut command, &[]);
        let shutdowns = shutdowns(&record, &daemon_log(&fixture));
        if let Some(pid) = shutdowns
            .first()
            .and_then(|shutdown| shutdown["daemon"].as_u64())
        {
            wait_for_daemon_exit(pid as u32, &fixture);
        }
        let log = daemon_log(&fixture);
        assert!(
            !shutdowns.is_empty()
                && shutdowns[0]["published_before_shutdown"] == Value::Bool(false),
            "the stall must come before the publication, or the shutdown is not taken during \
             the stop: {shutdowns:?}; daemon.log:\n{log}"
        );
        assert!(
            log.contains(PUBLISHED),
            "the sweep's work must be published despite the shutdown: stdout={} stderr={}; \
             daemon.log:\n{log}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Only the stalled sweep had relations to report, so a finished pass
        // with relations is that sweep's, and not one a later daemon ran.
        let finished = log.lines().any(|line| {
            line.contains("LSP cold sweep complete")
                && line
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("relations="))
                    .and_then(|count| count.parse::<u64>().ok())
                    .is_some_and(|count| count > 0)
        });
        assert!(
            finished,
            "the stalled sweep must reach its end, with its completion recorded: daemon.log:\n{log}"
        );
        // The shutdown reached the worker after the sweep, so the worker
        // stopped by it rather than being outlived by the drain. Waiting for
        // the shutdown on the worker's own receiver would mark it seen, and
        // the worker would sit idle until the drain gave up on it.
        assert!(
            log.contains("LSP enrichment worker shutting down"),
            "the enrichment worker must see the shutdown after the sweep: daemon.log:\n{log}"
        );
        assert!(
            !log.contains("did not reach its end within the shutdown budget"),
            "the sweep must finish inside the shutdown budget: daemon.log:\n{log}"
        );
    }
}

/// A sweep over a store whose files are all finished settles the context its
/// language's server runs under before it skips them, and starts that server
/// only when what the host would start cannot vouch for the finished proofs.
#[cfg(unix)]
mod finished_files_proof_context {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A Go server written as a Node package's entry, so the daemon can
    /// identify it by content: its script and its `package.json`. It records
    /// each session's handshake, document opens and shutdown, and proves the
    /// one call in the fixture.
    const FAKE_GOPLS_JS: &str = r#"#!/usr/bin/env node
const fs = require("fs");
const RECORD = "@RECORD@";
const version = require("./package.json").version;
let buffer = Buffer.alloc(0);
function send(message) {
  const body = Buffer.from(JSON.stringify(message));
  process.stdout.write(`Content-Length: ${body.length}\r\n\r\n`);
  process.stdout.write(body);
}
function sibling(uri, name) { return uri.slice(0, uri.lastIndexOf("/") + 1) + name; }
function at(uri, line, start, end) {
  return { uri, range: { start: { line, character: start }, end: { line, character: end } } };
}
function handle(message) {
  const method = message.method || "";
  const params = message.params || {};
  if (["initialize", "textDocument/didOpen", "shutdown"].includes(method)) {
    fs.appendFileSync(RECORD, JSON.stringify({ pid: process.pid, version, method }) + "\n");
  }
  if (!("id" in message)) {
    if (method === "exit") process.exit(0);
    return;
  }
  const uri = (params.textDocument || {}).uri || "";
  const line = (params.position || {}).line;
  let result = null;
  if (method === "initialize") {
    result = {
      capabilities: { definitionProvider: true, referencesProvider: true },
      serverInfo: { name: "gopls", version },
    };
  } else if (method === "textDocument/references" && uri.endsWith("/greet.go")) {
    result = [at(sibling(uri, "use.go"), 3, 8, 13)];
  } else if (method === "textDocument/definition" && uri.endsWith("/use.go") && line === 3) {
    result = [at(sibling(uri, "greet.go"), 2, 5, 10)];
  }
  send({ jsonrpc: "2.0", id: message.id, result });
}
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const split = buffer.indexOf("\r\n\r\n");
    if (split < 0) return;
    const header = buffer.slice(0, split).toString();
    const length = Number(/content-length:\s*(\d+)/i.exec(header)[1]);
    if (buffer.length < split + 4 + length) return;
    const body = buffer.slice(split + 4, split + 4 + length).toString();
    buffer = buffer.slice(split + 4 + length);
    handle(JSON.parse(body));
  }
});
"#;

    fn node_available() -> bool {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    /// The Go module, and a directory whose `gopls` links to the fake's entry
    /// inside its own package, with the file that records its sessions.
    fn fixture() -> (Fixture, tempfile::TempDir, PathBuf, PathBuf) {
        let fixture = Fixture::with_files(&[
            ("go.mod", "module example.com/fixture\n\ngo 1.22\n"),
            (
                "greet.go",
                "package fixture\n\nfunc Greet() string {\n\treturn \"hi\"\n}\n",
            ),
            (
                "use.go",
                "package fixture\n\nfunc Use() string {\n\treturn Greet()\n}\n",
            ),
        ]);
        let bin = tempdir().expect("fake gopls directory");
        let record = bin.path().join("sessions.jsonl");
        let package = bin.path().join("node_modules").join("fake-gopls");
        fs::create_dir_all(&package).expect("fake package");
        let manifest = package.join("package.json");
        fs::write(&manifest, r#"{"name": "fake-gopls", "version": "1.0.0"}"#)
            .expect("write the fake's manifest");
        let entry = package.join("cli.js");
        fs::write(
            &entry,
            FAKE_GOPLS_JS.replace("@RECORD@", &record.display().to_string()),
        )
        .expect("write the fake gopls");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o755))
            .expect("make the fake gopls executable");
        std::os::unix::fs::symlink(&entry, bin.path().join("gopls")).expect("link gopls");
        (fixture, bin, record, manifest)
    }

    /// Readiness probes initialize a server and drop it without `shutdown`.
    /// The sweep shuts down every server it started, including one started
    /// only to settle a finished file's context. Count those sessions instead
    /// of treating every readiness handshake as an enrichment start. Document
    /// opens independently distinguish re-querying from context settlement.
    fn assert_sweep_sessions(
        record: &Path,
        expected: &[(&str, bool)],
        probe_limits: &[(&str, usize)],
    ) -> std::collections::HashMap<String, usize> {
        #[derive(Debug, serde::Deserialize)]
        struct Event {
            pid: u32,
            version: String,
            method: String,
        }

        let raw = fs::read_to_string(record).expect("the fake server's session records");
        let mut sessions = std::collections::HashMap::new();
        let mut finished = Vec::new();
        for line in raw.lines() {
            let event: Event = serde_json::from_str(line).expect("a server session event");
            if event.method == "initialize" {
                assert!(
                    sessions
                        .insert(event.pid, (event.version, false, false))
                        .is_none(),
                    "each process initializes once: {raw}"
                );
                continue;
            }
            let (version, opened, stopped) = sessions
                .get_mut(&event.pid)
                .expect("an initialized server owns each later event");
            assert_eq!(
                version.as_str(),
                event.version,
                "one version per session: {raw}"
            );
            assert!(!*stopped, "no events follow a session's shutdown: {raw}");
            match event.method.as_str() {
                "textDocument/didOpen" => *opened = true,
                "shutdown" => {
                    *stopped = true;
                    finished.push((version.clone(), *opened));
                }
                method => panic!("unexpected server event {method}: {raw}"),
            }
        }
        assert!(
            sessions
                .values()
                .all(|(_, opened, stopped)| !opened || *stopped),
            "every session that opened documents must finish, not disappear as a probe: {raw}"
        );
        let mut probes = std::collections::HashMap::new();
        for (version, opened, stopped) in sessions.values() {
            if !opened && !stopped {
                *probes.entry(version.clone()).or_insert(0usize) += 1;
            }
        }
        let limits: std::collections::HashMap<_, _> = probe_limits.iter().copied().collect();
        // Handshake-only probes are distinct from real sweep/context workers.
        // They are bounded by the phases that could not reuse an identified
        // process observation; unused allowance never carries across versions.
        assert!(
            probes.iter().all(|(version, count)| {
                *count <= limits.get(version.as_str()).copied().unwrap_or(0)
            }),
            "successful handshake-only probes exceeded {limits:?}; observed {probes:?}; \
             all events:\n{raw}"
        );
        assert_eq!(
            finished,
            expected
                .iter()
                .map(|(version, opened)| (version.to_string(), *opened))
                .collect::<Vec<_>>(),
            "the exact sweep sessions and whether they queried files; all events:\n{raw}"
        );
        eprintln!(
            "successful probes={probes:?}, source-derived limits={limits:?}; \
             cleanup may end probes before initialization; all events:\n{raw}"
        );
        probes
    }

    /// Startup and the CLI both ask for a sweep. The running-bit CAS coalesces
    /// them when startup is still sweeping; otherwise the CLI queues a second
    /// pass. Bound that scheduling choice independently. A settled in-daemon
    /// context survives the first pass's server shutdown, so any second pass
    /// needs no worker. An identified worker also supplies reusable readiness;
    /// an unidentified shim still needs a new process observation.
    fn completed_passes(log: &str) -> usize {
        bounded_passes(log, "LSP cold sweep complete")
    }

    fn bounded_passes(log: &str, expected_finish: &str) -> usize {
        let finishes: Vec<_> = log
            .lines()
            .filter(|line| {
                line.contains("LSP cold sweep complete")
                    || line.contains("LSP cold sweep ended with incomplete enrichment")
                    || line.contains("LSP cold sweep interrupted")
            })
            .collect();
        assert!(
            matches!(finishes.len(), 1 | 2),
            "startup and the CLI must coalesce or complete one pass each; daemon.log:\n{log}"
        );
        assert!(
            finishes.iter().all(|line| line.contains(expected_finish)),
            "every pass must end as {expected_finish}; daemon.log:\n{log}"
        );
        finishes.len()
    }

    /// `kin daemon stop`, then `kin daemon sweep` in a fresh daemon, which
    /// knows no proof context until it settles one.
    fn sweep_in_a_fresh_daemon(fixture: &Fixture, bin: &Path) -> Output {
        for args in [&["daemon", "stop"][..], &["daemon", "sweep"][..]] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
            command
                .fixture_path_prefix(bin)
                .args(args)
                .current_dir(&fixture.repo)
                .env("HOME", &fixture.home)
                .env("KIN_HOME", &fixture.kin_home)
                .env("KIN_EMBED_BACKEND", "cpu")
                .env("KIN_DAEMON_AUTO_EMBED", "0");
            let output = command.output().expect("run kin daemon");
            if args[1] == "sweep" {
                return output;
            }
        }
        unreachable!("the loop returns the sweep's output")
    }

    fn daemon_log(fixture: &Fixture) -> String {
        let raw = fs::read_to_string(fixture.repo.join(".kin").join("daemon.log"))
            .expect("the daemon's log");
        let mut plain = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                if chars.next() == Some('[') {
                    for end in chars.by_ref() {
                        if ('@'..='~').contains(&end) {
                            break;
                        }
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    }

    /// What the daemon appended, or its whole new log if it replaced the old
    /// one. Comparing the prefix also handles a replacement longer than before.
    fn daemon_log_since(fixture: &Fixture, before: &str) -> String {
        let log = daemon_log(fixture);
        log.strip_prefix(before).map(str::to_string).unwrap_or(log)
    }

    const SETTLED_WITHOUT_A_START: &str = "no server started to confirm it";
    const ASKED_AGAIN: &str = "sweep asks about a finished file again";
    const STARTED_TO_SETTLE: &str = "starting the language server to learn whether finished";

    #[test]
    fn a_matching_server_is_not_started_and_a_changed_one_is_asked_again() {
        if !node_available() {
            eprintln!("skipping: this test's fake language server needs node");
            return;
        }
        let (fixture, bin, record, manifest) = fixture();
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.fixture_path_prefix(bin.path());
        let (output, _) = fixture.init_json(&mut command, &[]);
        let field = enrichment_field(&output);
        assert_eq!(
            field["state"],
            "produced",
            "the first sweep proves the fixture's call: {field}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        completed_passes(&daemon_log(&fixture));
        assert_sweep_sessions(&record, &[("1.0.0", true)], &[("1.0.0", 0)]);

        // A fresh daemon must observe one handshake. Subsequent no-op passes
        // share that observation without starting a second probe.
        let before = daemon_log(&fixture);
        let output = sweep_in_a_fresh_daemon(&fixture, bin.path());
        let log = daemon_log_since(&fixture, &before);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        completed_passes(&log);
        let matching_probes = 1;
        let observed =
            assert_sweep_sessions(&record, &[("1.0.0", true)], &[("1.0.0", matching_probes)]);
        assert_eq!(observed.get("1.0.0").copied(), Some(1));
        assert!(log.contains(SETTLED_WITHOUT_A_START), "daemon.log:\n{log}");

        // The server changed: one start settles the context, and the finished
        // files proven under the old one are asked about again.
        fs::write(&manifest, r#"{"name": "fake-gopls", "version": "1.0.1"}"#)
            .expect("release the fake again");
        let before = daemon_log(&fixture);
        let output = sweep_in_a_fresh_daemon(&fixture, bin.path());
        let log = daemon_log_since(&fixture, &before);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        completed_passes(&log);
        let changed_probes = 0;
        assert_sweep_sessions(
            &record,
            &[("1.0.0", true), ("1.0.1", true)],
            &[("1.0.0", matching_probes), ("1.0.1", changed_probes)],
        );
        assert!(log.contains(STARTED_TO_SETTLE), "daemon.log:\n{log}");
        assert!(
            log.contains(ASKED_AGAIN),
            "files proven by the old server are asked again; daemon.log:\n{log}"
        );

        // The selected server cannot start: it cannot vouch for the finished
        // proofs, so they are asked about and owed, not served as current.
        // Keep a refusing executable first on PATH instead of unlinking it and
        // accidentally selecting a real gopls installed on the test host.
        let before = daemon_log(&fixture);
        let server = bin.path().join("gopls");
        fs::remove_file(&server).expect("unlink the server entry");
        fs::write(&server, "#!/bin/sh\nexit 127\n").expect("write the unavailable server");
        fs::set_permissions(&server, fs::Permissions::from_mode(0o755))
            .expect("make the refusing server executable");
        let _ = sweep_in_a_fresh_daemon(&fixture, bin.path());
        let log = daemon_log_since(&fixture, &before);
        bounded_passes(&log, "LSP cold sweep ended with incomplete enrichment");
        // The refusing executable may be attempted, but it never initializes:
        // neither successful probe sessions nor sweep sessions can be added.
        assert_sweep_sessions(
            &record,
            &[("1.0.0", true), ("1.0.1", true)],
            &[("1.0.0", matching_probes), ("1.0.1", changed_probes)],
        );
        assert!(
            log.contains("could not start the language server to check finished files"),
            "daemon.log:\n{log}"
        );
        assert!(log.contains(ASKED_AGAIN), "daemon.log:\n{log}");
    }

    /// Through a shim that replaces itself with the server, the running
    /// server is what is identified: every start is checked, and only a
    /// changed server re-asks finished files.
    #[test]
    fn a_server_behind_an_exec_shim_is_identified_while_it_runs() {
        if !node_available() {
            eprintln!("skipping: this test's fake language server needs node");
            return;
        }
        let (fixture, bin, record, manifest) = fixture();
        let entry = fs::canonicalize(bin.path().join("gopls")).expect("the fake's entry");
        fs::remove_file(bin.path().join("gopls")).expect("unlink the direct entry");
        let shim = bin.path().join("gopls");
        fs::write(
            &shim,
            format!("#!/bin/bash\nexec node \"{}\" \"$@\"\n", entry.display()),
        )
        .expect("write the shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("shim executable");

        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.fixture_path_prefix(bin.path());
        let (output, _) = fixture.init_json(&mut command, &[]);
        assert_eq!(
            enrichment_field(&output)["state"],
            "produced",
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let initial_probes = completed_passes(&daemon_log(&fixture)) - 1;
        let observed =
            assert_sweep_sessions(&record, &[("1.0.0", true)], &[("1.0.0", initial_probes)]);

        // The shim cannot be identified before a start, so one start checks,
        // and the server it ran is the one that made the proofs.
        let before = daemon_log(&fixture);
        let _ = sweep_in_a_fresh_daemon(&fixture, bin.path());
        let log = daemon_log_since(&fixture, &before);
        let matching_probes =
            observed.get("1.0.0").copied().unwrap_or(0) + completed_passes(&log) - 1;
        let observed = assert_sweep_sessions(
            &record,
            &[("1.0.0", true), ("1.0.0", false)],
            &[("1.0.0", matching_probes)],
        );
        let matching_probes = observed.get("1.0.0").copied().unwrap_or(0);
        assert!(log.contains(STARTED_TO_SETTLE), "daemon.log:\n{log}");
        assert!(
            !log.contains(ASKED_AGAIN),
            "the same server behind the shim keeps its proofs; daemon.log:\n{log}"
        );

        let before = daemon_log(&fixture);
        fs::write(&manifest, r#"{"name": "fake-gopls", "version": "1.0.1"}"#)
            .expect("release the fake again");
        let _ = sweep_in_a_fresh_daemon(&fixture, bin.path());
        let log = daemon_log_since(&fixture, &before);
        let changed_probes = completed_passes(&log) - 1;
        assert_sweep_sessions(
            &record,
            &[("1.0.0", true), ("1.0.0", false), ("1.0.1", true)],
            &[("1.0.0", matching_probes), ("1.0.1", changed_probes)],
        );
        assert!(
            log.contains(ASKED_AGAIN),
            "a changed server behind the shim re-asks; daemon.log:\n{log}"
        );
    }
}
