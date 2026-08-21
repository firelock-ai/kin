// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every MCP answer says whether the graph behind it survives the daemon
//! (FIR-2421).
//!
//! The transcript this replays: an agent wrote a source file, called
//! `kin_graph_status`, read `entity_count: 14`, located a class it had just
//! written and got a real entity id back, wrote in its own log that its work
//! was in the graph, and never committed. Every one of those payloads was
//! true. The daemon admits host content into its live query graph
//! continuously, so the entities and the id were real; nothing in any of them
//! said the entity layer is rebuilt from zero on the next open. After the
//! session `kin log` held one change carrying `entities=0` and a fresh open
//! read the files back with no entities at all.
//!
//! So these cases drive the real stdio MCP surface against a real daemon over
//! a real working copy, and assert on the disclosure rather than on the
//! counts: a status and a locate taken while the work is uncommitted must both
//! say so, and the same two calls after a commit must say the opposite. Both
//! directions matter. A disclosure that always warns is noise an agent learns
//! to skip, which is the failure mode that would make this fix worthless
//! without ever failing a test.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

mod common;

use common::Command;

/// Wall-clock bound for one four-frame stdio session against a live daemon.
const SESSION_BOUND: Duration = Duration::from_secs(60);

/// How long the fixture waits for the daemon to record that it admitted the
/// host write.
///
/// Deliberately generous rather than tuned. The wait below is event driven, so
/// this bound never paces a passing run: it is only how long a run that is
/// going to fail spends proving it. A loaded runner reconciling several seconds
/// late is the case a tighter bound turned into a red queue entry.
const ADMISSION_BOUND: Duration = Duration::from_secs(120);

/// How long the fixture waits for the daemon to record that its file watcher is
/// registered, before making the host write that watcher has to observe.
const WATCHER_BOUND: Duration = Duration::from_secs(90);

/// How long the counters get to catch up with the admission the daemon just
/// recorded. Short on purpose: a bound long enough to hide a missing admission
/// would put back the ambiguity the wait above exists to remove.
const COUNT_SETTLE_BOUND: Duration = Duration::from_secs(30);

/// What the daemon logs once `FileWatcher::new` has registered the watch
/// (`crates/kin-index/src/watcher.rs`, immediately after `watch()` returns).
const WATCHER_RECORD: &str = "started file watcher";

/// What the reconciliation loop logs once it has admitted a working-copy change
/// into repository authority (`crates/kin-daemon/src/loop_runner.rs`).
const ADMISSION_RECORD: &str = "admitted exact workspace tree into repository authority";

/// What the daemon logs immediately after it writes `.kin/daemon.port`
/// (`crates/kin-daemon/src/daemon.rs`, the line after
/// `publish_daemon_endpoint`).
const ENDPOINT_RECORD: &str = "published the daemon endpoint";

/// What the reconciliation loop logs when its startup catch-up finds host paths
/// the working copy changed while nothing was watching
/// (`crates/kin-daemon/src/loop_runner.rs`).
const CATCH_UP_RECORD: &str = "admitting host paths modified since the last complete admission";

/// The settle budget a quiet host needs, and the floor every busier host starts
/// from.
///
/// Generous against the few hundred milliseconds this repository's four vectors
/// take, so expiry on an idle box means the lock is never being yielded rather
/// than that embedding was merely busy.
const RETRY_BOUND_FLOOR: Duration = Duration::from_secs(30);

/// The most the settle may stretch to, so a daemon that never yields the lock
/// still fails inside a bounded pass.
///
/// The same 120 seconds [`ADMISSION_BOUND`] allows itself, for the same reason:
/// the wait is event driven, so a passing run never spends it, and this is only
/// how long a run that is going to fail spends proving it.
const RETRY_BOUND_CEILING: Duration = Duration::from_secs(120);

/// How long the fixture will keep repeating a session while `kin_graph_status`
/// refuses to sample its counts, scaled by how oversubscribed this host is.
///
/// A single fixed number was calibrated for an idle box and had no margin left
/// on a busy one. Three solo runs of this case on an idle eighteen core
/// workstation took 25.9, 29.0 and 27.7 seconds end to end against a settle
/// bound of 30, so the case was already finishing inside a budget it had nearly
/// spent. Under fleet co-load the same case ran 70.3 seconds and the settle
/// burned all thirty of them without the daemon ever answering wrongly: it was
/// asking to be retried while the embedding-work lock moved, which is its
/// documented answer. The host read load average 136 on those eighteen cores at
/// the time, on a pass whose slowest routine test took 413 seconds.
///
/// What the settle waits on is the daemon finishing embedding work, and that is
/// CPU time competing with everything else on the host, so the budget tracks
/// the competition. The floor stays what a quiet box needs, which keeps the
/// discrimination this bound exists for: on an unloaded machine a daemon that
/// never yields still fails in thirty seconds, exactly as before.
fn retry_bound() -> Duration {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    scaled_retry_bound(sysinfo::System::load_average().one, cores)
}

/// [`RETRY_BOUND_FLOOR`] stretched by run-queue depth per core.
///
/// Split from the reading above so the arithmetic can be driven with observed
/// numbers rather than with whatever the box running the tests happens to
/// report at that instant.
/// The deadline a settle already under way should hold.
///
/// A load average is a one minute mean, so a host that saturates as a settle
/// begins still reads quiet for the first samples of it, and a budget taken
/// once at the start is the budget an idle box would have got. This takes the
/// widest the host justifies while the settle runs. It only ever widens, so a
/// reading that falls back cannot cut short a settle already in progress, and
/// every candidate is measured from `started` against a bound already clamped
/// to [`RETRY_BOUND_CEILING`], so no sequence of readings pushes the pass past
/// the two minutes it was always bounded by.
fn widened_settle_deadline(current: Instant, started: Instant, bound: Duration) -> Instant {
    current.max(started + bound)
}

fn scaled_retry_bound(run_queue_depth: f64, cores: usize) -> Duration {
    let widest = RETRY_BOUND_CEILING.as_secs_f64() / RETRY_BOUND_FLOOR.as_secs_f64();
    let stretch = run_queue_depth / cores.max(1) as f64;
    // Platforms that do not publish a load average report zero, and a garbled
    // reading is not a reason to change the budget, so anything that is not a
    // finite number falls back to the floor rather than propagating.
    let stretch = if stretch.is_finite() { stretch } else { 1.0 };
    RETRY_BOUND_FLOOR.mul_f64(stretch.clamp(1.0, widest))
}

struct IsolatedDaemon {
    child: Option<common::RuntimeOwnedChild>,
    log: std::path::PathBuf,
}

impl IsolatedDaemon {
    /// Spawn the daemon with its own log kept OUTSIDE the repository, so that
    /// reading the daemon's record of its own progress cannot itself produce
    /// the watcher events this fixture is about.
    fn spawn(repo: &Path, log: &Path, runtime: &common::IsolatedDaemonRuntime) -> Self {
        let sink = fs::File::create(log).expect("create the daemon log");
        let mut command = runtime.daemon_command();
        let child = command
            .arg("--repo")
            .arg(repo)
            .arg("--port")
            .arg("0")
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "0")
            // The waits below read the daemon's own INFO records, so ask for
            // them explicitly rather than inheriting whatever the ambient
            // filter happens to be.
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(sink))
            .spawn_owned()
            .expect("spawn isolated kin-daemon");
        Self {
            child: Some(child),
            log: log.to_path_buf(),
        }
    }

    /// Wait until the daemon records that its file watcher is registered.
    ///
    /// Serving is not watching. The daemon publishes `.kin/daemon.port` and
    /// retires its warming surface in `run_with_authority_on` BEFORE it spawns
    /// the reconciliation loop, and that loop is what calls `FileWatcher::new`;
    /// the loop then deliberately admits nothing at startup, because
    /// working-copy content crosses into authority only through a watcher
    /// observed edit or an explicit seam. So a host write made between those
    /// two points raises no event and nothing ever replays it, and the wait for
    /// admission afterwards can only burn its whole bound.
    ///
    /// Measured on this host the gap is a few milliseconds and the fixture won
    /// it by 5 to 113ms when it won; the runs that failed are exactly the runs
    /// where it lost. Waiting for the daemon to say the watch exists removes
    /// the race rather than widening a bound around it.
    fn wait_until_watching(&self) {
        self.wait_for_record(
            WATCHER_RECORD,
            0,
            WATCHER_BOUND,
            "register its file watcher",
        );
    }

    /// Byte offset the log has reached, so a later wait only considers records
    /// written after this point and cannot match an older line.
    fn log_offset(&self) -> u64 {
        fs::metadata(&self.log).map(|meta| meta.len()).unwrap_or(0)
    }

    /// Everything this daemon has recorded so far.
    fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Poll the daemon's log for `record`, considering only bytes at or after
    /// `from`. The bound expiring is a real failure that names the record that
    /// never arrived and quotes what the daemon did say instead.
    fn wait_for_record(&self, record: &str, from: u64, bound: Duration, what: &str) {
        let deadline = Instant::now() + bound;
        loop {
            let text = fs::read_to_string(&self.log).unwrap_or_default();
            let tail = text.get(from as usize..).unwrap_or(&text);
            if tail.contains(record) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not {what} within {bound:?}: its log carries no {record:?} \
                 record after byte {from}. What it did log:\n{tail}"
            );
            thread::sleep(Duration::from_millis(50));
        }
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

/// A committed repository with entity source, so durable authority carries a
/// nonzero entity count before anything uncommitted is written.
///
/// A repository whose durable count is zero would let a broken derivation pass
/// by accident: with `durable == 0` the live-only count is just the live count,
/// so a disclosure that ignored durable authority entirely would still print
/// the right number.
fn seed_repository(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/storage.rs"),
        b"pub fn open_store() -> u32 {\n    7\n}\n\npub fn close_store() -> u32 {\n    open_store() + 1\n}\n",
    )
    .expect("write entity source");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "storage"]);
}

/// Where that file is written. Named here because the wait for admission
/// re-arms the same path rather than only polling it.
const UNCOMMITTED_PATH: &str = "src/link_graph.rs";

/// The file the agent wrote and then located. Named for the transcript's
/// `link_graph.py`, which is the write whose entities the second locate found
/// seven seconds later.
const UNCOMMITTED_SOURCE: &[u8] =
    b"pub fn build_link_graph() -> u32 {\n    3\n}\n\npub fn walk_link_graph() -> u32 {\n    build_link_graph() + 1\n}\n\npub fn render_link_graph() -> u32 {\n    walk_link_graph() + 1\n}\n";

fn kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn kin_against_daemon(repo: &Path, home: &Path, port: u16, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .current_dir(repo)
        .output()
        .expect("run kin against the isolated daemon")
}

fn stdout_of(output: &std::process::Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// One `kin mcp start` session: handshake, then status, then locate.
///
/// The order is the transcript's. Both calls are made in one session because
/// the claim is about every envelope rather than about the status tool alone:
/// the locate is the call the agent actually believed, and it reaches its
/// envelope through the generic `/health` lift rather than through graph
/// status's own selected-graph observation, so the two exercise different
/// code even though they must agree.
fn session_frames() -> String {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kin-durability-test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kin_graph_status","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_locate","arguments":{"query":"build_link_graph"}}}"#,
    ]
    .join("\n")
        + "\n"
}

/// Drive the real stdio MCP binary against the running daemon and return the
/// parsed payload of each `tools/call` response, keyed by request id.
fn run_mcp_session(repo: &Path, home: &Path, port: u16) -> Vec<(u64, serde_json::Value)> {
    let started = Instant::now();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["mcp", "start"])
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("TMPDIR", std::env::temp_dir())
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kin mcp start");

    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(session_frames().as_bytes())
        .expect("write session frames");

    // Both pipes drain concurrently: a locate payload alone can exceed the
    // pipe buffer, and a reader that waits for exit first deadlocks against a
    // writer blocked on a full pipe.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let stdout_reader = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut collected);
        collected
    });
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stderr_reader = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut collected);
        collected
    });

    let deadline = started + SESSION_BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll kin mcp start") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader.join().expect("join stdout reader");
    let stderr =
        String::from_utf8_lossy(&stderr_reader.join().expect("join stderr reader")).into_owned();
    let status =
        status.unwrap_or_else(|| panic!("kin mcp start did not finish; stderr:\n{stderr}"));
    assert!(
        status.success(),
        "kin mcp start exited with {status}; stderr:\n{stderr}"
    );

    String::from_utf8(stdout)
        .expect("stdout is UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let frame: serde_json::Value =
                serde_json::from_str(line).expect("stdout lines are JSON-RPC");
            let id = frame.get("id")?.as_u64()?;
            let text = frame
                .get("result")?
                .get("content")?
                .get(0)?
                .get("text")?
                .as_str()?;
            Some((
                id,
                serde_json::from_str(text).expect("tool payload is JSON"),
            ))
        })
        .collect()
}

fn payload(session: &[(u64, serde_json::Value)], id: u64, what: &str) -> serde_json::Value {
    session
        .iter()
        .find(|(frame_id, _)| *frame_id == id)
        .unwrap_or_else(|| panic!("session carried no {what} response: {session:?}"))
        .1
        .clone()
}

/// The live entity count the daemon reports, read through `kin graph status`
/// so the poll below does not have to spawn a whole MCP session per tick.
///
/// `None` while the command exits non-zero. It does that on a critical graph
/// health issue, and one of those is transient by construction: authority
/// admission binds the entity layer and facets are written per file after it,
/// so a read taken between the two halves sees a derived tree that trails
/// authority (`crates/kin-cli/src/commands/graph_health.rs:481`). That is the
/// gap the poll below exists to cross, so a reading taken inside it is "not
/// yet" rather than a failure. Its text still reaches the caller, which is what
/// reports it when the bound expires.
fn live_entity_count(repo: &Path, home: &Path, port: u16) -> (Option<u64>, std::process::Output) {
    let output = kin_against_daemon(repo, home, port, &["graph", "status"]);
    if !output.status.success() {
        return (None, output);
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = text
        .lines()
        .find(|line| line.contains("Entities:"))
        .unwrap_or_else(|| panic!("graph status printed no entity line:\n{text}"));
    let after = line
        .split("Entities:")
        .nth(1)
        .expect("the entity line carries a count");
    let count = after
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("could not read an entity count from {line:?}"));
    (Some(count), output)
}

/// Wait until ambient admission has taken the host write into the live graph.
///
/// Event driven, on the daemon's own record of the admission it performed,
/// rather than a poll that can only ever report that a count has not moved.
/// A poll cannot tell "the reconciliation pass is still running" from "no
/// event was ever raised, so no pass will ever run", and those two are the
/// whole question: they differ by whether the watcher existed when the write
/// landed. `wait_until_watching` above now guarantees it did, and this wait
/// reads the consequence.
///
/// `since` is the log offset taken immediately before the write, so an
/// admission recorded earlier in this daemon's life cannot satisfy it.
///
/// A passing run costs exactly as long as admission actually took, so the
/// generous bound is spent only by a run that is going to fail, and that
/// failure names the record that never arrived instead of timing out vaguely.
fn wait_for_live_growth(
    daemon: &IsolatedDaemon,
    repo: &Path,
    home: &Path,
    port: u16,
    above: u64,
    since: u64,
) -> u64 {
    daemon.wait_for_record(
        ADMISSION_RECORD,
        since,
        ADMISSION_BOUND,
        "admit the host write",
    );

    // The daemon publishes its record and its counters a moment apart, so this
    // closes that last gap and nothing more. It is deliberately short: it must
    // not be able to stand in for the wait above, because a bound long enough
    // to hide a missing admission is the bug this test kept reporting.
    let deadline = Instant::now() + COUNT_SETTLE_BOUND;
    loop {
        let (live, status) = live_entity_count(repo, home, port);
        if live.is_some_and(|live| live > above) {
            return live.expect("the reading above carried a count");
        }
        // Printing the reading this loop actually took, rather than running the
        // command again to explain itself: a second run answers about a later
        // instant, and the helper that asserts on its exit status would panic
        // there instead of reporting here.
        assert!(
            Instant::now() < deadline,
            "the daemon recorded admitting the host write, but the live entity count stayed at \
             {live:?} against above={above}; graph status exited {} and said:\n{}\n{}",
            status.status,
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// Whether `kin_graph_status` refused this call and asked to be repeated.
///
/// `crates/kin-daemon/src/api.rs:2084` fails the call outright when the
/// embedding-work lock is held, because every count the payload reports has to
/// describe one instant and it cannot sample them while embedding is moving.
/// The answer carries that instruction and no observation.
fn asks_for_retry(payload: &serde_json::Value) -> bool {
    payload
        .get("message")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|message| message.contains("retry kin_graph_status"))
}

/// Drive the session, repeating it while the daemon answers with that refusal.
///
/// Re-arming the host write above re-parses and re-embeds the file, so the
/// window in which the status call can land on a held embedding lock is wider
/// than it was, but the refusal predates this: any write admitted shortly
/// before the session could always meet it. Reading that refusal as a payload
/// is asserting on the absence of an answer, so the fixture takes the retry the
/// tool asked for. The bound is what keeps this a discriminator rather than a
/// mask: a daemon that never yields the lock still fails, naming how many times
/// it refused.
fn settled_mcp_session(repo: &Path, home: &Path, port: u16) -> Vec<(u64, serde_json::Value)> {
    let started = Instant::now();
    let mut deadline = started + retry_bound();
    let mut refusals = 0_u32;
    loop {
        let session = run_mcp_session(repo, home, port);
        let status = payload(&session, 2, "kin_graph_status");
        if !asks_for_retry(&status) {
            return session;
        }
        refusals += 1;
        // A load average is a one minute mean, so a host that saturates as this
        // settle begins still reads quiet for the first samples of it and the
        // budget taken at the start is the one an idle box would have got. Take
        // the widest the host justifies while the settle runs instead. It only
        // ever widens, and every candidate is already clamped to
        // RETRY_BOUND_CEILING measured from `started`, so the pass stays
        // bounded by the same two minutes it was before.
        deadline = widened_settle_deadline(deadline, started, retry_bound());
        assert!(
            Instant::now() < deadline,
            "kin_graph_status refused {refusals} times without ever sampling its counts: {status}"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn durability(payload: &serde_json::Value) -> serde_json::Value {
    payload
        .get("_kin")
        .unwrap_or_else(|| panic!("payload carries no _kin envelope: {payload}"))
        .get("durability")
        .unwrap_or_else(|| panic!("envelope carries no durability object: {payload}"))
        .clone()
}

#[test]
fn mcp_status_and_locate_disclose_live_only_entities_and_then_stop_once_a_commit_records_them() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    // Canonicalized before anything binds it. On macOS a temporary directory
    // is reached through `/var`, which is a symlink to `/private/var`, and the
    // daemon's file watcher reports host events under the resolved path. A
    // repository bound to the unresolved one therefore never matches its own
    // watcher events, and ambient admission silently takes nothing: the
    // fixture would sit at the committed entity count with no error anywhere.
    let repo = repo.canonicalize().expect("resolve the repository path");
    let home = home.canonicalize().expect("resolve the home path");
    seed_repository(&repo);

    let init = kin(&repo, &home, &["init", ".", "--json"]);
    let init_payload: serde_json::Value =
        serde_json::from_slice(&stdout_of(&init, "kin init").into_bytes())
            .expect("init emits JSON");
    let durable_at_init = init_payload["semantic_enrichment"]["entity_count"]
        .as_u64()
        .expect("init reports a durable entity count");
    assert!(
        durable_at_init > 0,
        "the fixture needs durable entities before the uncommitted write, got \
         {durable_at_init}: {init_payload}"
    );

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    // Kept beside the repository rather than inside it: the fixture reads this
    // file while the daemon is watching, and a log under the working copy would
    // be a source of the very events under test.
    let daemon_log = root.path().join("kin-daemon.log");
    let mut daemon = IsolatedDaemon::spawn(&repo, &daemon_log, &runtime);
    let port = daemon.wait_until_serving(&repo.join(".kin"));
    // Serving is not watching, and the write below is the one the watcher has
    // to see. Nothing replays an event raised before the watch existed.
    daemon.wait_until_watching();

    let before_write = daemon.log_offset();
    // The transcript's first move: write a file, through nothing but the
    // filesystem, exactly as an agent's `write_file` tool does.
    fs::write(repo.join(UNCOMMITTED_PATH), UNCOMMITTED_SOURCE)
        .expect("write the uncommitted source");
    let live = wait_for_live_growth(&daemon, &repo, &home, port, durable_at_init, before_write);

    let uncommitted = settled_mcp_session(&repo, &home, port);
    let status = payload(&uncommitted, 2, "kin_graph_status");
    let locate = payload(&uncommitted, 3, "semantic_locate");

    assert_eq!(
        status["entity_count"].as_u64(),
        Some(live),
        "the fixture and the status tool must be looking at one graph: {status}"
    );
    assert_eq!(
        status["durable_entity_count"].as_u64(),
        Some(durable_at_init),
        "graph status must report the durable count `kin init` published, beside the live one \
         it already reported: {status}"
    );

    let status_durability = durability(&status);
    assert_eq!(
        status_durability["state"], "live_uncommitted",
        "the graph holds {live} entities against {durable_at_init} durable, so status must say \
         the work is unrecorded: {status_durability}"
    );
    assert_eq!(
        status_durability["live_only_entities"].as_u64(),
        Some(live - durable_at_init),
        "and must say how much of it: {status_durability}"
    );
    let note = status_durability["note"]
        .as_str()
        .expect("a durability object always carries a note");
    assert!(
        note.contains("uncommitted") && note.contains("Commit to record it"),
        "the note is what an agent reads instead of the counts: {note:?}"
    );

    // The call the agent actually believed. It reaches its envelope through
    // the generic `/health` lift rather than through graph status's own
    // observation, so it is separate code that has to agree.
    assert!(
        locate["entities"]
            .as_array()
            .is_some_and(|found| !found.is_empty()),
        "the fixture needs locate to find the uncommitted entity, or the disclosure beside it \
         proves nothing: {locate}"
    );
    let locate_durability = durability(&locate);
    assert_eq!(
        locate_durability["state"], "live_uncommitted",
        "locate returned an entity id for source no committed change carries, and must say so \
         in the same envelope: {locate_durability}"
    );
    assert_eq!(
        locate_durability["live_only_entities"].as_u64(),
        Some(live - durable_at_init),
        "and must count it the same way status does: {locate_durability}"
    );

    // The other direction. A disclosure that cannot go quiet is not a
    // disclosure, and the commit is what the agent should have run.
    let commit = kin_against_daemon(
        &repo,
        &home,
        port,
        &["commit", "-m", "record the link graph"],
    );
    stdout_of(&commit, "kin commit");

    let recorded = settled_mcp_session(&repo, &home, port);
    let status_after = payload(&recorded, 2, "kin_graph_status");
    let locate_after = payload(&recorded, 3, "semantic_locate");

    let status_after_durability = durability(&status_after);
    assert_eq!(
        status_after_durability["state"], "recorded",
        "after the commit durable authority carries the graph, so status must stop warning: \
         {status_after_durability}"
    );
    assert_eq!(
        status_after_durability["live_only_entities"].as_u64(),
        Some(0),
        "with nothing left uncommitted: {status_after_durability}"
    );
    assert_eq!(
        status_after["durable_entity_count"].as_u64(),
        status_after["entity_count"].as_u64(),
        "and the two counts it reports must now agree: {status_after}"
    );
    assert_eq!(
        durability(&locate_after)["state"],
        "recorded",
        "and every other envelope must agree with it: {locate_after}"
    );

    daemon.stop();
}

#[test]
fn a_quiet_host_keeps_the_settle_budget_the_fixed_bound_gave_it() {
    // The property the stretch must not cost: on a box that is not fighting
    // anyone, a daemon that never yields the lock still fails in thirty
    // seconds. The stretch is for contention, so a host at or under its own
    // core count gets nothing extra.
    assert_eq!(
        scaled_retry_bound(1.2, 18),
        RETRY_BOUND_FLOOR,
        "an idle host must keep paying exactly the old price"
    );
    assert_eq!(
        scaled_retry_bound(18.0, 18),
        RETRY_BOUND_FLOOR,
        "a host busy up to its core count is not oversubscribed"
    );
}

#[test]
fn the_load_that_produced_the_failure_buys_a_budget_that_covers_it() {
    // The reading taken when this case failed: load average 136.33 on eighteen
    // cores, in a pass where the case itself ran 70.265 seconds and the settle
    // spent all thirty of its seconds inside that.
    let bound = scaled_retry_bound(136.33, 18);
    assert_eq!(
        bound, RETRY_BOUND_CEILING,
        "seven times oversubscribed is past the widest stretch, so the ceiling applies"
    );
    assert!(
        bound >= Duration::from_secs_f64(70.265),
        "the budget has to cover what that run actually spent, and {bound:?} does not"
    );
}

#[test]
fn the_stretch_is_proportional_and_survives_a_host_that_reports_nothing() {
    assert_eq!(
        scaled_retry_bound(36.0, 18),
        Duration::from_secs(60),
        "twice oversubscribed buys twice the floor, not the ceiling"
    );
    assert_eq!(
        scaled_retry_bound(0.0, 18),
        RETRY_BOUND_FLOOR,
        "a platform that publishes no load average must not shrink the budget"
    );
    assert_eq!(
        scaled_retry_bound(f64::NAN, 18),
        RETRY_BOUND_FLOOR,
        "a garbled reading is not a reason to change the budget"
    );
    assert_eq!(
        scaled_retry_bound(f64::INFINITY, 18),
        RETRY_BOUND_FLOOR,
        "an unbounded reading is garbled rather than evidence of load, and must not \
         stretch anything"
    );
    assert_eq!(
        scaled_retry_bound(4.0, 0),
        RETRY_BOUND_CEILING,
        "a host reporting no cores at all must not divide by zero"
    );
}

#[test]
fn a_settle_that_begins_quiet_and_turns_busy_gets_the_busy_budget() {
    // Why the settle re-reads the host instead of budgeting once: a load
    // average is a one minute mean, so a box that goes from idle to saturated
    // at the instant this case starts reports an idle number for the first
    // samples of the settle, and a budget taken once is the idle one for the
    // whole run. The rule is to hold the widest budget the host justifies while
    // the settle runs.
    let started = Instant::now();
    let quiet = widened_settle_deadline(started, started, scaled_retry_bound(1.0, 18));
    assert_eq!(
        quiet,
        started + RETRY_BOUND_FLOOR,
        "the first reading of an idle host is the floor"
    );

    let busy = widened_settle_deadline(quiet, started, scaled_retry_bound(136.33, 18));
    assert_eq!(
        busy,
        started + RETRY_BOUND_CEILING,
        "a saturation the first reading could not see still buys its budget"
    );

    // And only ever widens: a reading that falls back must not cut short a
    // settle already under way, or the lag works in the other direction.
    assert_eq!(
        widened_settle_deadline(busy, started, scaled_retry_bound(1.0, 18)),
        busy,
        "a later quiet reading must not shorten a settle that already widened"
    );

    // Still bounded by the same ceiling the fixed pass had, measured from the
    // instant the settle began.
    assert!(
        busy <= started + RETRY_BOUND_CEILING,
        "no sequence of readings may push the settle past its ceiling"
    );
}

/// FIR-2466. The endpoint a client finds is a daemon that is already watching.
///
/// `.kin/daemon.port` is the readiness signal real clients key on, and the
/// daemon used to publish it and spawn the reconciliation loop afterwards. The
/// loop is what calls `FileWatcher::new`, and startup replays nothing, so a
/// write landing between those two points raised no event and never reached the
/// graph at all. The gap measured a few milliseconds on this host and the
/// fixture that depended on losing that race lost it repeatedly.
///
/// Asserted on the ordering of the daemon's own records rather than on a write
/// that has to win a race, so restoring the old order fails this outright
/// instead of failing it sometimes.
#[test]
fn the_reconciliation_watch_is_armed_before_the_endpoint_is_published() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    let repo = repo.canonicalize().expect("resolve the repository path");
    let home = home.canonicalize().expect("resolve the home path");
    seed_repository(&repo);
    stdout_of(&kin(&repo, &home, &["init", "."]), "kin init");

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let daemon_log = root.path().join("kin-daemon.log");
    let mut daemon = IsolatedDaemon::spawn(&repo, &daemon_log, &runtime);
    daemon.wait_until_serving(&repo.join(".kin"));
    // Both records have to be present before their positions mean anything.
    // The port file appears a moment before the line that reports it, so the
    // wait above proves the publication happened and this proves it was logged.
    daemon.wait_for_record(ENDPOINT_RECORD, 0, WATCHER_BOUND, "publish its endpoint");
    daemon.wait_for_record(WATCHER_RECORD, 0, WATCHER_BOUND, "register its file watcher");

    let log = daemon.log_text();
    let watch_at = log
        .find(WATCHER_RECORD)
        .unwrap_or_else(|| panic!("the daemon logged no watcher record:\n{log}"));
    let publish_at = log
        .find(ENDPOINT_RECORD)
        .unwrap_or_else(|| panic!("the daemon logged no endpoint record:\n{log}"));
    assert!(
        watch_at < publish_at,
        "the watch must exist before the endpoint advertises this daemon, but the watcher \
         record is at byte {watch_at} and the publication record at {publish_at}; a client \
         writing the instant the port appears would have that write observed by nobody. \
         The log:\n{log}"
    );

    daemon.stop();
}

/// FIR-2499. A file written while no daemon was running reaches the graph
/// without a commit.
///
/// The stranger's finding was that the graph is always one commit behind the
/// work, and the mechanism is this: a watcher reports only edits it was alive
/// for. An idle timeout ends a daemon mid-session, the next command starts a
/// fresh one, and everything written in between was seen by nobody. Startup
/// admitted nothing, so nothing ever replayed it and the file stayed invisible
/// until a commit swept it in.
///
/// Written between two daemons deliberately: it is the only construction in
/// which no watcher can have seen the write, so a pass here cannot be the
/// watcher quietly doing the work.
#[test]
fn a_file_written_while_no_daemon_watched_is_admitted_by_the_next_one() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    let repo = repo.canonicalize().expect("resolve the repository path");
    let home = home.canonicalize().expect("resolve the home path");
    seed_repository(&repo);
    let init = kin(&repo, &home, &["init", ".", "--json"]);
    let init_payload: serde_json::Value =
        serde_json::from_slice(&stdout_of(&init, "kin init").into_bytes())
            .expect("init emits JSON");
    let durable_at_init = init_payload["semantic_enrichment"]["entity_count"]
        .as_u64()
        .expect("init reports a durable entity count");

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let first_log = root.path().join("kin-daemon-first.log");
    let mut first = IsolatedDaemon::spawn(&repo, &first_log, &runtime);
    let first_port = first.wait_until_serving(&repo.join(".kin"));
    first.wait_until_watching();

    // One ordinary watched write, so this store records a complete admission
    // and the catch-up below has a window to open at. Without a marker there is
    // no lower bound and the pass correctly declines to run at all.
    let before_write = first.log_offset();
    fs::write(repo.join(UNCOMMITTED_PATH), UNCOMMITTED_SOURCE)
        .expect("write the watched source");
    let watched = wait_for_live_growth(
        &first,
        &repo,
        &home,
        first_port,
        durable_at_init,
        before_write,
    );
    first.stop();

    // The write nothing could see. No daemon is running, so no watcher exists
    // to raise an event for it and nothing will replay one.
    fs::write(
        repo.join("src/catch_up.rs"),
        b"pub fn build_catch_up() -> u32 {\n    5\n}\n\npub fn walk_catch_up() -> u32 {\n    build_catch_up() + 1\n}\n\npub fn render_catch_up() -> u32 {\n    walk_catch_up() + 1\n}\n",
    )
    .expect("write the unwatched source");

    let second_log = root.path().join("kin-daemon-second.log");
    let mut second = IsolatedDaemon::spawn(&repo, &second_log, &runtime);
    let second_port = second.wait_until_serving(&repo.join(".kin"));
    second.wait_for_record(
        CATCH_UP_RECORD,
        0,
        WATCHER_BOUND,
        "plan a startup catch-up over what changed while it was down",
    );
    let caught_up = wait_for_live_growth(&second, &repo, &home, second_port, watched, 0);
    assert!(
        caught_up > watched,
        "the graph has to carry the file written while nothing watched: {caught_up} against \
         {watched} before it"
    );

    second.stop();
}
