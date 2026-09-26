// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Nothing a language server started outlives the daemon's hold on it: not
//! after a stop, not after a drop, and not after the daemon itself dies without
//! running another line.
//!
//! The fake server below is shaped like typescript-language-server with a
//! tsserver that does not follow it. It starts a child of its own that ignores
//! SIGTERM and never reads stdin, so neither a polite stop nor its parent's
//! exit ends that child. Only a kill aimed at the whole process group does. The
//! server itself exits when its stdin closes, as a vscode-languageserver server
//! does.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use kin_model::LanguageId;

use super::{
    retire_disconnected_server, start_resolved_language_server, stop_language_servers,
    take_servers_a_sweep_started,
};

/// Records its own pid and its child's, then answers JSON-RPC until stdin
/// closes or `exit` arrives. The child inherits SIGTERM as ignored across its
/// exec, so the stop signal cannot end it.
const FAKE_SERVER: &str = r#"
import json, os, signal, subprocess, sys

def ignore_term():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

record = sys.argv[1]
child = subprocess.Popen(
    ["sleep", "600"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    preexec_fn=ignore_term,
)
with open(record + ".partial", "w") as out:
    out.write(f"{os.getpid()} {child.pid}\n")
os.replace(record + ".partial", record)
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
    if "id" not in message:
        if message.get("method") == "exit":
            sys.exit(0)
        continue
    result = {"capabilities": {}} if message.get("method") == "initialize" else None
    body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    sys.stdout.buffer.flush()
"#;

/// Where the fake server records the two pids, under the test's root.
const PIDS: &str = "fake-server.pids";

/// How long the processes get to be gone. A stop returns once the group is
/// empty, a drop sends SIGKILL before it returns, and the watcher takes the
/// termination grace, about two seconds. The rest is room for a loaded machine.
const SETTLE: Duration = Duration::from_secs(20);

/// Selects worker mode for [`abrupt_owner_worker`] and names its scratch root.
const ABRUPT_OWNER_ROOT: &str = "KIN_TEST_LANGUAGE_SERVER_ABRUPT_OWNER_ROOT";

/// Written by the worker once it holds a started server.
const OWNER_READY: &str = "owner.ready";

/// The worker's own lifetime cap, so a parent that died first cannot leave it
/// holding a server.
const OWNER_WALL_CLOCK_CAP: Duration = Duration::from_secs(120);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime")
}

/// Start the fake server the way the sweep and the incremental path start one.
async fn start_fake_server(root: &Path) -> (kin_lsp::lifecycle::LspServer, [u32; 2]) {
    let record = root.join(PIDS);
    let server = start_resolved_language_server(
        LanguageId::Python,
        "python3",
        &[
            "-u".to_string(),
            "-c".to_string(),
            FAKE_SERVER.to_string(),
            record.display().to_string(),
        ],
        root,
        kin_lsp::adapters::ServerLaunch::default(),
    )
    .await
    .expect("the daemon starts the fake language server");
    (server, read_pids(&record))
}

/// The server's pid and its child's. The server writes them before it answers
/// `initialize`, so they exist once a start has returned.
fn read_pids(record: &Path) -> [u32; 2] {
    let text = std::fs::read_to_string(record).expect("the fake server recorded its pids");
    let pids: Vec<u32> = text
        .split_whitespace()
        .map(|pid| pid.parse().expect("a pid"))
        .collect();
    [pids[0], pids[1]]
}

fn running(pids: &[u32; 2]) -> Vec<u32> {
    pids.iter()
        .copied()
        .filter(|pid| kin_daemon_spawn::process_is_alive(*pid))
        .collect()
}

/// Kills whatever it recorded if the test ends before the processes were seen
/// gone, so a failing assertion does not leave a ten-minute `sleep` behind.
struct Leftovers([u32; 2]);

impl Leftovers {
    /// The processes are gone; there is nothing left to kill.
    fn disarm(mut self) {
        self.0 = [0, 0];
    }
}

impl Drop for Leftovers {
    fn drop(&mut self) {
        for pid in self.0 {
            // Signalled only while still running, which a recycled pid of
            // someone else's cannot be mistaken for.
            if pid > 1 && kin_daemon_spawn::process_is_alive(pid) {
                // SAFETY: `kill` takes no pointers; `pid` is a single process.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
    }
}

/// Start the fake server on `rt` and hand back everything a test needs to
/// hold it.
fn started(
    rt: &tokio::runtime::Runtime,
    root: &Path,
) -> (kin_lsp::lifecycle::LspServer, [u32; 2], Leftovers) {
    let (server, pids) = rt.block_on(start_fake_server(root));
    let leftovers = Leftovers(pids);
    assert_eq!(
        running(&pids),
        pids.to_vec(),
        "the fake server and its child must be running before anything lets go of them, \
         or their absence afterwards proves nothing"
    );
    (server, pids, leftovers)
}

fn assert_none_survive(pids: &[u32; 2], after: &str, leftovers: Leftovers) {
    let deadline = Instant::now() + SETTLE;
    let mut survivors = running(pids);
    while !survivors.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        survivors = running(pids);
    }
    assert!(
        survivors.is_empty(),
        "{:?} still running {}s after {after}; the server was {} and its child {}",
        survivors,
        SETTLE.as_secs(),
        pids[0],
        pids[1]
    );
    leftovers.disarm();
}

/// The path the enrichment worker takes on shutdown, on a supervisor halt and
/// at a sweep's end: every server it is letting go of, stopped at once.
#[test]
fn stopped_language_servers_leave_no_descendant_behind() {
    let first = tempfile::tempdir().expect("scratch root");
    let second = tempfile::tempdir().expect("scratch root");
    let rt = runtime();
    let (python, python_pids, python_leftovers) = started(&rt, first.path());
    let (typescript, typescript_pids, typescript_leftovers) = started(&rt, second.path());
    rt.block_on(stop_language_servers(
        [
            (LanguageId::Python, python),
            (LanguageId::TypeScript, typescript),
        ],
        "the test stopped them",
    ));
    assert_none_survive(
        &python_pids,
        "the daemon stopped its language servers",
        python_leftovers,
    );
    assert_none_survive(
        &typescript_pids,
        "the daemon stopped its language servers",
        typescript_leftovers,
    );
}

/// The path a readiness probe takes, and every drop of an unfinished start or a
/// cancelled worker.
#[test]
fn a_dropped_language_server_leaves_no_descendant_behind() {
    let root = tempfile::tempdir().expect("scratch root");
    let rt = runtime();
    let (server, pids, leftovers) = started(&rt, root.path());
    rt.block_on(async move { drop(server) });
    assert_none_survive(&pids, "the daemon dropped the language server", leftovers);
}

/// Kills the owner however the test ends, including on a failed assertion
/// before the kill the test itself makes.
struct Owner(std::process::Child);

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A daemon that is killed, crashes or force-exits runs no destructor. The
/// owner here is a separate process holding a started server, and SIGKILL ends
/// it without letting it run another instruction.
#[test]
fn a_daemon_that_dies_abruptly_leaves_no_language_server_behind() {
    let root = tempfile::tempdir().expect("scratch root");
    let mut owner = Owner(
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "daemon::language_server_group_test::abrupt_owner_worker",
                "--nocapture",
            ])
            .env(ABRUPT_OWNER_ROOT, root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the owner"),
    );

    let ready = root.path().join(OWNER_READY);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready.is_file() {
        assert!(
            owner.0.try_wait().expect("poll the owner").is_none(),
            "the owner exited before it held a started language server"
        );
        assert!(
            Instant::now() < deadline,
            "the owner never started its language server"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let pids = read_pids(&root.path().join(PIDS));
    let leftovers = Leftovers(pids);
    assert_eq!(
        running(&pids),
        pids.to_vec(),
        "running before the owner dies"
    );

    owner.0.kill().expect("SIGKILL the owner");
    owner.0.wait().expect("reap the owner");
    assert_none_survive(&pids, "the daemon holding the server was killed", leftovers);
}

/// The owner for the test above: inert in an ordinary run, and otherwise holds
/// a started server until it is killed.
#[test]
fn abrupt_owner_worker() {
    let Some(root) = std::env::var_os(ABRUPT_OWNER_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    runtime().block_on(async move {
        let (_server, _pids) = start_fake_server(&root).await;
        std::fs::write(root.join(OWNER_READY), b"ready").expect("mark the owner ready");
        tokio::time::sleep(OWNER_WALL_CLOCK_CAP).await;
    });
}

/// A sweep stops the servers it started and leaves the ones the incremental
/// path already had running. A released language forgets its first-open settle,
/// which belonged to the server being stopped.
#[test]
fn a_sweep_releases_the_servers_it_started_and_keeps_resident_ones() {
    use std::collections::{HashMap, HashSet};

    let mut servers = HashMap::from([
        (LanguageId::Python, "running before the sweep"),
        (LanguageId::TypeScript, "started by the sweep"),
    ]);
    let resident = HashSet::from([LanguageId::Python]);
    let mut first_open_done = HashSet::from([LanguageId::Python, LanguageId::TypeScript]);

    let released = take_servers_a_sweep_started(&mut servers, &resident, &mut first_open_done);

    assert_eq!(
        released,
        vec![(LanguageId::TypeScript, "started by the sweep")]
    );
    assert_eq!(
        servers,
        HashMap::from([(LanguageId::Python, "running before the sweep")])
    );
    assert_eq!(first_open_done, HashSet::from([LanguageId::Python]));
}

/// A server that dies mid-sweep is taken out of the pass with what it left
/// behind, and the child it started, which ignores SIGTERM, does not outlive it.
///
/// The server is killed from outside, the way the kernel ends a process that
/// cannot get memory or threads, so there is no stderr to read and the exit is
/// the only account of it.
#[test]
fn a_server_that_died_mid_sweep_is_retired_with_its_exit_and_leaves_no_descendant() {
    use std::collections::{HashMap, HashSet};

    let root = tempfile::tempdir().expect("scratch root");
    let rt = runtime();
    let (server, pids, leftovers) = started(&rt, root.path());
    let mut servers = HashMap::from([(LanguageId::Python, server)]);
    let mut first_open_done = HashSet::from([LanguageId::Python]);

    // SAFETY: `kill` takes no pointers; `pids[0]` is the server this test started.
    unsafe {
        libc::kill(pids[0] as libc::pid_t, libc::SIGKILL);
    }

    let reason = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + SETTLE;
        while !servers[&LanguageId::Python].is_disconnected() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a server whose process was killed must read as disconnected"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        retire_disconnected_server(
            &mut servers,
            &mut first_open_done,
            LanguageId::Python,
            "fake-server",
        )
        .await
    });

    let reason = reason.expect("a disconnected server is retired");
    assert!(
        reason.contains("the `fake-server` language server stopped answering"),
        "{reason}"
    );
    assert!(
        reason.contains("it was killed by signal 9"),
        "how the server ended travels with the reason: {reason}"
    );
    assert!(servers.is_empty(), "a retired server leaves the pass");
    assert!(
        first_open_done.is_empty(),
        "its first-open settle leaves with it, so a fresh server gets its own"
    );
    assert_none_survive(
        &pids,
        "the daemon retired a language server that died",
        leftovers,
    );
}

/// The control: a server that is still connected stays in the pass, with its
/// settle, and nothing is said about it.
#[test]
fn a_connected_server_is_not_retired() {
    use std::collections::{HashMap, HashSet};

    let root = tempfile::tempdir().expect("scratch root");
    let rt = runtime();
    let (server, pids, leftovers) = started(&rt, root.path());
    let mut servers = HashMap::from([(LanguageId::Python, server)]);
    let mut first_open_done = HashSet::from([LanguageId::Python]);

    let reason = rt.block_on(retire_disconnected_server(
        &mut servers,
        &mut first_open_done,
        LanguageId::Python,
        "fake-server",
    ));
    assert_eq!(reason, None);
    assert!(servers.contains_key(&LanguageId::Python));
    assert!(first_open_done.contains(&LanguageId::Python));
    let missing = rt.block_on(retire_disconnected_server(
        &mut servers,
        &mut first_open_done,
        LanguageId::Go,
        "gopls",
    ));
    assert_eq!(
        missing, None,
        "a language with no server has nothing to retire"
    );

    rt.block_on(stop_language_servers(servers, "the test stopped it"));
    assert_none_survive(&pids, "the daemon stopped its language server", leftovers);
}
