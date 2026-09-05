// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the graph section reads after history arrives, or a base moves, any way
//! other than a commit.
//!
//! A commit refreshes this replica's workspace base graph section, so a store
//! that has only ever committed opens without folding its base out of history.
//! Nothing else did. A fresh `kin clone` read `Graph section: absent`, and a
//! store whose base a branch switch or a merge had moved read `present but
//! refused (resolved_at)`, both naming `kin graph materialize` as the fix, so a
//! stranger who did nothing unusual paid a full history fold at every open of a
//! store they had just created. That is journey GAP-4's surviving half.
//!
//! The journey read the `resolved_at` refusal on an origin right after it
//! received a push, and that attribution is wrong: kin-remote's
//! `transfer_transaction` builds every received pack with
//! `workspace_mutation: None`, so a receive moves a ref and never the receiver's
//! own base. Measured here on `0b67c5048` at 2026-09-05T21:43Z, an origin that
//! received a push still served its own base from its own section; what folded
//! was the store whose base a branch switch had moved, which is what journey
//! step 6 did before step 7 read it, and which is also what the product's own
//! remedy for a workspace behind its ref asks a user to run.
//!
//! Every case here drives two real repository daemons through the product CLI
//! and reads the product's own `kin graph status` line, because the state under
//! test is a property of the store on disk rather than of any one process. The
//! positive control that keeps the rest honest is
//! [`a_committed_store_serves_its_workspace_base_from_a_section`]: the same
//! assertion, on the one path that already refreshed.

use std::fs;
use std::path::Path;
use std::process::Output;

use serde_json::Value;
use tempfile::tempdir;

mod common;

/// The prefix of the one `kin graph status` line this file is about.
const SECTION_PREFIX: &str = "Graph section:";

/// What the line says when an open serves the base from a persisted section.
const SERVING: &str = "present and current at";

fn require_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run isolated Kin command")
}

/// The product's own `Graph section:` line, read from `kin graph status`.
///
/// Read off stdout rather than asserted on a successful exit, because
/// `kin graph status` exits non-zero when it finds a critical graph health
/// issue and the section line is printed either way. A missing line is the one
/// thing that panics, and it panics with both streams, because a surface that
/// fell silent about the state is the defect this whole module exists to catch.
fn graph_section_line(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> String {
    let output = run(runtime, repo, &["graph", "status"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout
        .lines()
        .find(|line| line.starts_with(SECTION_PREFIX))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "kin graph status printed no `{SECTION_PREFIX}` line in {}\nstdout={stdout}\nstderr={}",
                repo.display(),
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

fn assert_serving(line: &str, what: &str) {
    assert!(
        line.contains(SERVING),
        "{what} must serve its workspace base from a persisted section, so no open of it folds \
         history: {line}"
    );
}

fn history(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    serde_json::from_slice(
        &require_success(run(runtime, repo, &["log", "--json", "--count", "1"])).stdout,
    )
    .expect("history JSON")
}

/// The change this workspace's base resolves to, as the hex the section line
/// prints.
///
/// `SemanticChangeId` wraps `Hash256`, which wraps `[u8; 32]`, and serde's
/// newtype passthrough serializes all three as an array of 32 numbers rather
/// than as a string. Its `Display` is `hex::encode`, so the hex has to be built
/// here to compare against the line the product prints; reading the field with
/// `as_str` reports every head as absent.
fn base_change(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> String {
    let report = history(runtime, repo);
    let bytes = report["start_change"].as_array().unwrap_or_else(|| {
        panic!(
            "{} reports no workspace base change: {}",
            repo.display(),
            report["start_change"]
        )
    });
    bytes
        .iter()
        .map(|byte| {
            format!(
                "{:02x}",
                byte.as_u64().expect("a change id byte is a number")
            )
        })
        .collect()
}

fn configure_author(repo: &Path) {
    let path = repo.join(".kin/config.toml");
    let mut config = kin_core::KinConfig::load_or_default(&path).unwrap();
    config.default_author =
        Some("Graph Section Transfer Test <graph-section@example.invalid>".to_string());
    config.save(&path).unwrap();
}

fn initialize_source(runtime: &common::IsolatedDaemonRuntime, source: &Path) -> (String, String) {
    fs::create_dir(source).unwrap();
    let initialized = kin_core::init_replica(source, "trunk").unwrap();
    let repository = initialized.repository_id.to_string();
    drop(initialized);
    configure_author(source);
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
    require_success(run(
        runtime,
        source,
        &["commit", "-m", "Add a native source body"],
    ));
    let port = fs::read_to_string(source.join(".kin/daemon.port")).unwrap();
    (repository, format!("http://127.0.0.1:{}", port.trim()))
}

fn clone_from(
    runtime: &common::IsolatedDaemonRuntime,
    parent: &Path,
    destination: &Path,
    source: &Path,
    endpoint: &str,
    repository: &str,
) -> Output {
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .fixture_remote_bearer_token(token.trim())
        .current_dir(parent)
        .args(["clone", endpoint, "--repository", repository])
        .arg(destination)
        .output()
        .expect("clone native repository")
}

fn transfer(
    runtime: &common::IsolatedDaemonRuntime,
    destination: &Path,
    source: &Path,
    verb: &str,
) {
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    require_success(
        runtime
            .kin_command()
            .env("KIN_DAEMON_BIN", runtime.daemon_bin())
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_EMBED_BACKEND", "cpu")
            .fixture_remote_bearer_token(token.trim())
            .current_dir(destination)
            .arg(verb)
            .output()
            .expect("transfer native repository"),
    );
}

/// One commit in a replica, so it has a head of its own to push.
fn commit_in_clone(runtime: &common::IsolatedDaemonRuntime, destination: &Path) {
    configure_author(destination);
    fs::write(
        destination.join("src/added.rs"),
        b"pub fn introduced() -> bool { true }\n",
    )
    .unwrap();
    require_success(run(
        runtime,
        destination,
        &["commit", "-m", "Publish a native artifact from the clone"],
    ));
}

/// The control that keeps every case below honest.
///
/// A store that has only committed already reads `present and current`, because
/// the commit path refreshes the section. If this ever goes red the assertion
/// itself is broken, not the transfer paths, and every other case in this file
/// is measuring nothing.
#[test]
fn a_committed_store_serves_its_workspace_base_from_a_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    initialize_source(&source_runtime, &source);
    assert_serving(
        &graph_section_line(&source_runtime, &source),
        "a store whose own commit refreshed its section",
    );
}

/// A stranger's first act on a peer's repository must not leave a store that
/// folds its whole base out of history at every open.
#[test]
fn a_fresh_clone_serves_its_workspace_base_from_a_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    assert_serving(
        &graph_section_line(&clone_runtime, &destination),
        "a fresh native clone",
    );
}

/// The section a clone leaves has to be on disk, not in the process that wrote
/// it. A daemon restart is the ordinary case: it happens more often than a
/// person commits, and a store whose acceleration does not survive one pays the
/// fold at every open exactly as if nothing had been written.
#[test]
fn a_cold_reopen_of_a_fresh_clone_still_serves_from_its_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    require_success(run(&clone_runtime, &destination, &["daemon", "stop"]));
    assert_serving(
        &graph_section_line(&clone_runtime, &destination),
        "a fresh native clone reopened by a new daemon",
    );
}

/// A pull is the other way history reaches a replica that did not author it,
/// and it lands through the daemon's receive path rather than through the
/// bootstrap a clone takes, so it is its own case.
#[test]
fn a_replica_that_pulled_serves_its_workspace_base_from_a_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 43 }\n").unwrap();
    require_success(run(
        &source_runtime,
        &source,
        &["commit", "-m", "Advance the origin past the clone"],
    ));
    let pulled = base_change(&source_runtime, &source);
    transfer(&clone_runtime, &destination, &source, "pull");
    let line = graph_section_line(&clone_runtime, &destination);
    assert_serving(&line, "a replica that pulled new history");
    assert!(
        line.contains(&pulled),
        "the section must describe the head the pull admitted ({pulled}): {line}"
    );
}

/// An origin that received a push must not be the one store in the round trip
/// that folds, and after this the section it serves must still be its OWN base.
///
/// A received transfer moves a ref and nothing else: kin-remote's
/// `transfer_transaction` builds every pack's transaction with
/// `workspace_mutation: None`, so the receiver's workspace stays where it was
/// and the section its last commit wrote still answers for it. Measured on
/// `0b67c5048` at 2026-09-05T21:43Z, this case was already green, which is why
/// it is stated as the regression guard it is rather than as a defect: a
/// post-receive refresh that wrote a section at the RECEIVED head would be
/// writing one kin-db then refuses for this workspace, turning a store that
/// serves into a store that folds.
#[test]
fn an_origin_that_received_a_push_still_serves_its_own_workspace_base() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    let origins_own_base = base_change(&source_runtime, &source);
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    commit_in_clone(&clone_runtime, &destination);
    transfer(&clone_runtime, &destination, &source, "push");
    let line = graph_section_line(&source_runtime, &source);
    assert_serving(&line, "an origin that received a push");
    assert!(
        line.contains(&origins_own_base),
        "and the section must still answer for the origin's own base \
         ({origins_own_base}), which the push did not move: {line}"
    );
}

/// The received-head test, taken at the point the head actually reaches this
/// workspace.
///
/// A push leaves the origin's working tree behind its own ref, and `kin status`
/// says so and prints `kin branch switch <ref>` as the remedy. That switch is
/// what moves this workspace onto the delivered head, and until now nothing
/// refreshed the section afterwards, so following the product's own advice
/// turned a store that served into one that folds. A section that names the
/// wrong change is refused by kin-db exactly as an absent one is, so this
/// asserts the change by name rather than only the word `present`.
#[test]
fn the_section_an_origin_serves_names_the_head_the_push_delivered() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    let before_push = base_change(&source_runtime, &source);
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    commit_in_clone(&clone_runtime, &destination);
    let delivered = base_change(&clone_runtime, &destination);
    assert_ne!(
        delivered, before_push,
        "the push must deliver a head the origin did not already hold"
    );
    transfer(&clone_runtime, &destination, &source, "push");
    require_success(run(
        &source_runtime,
        &source,
        &["branch", "switch", "trunk"],
    ));
    let line = graph_section_line(&source_runtime, &source);
    assert_serving(&line, "an origin that followed the ref a push moved");
    assert!(
        line.contains(&delivered),
        "the section must describe the head the push delivered ({delivered}): {line}"
    );
    assert!(
        !line.contains(&before_push),
        "and not the head the origin held before it ({before_push}): {line}"
    );
}

/// Truthfulness, which is the other half of never being fatal.
///
/// A clone of a repository with no history has no base to memoize, so there is
/// nothing for any refresh to write. The surface must say that, in kin-db's own
/// vocabulary, rather than report the `present and current` that a refresh
/// which reported its own intention rather than reading the store would print.
#[test]
fn a_clone_with_no_base_reports_the_state_it_is_in_rather_than_a_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    fs::create_dir(&source).unwrap();
    let initialized = kin_core::init_replica(&source, "trunk").unwrap();
    let repository = initialized.repository_id.to_string();
    drop(initialized);
    configure_author(&source);
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    require_success(run(&source_runtime, &source, &["admit"]));
    let port = fs::read_to_string(source.join(".kin/daemon.port")).unwrap();
    let endpoint = format!("http://127.0.0.1:{}", port.trim());
    require_success(clone_from(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
    ));
    let line = graph_section_line(&clone_runtime, &destination);
    assert!(
        line.contains("names no base target"),
        "a replica with no history must report that it has no base rather than claim a section: \
         {line}"
    );
    assert!(
        !line.contains(SERVING),
        "and must never claim to serve a base it does not have: {line}"
    );
}

/// The journey read the origin's `resolved_at` refusal after a received push,
/// but a received transfer carries `workspace_mutation: None`, so it moves a ref
/// and never the receiver's own base. What moves a base without committing is a
/// workspace transition, and this walks the ones journey step 6 walked: a branch
/// created, switched onto, committed on, switched away from, and merged back.
///
/// Each step names itself, so a red run says which transition left the section
/// behind rather than only that one did.
#[test]
fn every_workspace_transition_leaves_a_section_serving_the_base_it_moved_to() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let runtime = common::IsolatedDaemonRuntime::new(&source);
    initialize_source(&runtime, &source);
    assert_serving(&graph_section_line(&runtime, &source), "after the commit");

    require_success(run(&runtime, &source, &["branch", "create", "feature"]));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after `kin branch create`",
    );

    require_success(run(&runtime, &source, &["branch", "switch", "feature"]));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after `kin branch switch feature`",
    );

    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 41 }\n").unwrap();
    require_success(run(
        &runtime,
        &source,
        &["commit", "-m", "Edit the answer on a branch"],
    ));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after committing on the branch",
    );

    require_success(run(&runtime, &source, &["branch", "switch", "trunk"]));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after switching back to the default branch",
    );

    require_success(run(&runtime, &source, &["merge", "feature"]));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after merging the branch back",
    );
}
