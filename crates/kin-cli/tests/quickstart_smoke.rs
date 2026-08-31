// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded proof of the public local quickstart against a controlled repository.
//!
//! The source lives under `tests/fixtures`, and every product read in this test
//! goes through Kin's repository-v6 authority and daemon-owned graph. No test
//! oracle reads the temporary working file after `kin init`, and background
//! embedding is off so the default suite never asks for a model or GPU.

use serial_test::serial;
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

const FIXTURE_SOURCE: &str = include_str!("fixtures/quickstart/checkout.py");
const LOCATE_QUERY: &str = "apply_quickstart_discount";
const CALLER_NAME: &str = "quickstart_checkout_total";
const SMOKE_TIMEOUT: Duration = Duration::from_secs(120);

fn remaining(deadline: Instant, label: &str) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .unwrap_or_else(|| {
            panic!("the {SMOKE_TIMEOUT:?} quickstart deadline expired before {label}")
        })
}

fn run(command: &mut Command<'_>, deadline: Instant, label: &str) -> Output {
    command
        .output_within(remaining(deadline, label))
        .unwrap_or_else(|error| panic!("run {label}: {error}"))
}

fn require_success(output: Output, label: &str) -> Output {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git(repo: &Path, args: &[&str], deadline: Instant) {
    let output = run(
        Command::new("git").args(args).current_dir(repo),
        deadline,
        &format!("git {args:?}"),
    );
    require_success(output, &format!("git {args:?}"));
}

fn kin_command<'runtime>(
    runtime: &'runtime common::IsolatedDaemonRuntime,
    daemon_bin: &Path,
) -> Command<'runtime> {
    let mut command = runtime.kin_command();
    command
        .env("KIN_DAEMON_BIN", daemon_bin)
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0");
    command
}

#[test]
#[serial]
fn public_quickstart_reads_one_fixture_from_graph_authority() {
    let started = Instant::now();
    let deadline = started + SMOKE_TIMEOUT;
    let repo = tempdir().expect("create quickstart repository");
    let repo_path = repo.path().to_path_buf();
    std::fs::write(repo.path().join("checkout.py"), FIXTURE_SOURCE)
        .expect("write the checked-in quickstart fixture");

    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    // The compatibility probe and its one-time fallback build share the same
    // deadline as the public command sequence. Harness preparation cannot sit
    // outside the smoke's claimed wall-clock cap.
    let daemon_bin = runtime.daemon_bin_before(deadline);

    git(
        repo.path(),
        &["init", "-q", "--initial-branch", "main"],
        deadline,
    );
    git(repo.path(), &["add", "checkout.py"], deadline);
    git(
        repo.path(),
        &[
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-q",
            "-m",
            "quickstart fixture",
        ],
        deadline,
    );

    let init = run(
        kin_command(&runtime, &daemon_bin)
            .args(["init", "."])
            .current_dir(repo.path()),
        deadline,
        "kin init",
    );
    require_success(init, "kin init");

    let status = require_success(
        run(
            kin_command(&runtime, &daemon_bin)
                .args(["status", "--json"])
                .current_dir(repo.path()),
            deadline,
            "kin status --json",
        ),
        "kin status --json",
    );
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status is one JSON document");
    assert_eq!(status["authority"], "repository-v6");
    assert_eq!(status["workspace"]["dirty"], false);
    assert!(
        status["semantic_enrichment"]["entity_count"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "the admitted fixture must carry both functions in durable authority: {status}"
    );

    let overview = require_success(
        run(
            kin_command(&runtime, &daemon_bin)
                .args(["overview", "--json"])
                .current_dir(repo.path()),
            deadline,
            "kin overview --json",
        ),
        "kin overview --json",
    );
    let overview: serde_json::Value =
        serde_json::from_slice(&overview.stdout).expect("overview is one JSON document");
    assert_eq!(overview["files"], 1);
    assert!(
        overview["entities"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "overview must read the fixture's graph entities: {overview}"
    );

    let locate = require_success(
        run(
            kin_command(&runtime, &daemon_bin)
                .args(["locate", LOCATE_QUERY, "--json", "--no-snippets"])
                .current_dir(repo.path()),
            deadline,
            "kin locate",
        ),
        "kin locate",
    );
    let locate: serde_json::Value =
        serde_json::from_slice(&locate.stdout).expect("locate is one JSON document");
    assert_eq!(
        locate["semantic_coverage"]["graph_bodies"],
        serde_json::json!({"source_paths": 1, "with_body": 1, "gap_paths": 0}),
        "the locate answer must account for the fixture through graph-owned source bodies: {locate}"
    );
    let hit = locate["entities"]
        .as_array()
        .and_then(|entities| {
            entities
                .iter()
                .find(|entity| entity["name"] == LOCATE_QUERY)
        })
        .unwrap_or_else(|| panic!("locate did not return the fixture entity: {locate}"));
    assert_eq!(hit["provenance"]["file"], "checkout.py");
    let entity_id = hit["entity_id"]
        .as_str()
        .expect("the graph entity hit carries its stable id");

    let refs = require_success(
        run(
            kin_command(&runtime, &daemon_bin)
                .args(["refs", entity_id])
                .current_dir(repo.path()),
            deadline,
            "kin refs",
        ),
        "kin refs",
    );
    let refs = String::from_utf8(refs.stdout).expect("refs output is utf-8");
    assert!(
        refs.contains(CALLER_NAME) && refs.contains("checkout.py"),
        "refs must report the fixture caller from graph relations: {refs}"
    );

    // The runtime owns every daemon/supervisor child. Drop it before removing
    // the repository, then require the temporary repository to disappear.
    drop(runtime);
    repo.close().expect("remove the quickstart repository");
    assert!(!repo_path.exists(), "the quickstart fixture leaked files");
    assert!(
        started.elapsed() <= SMOKE_TIMEOUT,
        "the public quickstart and its cleanup exceeded the {SMOKE_TIMEOUT:?} hard deadline"
    );
}
