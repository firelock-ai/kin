// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin path` end to end: a real `kin init`, the daemon's `/commands/path`
//! route, and the three output shapes a caller reads (JSON, the readable
//! report, and the compact one-line-per-hop form), plus the exit code a script
//! reads when the graph holds no route.

use serial_test::serial;
use std::fs;
use tempfile::tempdir;

mod common;

use common::Command;

/// Commit everything so `kin init` sees a clean migration source.
fn commit_worktree(repo: &std::path::Path, message: &str) {
    let add = Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo)
        .output()
        .expect("git add");
    assert!(
        add.status.success(),
        "git add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let commit = Command::new("git")
        .args([
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-q",
            "-m",
            message,
        ])
        .current_dir(repo)
        .output()
        .expect("git commit");
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
}

fn kin_command(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut cmd = runtime.kin_command();
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    cmd
}

/// A three-link chain in one Rust file: `edit` calls `push`, `push` calls
/// `write`, and `orphan` calls nothing and is called by nothing.
fn seed_repository(repo: &std::path::Path) {
    fs::create_dir_all(repo.join("src")).expect("create src dir");
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn edit() {\n    push();\n}\n\npub fn push() {\n    write();\n}\n\npub fn write() {}\n\npub fn orphan() {}\n",
    )
    .expect("write source");
    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo)
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );
    commit_worktree(repo, "seed");
}

#[test]
#[serial]
fn path_answers_json_report_and_compact_and_exits_three_on_no_route() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seed_repository(repo.path());

    let init = kin_command(&runtime)
        .arg("init")
        .arg(".")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    // JSON: one document on stdout, the route in order, the envelope beside it.
    let json = kin_command(&runtime)
        .args(["path", "edit", "write", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path --json");
    assert!(
        json.status.success(),
        "kin path --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&json.stdout),
        String::from_utf8_lossy(&json.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("path --json stdout is one JSON document");
    assert_eq!(payload["found"], serde_json::json!(true), "{payload}");
    assert_eq!(
        payload["direction"],
        serde_json::json!("forward"),
        "{payload}"
    );
    let steps = payload["routes"][0]["steps"]
        .as_array()
        .expect("the first route has steps");
    let names: Vec<&str> = steps
        .iter()
        .map(|step| step["name"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(names, vec!["edit", "push", "write"], "{payload}");
    assert_eq!(
        steps[0]["relation"],
        serde_json::json!("Calls"),
        "{payload}"
    );
    assert_eq!(
        steps[0]["file"],
        serde_json::json!("src/lib.rs"),
        "{payload}"
    );
    assert_eq!(steps[0]["start_line"], serde_json::json!(1), "{payload}");
    // Whether this build's Rust extraction records a syntax site on a call edge
    // is a fact about the parser, not about the route; the contract is that an
    // empty list always says why.
    let site_lines = steps[0]["site_lines"]
        .as_array()
        .expect("site_lines is always an array");
    if site_lines.is_empty() {
        assert_eq!(
            steps[0]["site_lines_absent_reason"],
            serde_json::json!("no_evidence_span"),
            "{payload}"
        );
    } else {
        assert_eq!(site_lines, &vec![serde_json::json!(2)], "{payload}");
        assert!(steps[0]["site_lines_absent_reason"].is_null(), "{payload}");
    }
    assert!(steps[2]["relation"].is_null(), "{payload}");
    assert!(
        payload.get("_kin").is_some() && payload.get("negative").is_some(),
        "the daemon annotates the answer with its envelope and negative: {payload}"
    );
    assert_eq!(
        payload["from"]["same_name_candidates"],
        serde_json::json!(1),
        "{payload}"
    );

    // Compact: a header and one line per hop, nothing else.
    let compact = kin_command(&runtime)
        .args(["path", "edit", "write", "--compact"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path --compact");
    assert!(compact.status.success());
    let stdout = String::from_utf8_lossy(&compact.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 4, "header plus one line per hop: {stdout}");
    assert!(
        lines[0].starts_with("route 1 of 1 (forward, 2 hops): edit -> write"),
        "{stdout}"
    );
    assert!(
        lines[1].trim().starts_with("edit [function] src/lib.rs:1"),
        "{stdout}"
    );
    assert!(
        lines[2].trim().starts_with("-Calls") && lines[2].contains("push [function] src/lib.rs:5"),
        "{stdout}"
    );
    assert!(
        lines[3].trim().starts_with("-Calls") && lines[3].contains("write [function] src/lib.rs:9"),
        "{stdout}"
    );

    // The readable report carries the route, the walk, both ends and the verdict.
    let report = kin_command(&runtime)
        .args(["path", "edit", "write"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path");
    assert!(report.status.success());
    let stdout = String::from_utf8_lossy(&report.stdout);
    assert!(stdout.contains("explored: forward walk"), "{stdout}");
    assert!(
        stdout.contains("from: edit [function] src/lib.rs:1"),
        "{stdout}"
    );
    assert!(stdout.contains("verdict: "), "{stdout}");

    // Pinned the wrong way round, forward holds nothing: exit 3, the gap on
    // stderr, and nothing route-shaped on stdout.
    let none = kin_command(&runtime)
        .args(["path", "write", "edit", "--direction", "forward"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path with no route");
    assert_eq!(
        none.status.code(),
        Some(3),
        "no route exits 3: stdout={} stderr={}",
        String::from_utf8_lossy(&none.stdout),
        String::from_utf8_lossy(&none.stderr)
    );
    assert!(
        none.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&none.stdout)
    );
    let stderr = String::from_utf8_lossy(&none.stderr);
    assert!(stderr.contains("no route"), "{stderr}");
    assert!(stderr.contains("frontier_exhausted"), "{stderr}");

    // Either sense finds the reverse route and says so.
    let reverse = kin_command(&runtime)
        .args(["path", "write", "edit", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path either");
    assert!(reverse.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&reverse.stdout).unwrap();
    assert_eq!(
        payload["direction"],
        serde_json::json!("reverse"),
        "{payload}"
    );

    // An end that does not resolve is an error, not a route and not a gap.
    let missing = kin_command(&runtime)
        .args(["path", "nowhere", "write"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path with a missing end");
    assert_eq!(missing.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("nowhere"), "{stderr}");

    // A disconnected pair with no depth bound in the way is a frontier gap in
    // both senses, and the JSON says so with an empty route list.
    let orphan = kin_command(&runtime)
        .args(["path", "edit", "orphan", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin path to an orphan");
    assert_eq!(orphan.status.code(), Some(3));
    let payload: serde_json::Value = serde_json::from_slice(&orphan.stdout).unwrap();
    assert_eq!(payload["found"], serde_json::json!(false), "{payload}");
    assert_eq!(payload["routes"], serde_json::json!([]), "{payload}");
    assert_eq!(
        payload["gap"]["reason"],
        serde_json::json!("frontier_exhausted"),
        "{payload}"
    );
}
