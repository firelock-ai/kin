// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin stash` seals and restores exact graph-owned workspace state through the
//! real `kin` and `kin-daemon` binaries.
//!
//! The in-process route tests cover the seal and restore transactions. What
//! only a real binary can cover is the surface a user reaches: that `kin stash`
//! is past its capability gate, that a seal is driven by the workspace the
//! background daemon actually admitted rather than by a hand-installed graph,
//! and that the sealed bytes come back. LSP enrichment is deliberately left
//! enabled, because the wedge that held this gate closed was an enrichment
//! write racing a repository command.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

/// How long to wait for the daemon watcher to admit a host edit into workspace
/// authority. Sealing is defined over graph-owned changes, so the workspace has
/// to be dirty in authority before a seal has anything to do.
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(120);

fn require_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
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

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin(repo: &Path, home: &Path, args: &[&str]) -> String {
    let output = run_kin(repo, home, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn require_kin_json(repo: &Path, home: &Path, args: &[&str]) -> Value {
    let stdout = require_kin(repo, home, args);
    serde_json::from_str(&stdout).expect("kin should emit JSON")
}

const BASE_SOURCE: &[u8] = b"pub fn shipped() -> u8 { 1 }\n";
const SEALED_SOURCE: &[u8] = b"pub fn shipped() -> u8 { 2 }\npub fn added() -> u8 { 3 }\n";
const SEALED_OPAQUE: &[u8] = &[0x00, 0xfe, 0x7f, 0x41];

/// A single-commit Git history admitted into Kin.
fn initialize(repo: &Path, home: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(repo, &["config", "user.name", "Kin"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), BASE_SOURCE).expect("write source");
    fs::write(repo.join("compose.yaml"), b"services: {}\n")
        .expect("write unsupported-language file");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "base"]);

    let init = run_kin(repo, home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn workspace_dirty(repo: &Path, home: &Path) -> bool {
    require_kin_json(repo, home, &["status", "--json"])["workspace"]["dirty"]
        .as_bool()
        .expect("status reports workspace dirtiness")
}

/// Block until the daemon has admitted the working-copy edits into workspace
/// authority, or fail naming the wait rather than sealing an empty workspace.
fn await_admitted_workspace_changes(repo: &Path, home: &Path) {
    let deadline = Instant::now() + ADMISSION_TIMEOUT;
    while Instant::now() < deadline {
        if workspace_dirty(repo, home) {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "the daemon did not admit the working-copy edits into workspace authority within {:?}",
        ADMISSION_TIMEOUT
    );
}

fn stash_entries(repo: &Path, home: &Path) -> Vec<Value> {
    let report = require_kin_json(repo, home, &["stash", "list", "--json"]);
    assert_eq!(report["schema"], "kin.stash-list.v1");
    assert_eq!(report["authority"], "repository-v6");
    report["entries"]
        .as_array()
        .expect("stash list reports its entries")
        .clone()
}

#[test]
fn stash_seals_graph_owned_workspace_state_and_pop_restores_it() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize(&repo, &home);

    assert!(
        stash_entries(&repo, &home).is_empty(),
        "a fresh repository holds no sealed state"
    );

    fs::write(repo.join("src/lib.rs"), SEALED_SOURCE).expect("edit tracked source");
    fs::write(repo.join("scratch.mystery"), SEALED_OPAQUE).expect("add opaque artifact");
    await_admitted_workspace_changes(&repo, &home);

    let sealed = require_kin(
        &repo,
        &home,
        &["stash", "push", "--yes", "-m", "sealed under test"],
    );
    assert!(
        sealed.contains("refs/kin/stash/0"),
        "the seal did not name the exact ref it wrote: {sealed}"
    );

    // The workspace is back at its authority base: tracked bytes restored, and
    // an artifact the base tree never held removed rather than left behind.
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).expect("read source after seal"),
        BASE_SOURCE,
        "sealing did not return tracked bytes to the authority base"
    );
    assert!(
        !repo.join("scratch.mystery").exists(),
        "sealing left an artifact the authority base does not hold"
    );
    assert!(
        !workspace_dirty(&repo, &home),
        "the workspace still reports graph-owned changes after a seal"
    );

    let entries = stash_entries(&repo, &home);
    assert_eq!(entries.len(), 1, "the seal is not listed: {entries:?}");
    assert_eq!(entries[0]["ordinal"], 0);
    assert_eq!(entries[0]["message"], "sealed under test");

    let restored = require_kin(&repo, &home, &["stash", "pop"]);
    assert!(
        restored.contains("refs/kin/stash/0"),
        "the restore did not name the stash it consumed: {restored}"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).expect("read source after restore"),
        SEALED_SOURCE,
        "restoring did not bring the sealed bytes back"
    );
    assert_eq!(
        fs::read(repo.join("scratch.mystery")).expect("read opaque artifact after restore"),
        SEALED_OPAQUE,
        "restoring dropped an opaque artifact the seal held"
    );
    assert!(
        stash_entries(&repo, &home).is_empty(),
        "a restored stash must be dropped, not left for a second restore"
    );

    // The transition left the projection agreeing with graph truth, so the
    // commands gated on a fresh workspace still work against what it returned.
    let drift = require_kin_json(&repo, &home, &["doctor", "--drift", "--json"]);
    assert_eq!(
        drift["clean"], true,
        "the stash cycle left the projection diverged from graph truth: {drift}"
    );
}

#[test]
fn stash_answers_from_the_stash_surface_rather_than_the_capability_gate() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize(&repo, &home);

    // A clean workspace has nothing to seal. The refusal must come from the
    // stash transaction, not from the capability gate that used to answer
    // before the command was ever reached.
    let refused = run_kin(&repo, &home, &["stash", "push", "--yes"]);
    assert!(
        !refused.status.success(),
        "sealing a clean workspace published an empty stash"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("holds no graph-owned changes to seal"),
        "the refusal must come from the stash surface: {stderr}"
    );
    assert!(
        !stderr.contains("fail-closed on repository-v6"),
        "`kin stash` is still answering from the capability gate: {stderr}"
    );

    // Restoring with nothing sealed is likewise a stash refusal.
    let popped = run_kin(&repo, &home, &["stash", "pop"]);
    assert!(
        !popped.status.success(),
        "restoring without a sealed stash reported success"
    );
    let stderr = String::from_utf8_lossy(&popped.stderr);
    assert!(
        stderr.contains("holds no sealed stash to restore"),
        "the refusal must come from the stash surface: {stderr}"
    );
}
