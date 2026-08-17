// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Who `kin` says authored a change, through the real binaries.
//!
//! The defect these cover shipped in 0.5.36 and was found by a stranger running
//! Kin in a container: every change in `kin log` read `Author: unknown`, on a
//! host that had `git config --global user.name` and `user.email` set the whole
//! time. Identity resolution was two environment variable reads with a string
//! literal behind them and never consulted Git at all, and a container commonly
//! sets neither variable.
//!
//! A unit test on the resolver cannot cover that, because the resolver was not
//! the thing that was missing; the wiring was. So these drive `kin` itself and
//! read the surface the report came from.

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(repo)
        .output()
        .expect("run git")
}

fn require_git(repo: &Path, args: &[&str]) {
    let output = run_git(repo, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn require_kin_json(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Value {
    let output = require_kin(runtime, repo, args);
    serde_json::from_slice(&output.stdout).expect("kin should emit JSON")
}

/// A Git history with two commits by two different people, admitted into Kin.
///
/// Two authors rather than one on purpose: a per-commit author that is preserved
/// and a per-commit author that is overwritten by a single repository-wide value
/// look identical when every commit shares an author.
fn initialize(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);

    require_git(repo, &["config", "user.name", "Grace Hopper"]);
    require_git(repo, &["config", "user.email", "grace@example.com"]);
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 2 }\n").expect("edit source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "second commit"]);

    // Back to the first author, so the identity a native commit resolves is
    // distinguishable from the one the most recent imported commit carries.
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);

    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn log_entries(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Vec<Value> {
    let report = require_kin_json(runtime, repo, &["log", "--json", "--count", "20"]);
    assert_eq!(report["schema"], "kin.log.v1");
    report["entries"]
        .as_array()
        .expect("log reports its entries")
        .clone()
}

fn authors(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            entry["author"]
                .as_str()
                .expect("every log entry names an author")
                .to_string()
        })
        .collect()
}

/// The reported symptom, driven end to end: a commit made on a host with a Git
/// identity is attributed to that identity, in the surface the report quoted.
#[test]
fn a_native_commit_records_the_configured_git_identity() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    require_kin(&runtime, &repo, &["commit", "-m", "publish added source"]);

    let entries = log_entries(&runtime, &repo);
    let newest = entries.first().expect("the native commit");
    assert_eq!(newest["message"], "publish added source");
    assert_eq!(
        newest["author"].as_str().expect("author"),
        "Ada Lovelace <ada@example.com>",
        "a native commit must carry the identity Git resolves here"
    );
    assert!(
        !authors(&entries).iter().any(|author| author == "unknown"),
        "no change may be attributed to the placeholder: {:?}",
        authors(&entries)
    );
}

/// Importing a Git history must keep each commit's own author. A live-identity
/// resolver applied to imported history would rewrite everyone who ever
/// committed into whoever happened to run `kin init`, which is the same defect
/// as the placeholder pointed at the past instead of the present.
#[test]
fn an_imported_git_history_keeps_its_original_per_commit_authors() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    let imported = authors(&log_entries(&runtime, &repo));

    assert!(
        imported
            .iter()
            .any(|author| author.contains("Ada Lovelace")),
        "the first commit's author was lost: {imported:?}"
    );
    assert!(
        imported
            .iter()
            .any(|author| author.contains("Grace Hopper")),
        "the second commit's author was lost: {imported:?}"
    );
    assert!(
        !imported.iter().any(|author| author == "unknown"),
        "an imported change was attributed to the placeholder: {imported:?}"
    );
}

/// With nothing configured, the commit is refused rather than attributed to
/// nobody, and the refusal names the commands that fix it. The refusal happens
/// before the daemon is contacted, because a commit that cannot be attributed
/// must not reach the authority path at all.
#[test]
fn a_commit_with_no_resolvable_identity_is_refused_with_its_remedy() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    require_git(&repo, &["config", "--unset", "user.name"]);
    require_git(&repo, &["config", "--unset", "user.email"]);

    fs::write(repo.join("src/orphan.rs"), b"pub fn orphan() -> u8 { 4 }\n").expect("add source");
    let refused = run_kin(&runtime, &repo, &["commit", "-m", "nobody authored this"]);

    assert!(
        !refused.status.success(),
        "a commit with no resolvable identity must be refused: stdout={}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("git config --global user.name"),
        "the refusal must name the command that sets a name: {message}"
    );
    assert!(
        message.contains("git config --global user.email"),
        "the refusal must name the command that sets an email: {message}"
    );
    assert!(
        message.contains("default_author"),
        "the refusal must name the Kin-specific setting: {message}"
    );

    let authors = authors(&log_entries(&runtime, &repo));
    assert!(
        !authors.iter().any(|author| author == "unknown"),
        "a refused commit must publish nothing: {authors:?}"
    );
}

/// The Kin-specific setting outranks Git, so a repository can attribute its
/// changes to something other than whatever the host developer set for
/// themselves.
#[test]
fn a_kin_specific_author_outranks_the_git_identity() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    let config_path = repo.join(".kin/config.toml");
    let config = fs::read_to_string(&config_path).expect("read kin config");
    fs::write(
        &config_path,
        format!("default_author = \"Kin Author <kin@example.com>\"\n{config}"),
    )
    .expect("write kin config");

    fs::write(
        repo.join("src/preferred.rs"),
        b"pub fn preferred() -> u8 { 5 }\n",
    )
    .expect("add source");
    require_kin(
        &runtime,
        &repo,
        &["commit", "-m", "publish preferred source"],
    );

    let entries = log_entries(&runtime, &repo);
    let newest = entries.first().expect("the native commit");
    assert_eq!(newest["message"], "publish preferred source");
    assert_eq!(
        newest["author"].as_str().expect("author"),
        "Kin Author <kin@example.com>",
        "the Kin-specific setting must win over the Git identity"
    );
}
