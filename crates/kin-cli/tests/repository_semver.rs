// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin semver` derives API impact from repository-v6 entity change classes.
//!
//! These assertions fail if the impact stops being a function of the entities
//! repository authority owns at two explicit endpoints: if private or test
//! entities start driving the bump, if a changed declaration stops being a
//! breaking change, or if the endpoints stop being explicit.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn require_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
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

fn git_stdout(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout)
        .expect("Git text output")
        .trim()
        .to_string()
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
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin_json(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Value {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("kin should emit JSON")
}

fn changes_by_name(report: &Value) -> BTreeMap<String, &Value> {
    report["changes"]
        .as_array()
        .expect("change array")
        .iter()
        .map(|change| {
            (
                change["name"].as_str().expect("change name").to_string(),
                change,
            )
        })
        .collect()
}

/// Two commits whose Rust surface exercises every API change class at once.
fn build_repository(repo: &Path) -> (String, String) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(repo, &["config", "user.name", "Kin"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");

    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn stable() -> u8 { 1 }\n\
          pub fn resigned(value: u8) -> u8 { value }\n\
          pub fn rebodied() -> u8 { 1 }\n\
          pub fn retired() -> u8 { 1 }\n\
          fn hidden() -> u8 { 1 }\n",
    )
    .expect("write base source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "base surface"]);
    let base = git_stdout(repo, &["rev-parse", "HEAD"]);

    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn stable() -> u8 { 1 }\n\
          pub fn resigned(value: u8, extra: u8) -> u8 { value + extra }\n\
          pub fn rebodied() -> u8 { 2 }\n\
          pub fn introduced() -> u8 { 3 }\n\
          fn hidden() -> u8 { 2 }\n",
    )
    .expect("write head source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "head surface"]);
    let head = git_stdout(repo, &["rev-parse", "HEAD"]);
    (base, head)
}

#[test]
fn semver_impact_is_derived_from_published_entity_change_classes() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let (base, head) = build_repository(&repo);

    let init = run_kin(&runtime, &repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let report = require_kin_json(
        &runtime,
        &repo,
        &["semver", "--base", &base, "--head", &head, "--json"],
    );
    assert_eq!(report["schema"], "kin.semver-impact.v1");
    assert_eq!(report["authority"], "repository-v6");
    assert_eq!(report["base"]["source"], "git_object");
    assert_eq!(report["head"]["source"], "git_object");

    let changes = changes_by_name(&report);
    assert_eq!(
        changes["resigned"]["class"], "signature_changed",
        "a changed public declaration must be a breaking change"
    );
    assert_eq!(changes["resigned"]["impact"], "major");
    assert_eq!(
        changes["retired"]["class"], "removed",
        "removing published surface must be a breaking change"
    );
    assert_eq!(changes["retired"]["impact"], "major");
    assert_eq!(
        changes["introduced"]["class"], "added",
        "new published surface must be additive"
    );
    assert_eq!(changes["introduced"]["impact"], "minor");
    assert_eq!(
        changes["rebodied"]["class"], "behavior_changed",
        "a changed body behind a stable declaration must be a patch"
    );
    assert_eq!(changes["rebodied"]["impact"], "patch");

    assert!(
        !changes.contains_key("stable"),
        "an unchanged entity produced API impact: {:?}",
        changes.keys().collect::<Vec<_>>()
    );
    assert!(
        !changes.contains_key("hidden"),
        "a private entity produced API impact: {:?}",
        changes.keys().collect::<Vec<_>>()
    );

    // The endpoint sizes are the published surface the impact was classified
    // over. Both endpoints carry a private function and the file container on
    // top of it, so reporting the endpoint's total entity count here would
    // describe a different population than the one the changes came from.
    assert_eq!(
        report["base_api_entities"], 4,
        "base endpoint must count only its published API surface: {report}"
    );
    assert_eq!(
        report["head_api_entities"], 4,
        "head endpoint must count only its published API surface: {report}"
    );
    assert!(
        report["base_api_entities"].as_u64().expect("base count")
            < report["base"]["entity_count"]
                .as_u64()
                .expect("base entity count"),
        "the published surface must be narrower than every entity at the endpoint: {report}"
    );
    assert!(
        report["head_api_entities"].as_u64().expect("head count")
            < report["head"]["entity_count"]
                .as_u64()
                .expect("head entity count"),
        "the published surface must be narrower than every entity at the endpoint: {report}"
    );

    assert_eq!(
        report["impact"], "major",
        "the overall bump must be the strongest change class present"
    );
    assert_eq!(report["summary"]["major"], 2);
    assert_eq!(report["summary"]["minor"], 1);
    assert_eq!(report["summary"]["patch"], 1);

    // The same endpoints in the same order always derive the same answer: the
    // impact is a function of graph state, not of when it was asked.
    let repeated = require_kin_json(
        &runtime,
        &repo,
        &["semver", "--base", &base, "--head", &head, "--json"],
    );
    assert_eq!(repeated, report, "semver impact is not deterministic");
}

#[test]
fn semver_reports_no_impact_between_identical_endpoints() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let (_, head) = build_repository(&repo);

    let init = run_kin(&runtime, &repo, &["init", ".", "--json"]);
    assert!(init.status.success());

    let report = require_kin_json(
        &runtime,
        &repo,
        &["semver", "--base", &head, "--head", &head, "--json"],
    );
    assert_eq!(report["impact"], "none");
    assert_eq!(report["summary"]["major"], 0);
    assert_eq!(report["summary"]["minor"], 0);
    assert_eq!(report["summary"]["patch"], 0);
    assert!(report["changes"].as_array().expect("changes").is_empty());
}

#[test]
fn semver_requires_an_explicit_base_endpoint() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    build_repository(&repo);
    let init = run_kin(&runtime, &repo, &["init", ".", "--json"]);
    assert!(init.status.success());

    let output = run_kin(&runtime, &repo, &["semver"]);
    assert!(
        !output.status.success(),
        "semver derived an impact without an explicit base endpoint"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--base"),
        "the refusal must name the missing explicit endpoint: {stderr}"
    );

    let unknown = run_kin(
        &runtime,
        &repo,
        &["semver", "--base", "refs/heads/nonexistent"],
    );
    assert!(
        !unknown.status.success(),
        "semver resolved an endpoint that repository authority does not have"
    );
}
