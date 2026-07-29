// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

#[cfg(windows)]
const NULL_GIT_CONFIG: &str = "NUL";
#[cfg(not(windows))]
const NULL_GIT_CONFIG: &str = "/dev/null";

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
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

fn seed_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    fs::write(path.join("README.md"), "first\n").expect("write first revision");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "first"]);
    fs::write(path.join("README.md"), "second\n").expect("write second revision");
    fs::write(
        path.join("compose.yaml"),
        "services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "second"]);
}

fn kin_init(repo: &Path, home: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(repo)
        .args(extra)
        .env("HOME", home)
        .output()
        .expect("run kin init")
}

#[test]
fn fresh_native_init_creates_unborn_repository_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home).expect("create home");

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "fresh native init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authority: repository-v6 (graph-owned)"));
    assert!(stdout.contains("History: unborn (no synthetic commit)"));
    assert!(repo.join(".kin/manifest.json").is_file());
    assert!(!repo.join(".git").exists());
    assert!(!repo.join("AGENTS.md").exists());
}

#[test]
fn fresh_native_init_json_reports_exact_unborn_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native-json");
    fs::create_dir_all(&home).expect("create home");

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(
        output.status.success(),
        "fresh native init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("native init stdout should be JSON");
    assert_eq!(payload["schema"], "kin.init-result.v5");
    assert_eq!(payload["authority"], "repository-v6");
    assert_eq!(payload["source_boundary"], "native-unborn");
    assert_eq!(payload["history"], "unborn");
    assert_eq!(
        payload["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(payload["semantic_enrichment"]["authority_generation"], 1);
    assert_eq!(payload["semantic_enrichment"]["workspace_generation"], 0);
    assert_eq!(payload["semantic_enrichment"]["presence"], "absent");
    assert_eq!(payload["semantic_enrichment"]["entity_count"], 0);
    assert_eq!(payload["semantic_enrichment"]["relation_count"], 0);
    assert_eq!(payload["exact_reachable_git_history"], false);
    assert_eq!(payload["authority_generation"], 1);
    assert_eq!(payload["workspace_generation"], 0);
    assert!(payload["initial_change_id"].is_null());
}

#[test]
fn fresh_git_init_json_reports_exact_reachable_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("git-backed");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(
        output.status.success(),
        "fresh Git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("Git init stdout should be JSON");
    assert_eq!(payload["schema"], "kin.init-result.v5");
    assert_eq!(payload["authority"], "repository-v6");
    assert_eq!(payload["source_boundary"], "git-exact-reachable-history");
    assert_eq!(payload["history"], "exact-reachable");
    assert_eq!(
        payload["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(payload["semantic_enrichment"]["authority_generation"], 1);
    assert_eq!(payload["semantic_enrichment"]["workspace_generation"], 0);
    assert_eq!(payload["semantic_enrichment"]["presence"], "absent");
    assert_eq!(payload["semantic_enrichment"]["entity_count"], 0);
    assert!(payload["semantic_enrichment"]["semantic_change_count"]
        .as_u64()
        .is_some_and(|changes| changes >= 2));
    assert_eq!(payload["exact_reachable_git_history"], true);
    assert_eq!(payload["authority_generation"], 1);
    assert_eq!(payload["workspace_generation"], 0);
    assert!(!payload["initial_change_id"].is_null());
    assert!(repo.join(".kin/manifest.json").is_file());
    assert!(!repo.join("AGENTS.md").exists());
}

#[test]
fn init_and_status_report_the_same_admission_enrichment() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("enriched");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn helper() -> u32 {\n    7\n}\n\npub fn caller() -> u32 {\n    helper() + 1\n}\n",
    )
    .expect("write entity source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "entity source"]);

    let init = kin_init(&repo, &home, &["--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let admitted: Value = serde_json::from_slice(&init.stdout).expect("init stdout should be JSON");

    assert_eq!(admitted["semantic_enrichment"]["presence"], "present");
    assert!(
        admitted["semantic_enrichment"]["entity_count"]
            .as_u64()
            .is_some_and(|entities| entities >= 2),
        "admission enriches the supported source it imported: {}",
        admitted["semantic_enrichment"]
    );

    let status = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["status", "--json"])
        .env("HOME", &home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(&repo)
        .output()
        .expect("run kin status");
    assert!(
        status.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let reported: Value =
        serde_json::from_slice(&status.stdout).expect("status stdout should be JSON");

    assert_eq!(
        reported["semantic_enrichment"], admitted["semantic_enrichment"],
        "init and status report the same generation-bound durable authority view"
    );
}

#[test]
fn exact_git_remote_mapping_is_sealed_during_admission() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("remote-backed");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);
    run_git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/acme/repository.git",
        ],
    );

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fs::read_to_string(repo.join(".kin/config.toml")).expect("read Kin config");
    assert!(config.contains("name = \"origin\""), "{config}");
    assert!(
        config.contains("https://example.invalid/acme/repository.git"),
        "{config}"
    );
}

#[test]
fn existing_repository_is_not_rebuilt_from_the_working_tree() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home).expect("create home");

    let first = kin_init(&repo, &home, &[]);
    assert!(first.status.success());
    let manifest_before = fs::read(repo.join(".kin/manifest.json")).expect("read initial manifest");

    let second = kin_init(&repo, &home, &[]);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr)
        .contains("never rebuilds graph authority from the working tree"));
    assert_eq!(
        fs::read(repo.join(".kin/manifest.json")).expect("read unchanged manifest"),
        manifest_before
    );
}

#[test]
fn pre_release_init_flags_are_not_accepted() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    fs::create_dir_all(&home).expect("create home");

    for flag in ["--git-history", "--no-lsp", "--force", "--verbose"] {
        let repo = root.path().join(flag.trim_start_matches('-'));
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.arg("init").arg(&repo).arg(flag).env("HOME", &home);
        if flag == "--git-history" {
            command.arg("full");
        }
        let output = command.output().expect("run rejected kin init flag");
        assert!(!output.status.success(), "{flag} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!repo.join(".kin").exists());
    }
}

#[test]
fn non_git_existing_files_fail_instead_of_becoming_implicit_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("files");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    fs::write(repo.join("compose.yaml"), "services: {}\n").expect("write source");

    let output = kin_init(&repo, &home, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("will not silently ignore or derive authority"));
    assert!(!repo.join(".kin").exists());
}
