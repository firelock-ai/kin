// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(path: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(path)
        .output()
        .expect("run git")
}

fn require_git(path: &Path, args: &[&str]) {
    let output = run_git(path, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(path: &Path, args: &[&str]) -> String {
    let output = run_git(path, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Git stdout should be UTF-8")
        .trim()
        .to_string()
}

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin_json(repo: &Path, home: &Path, args: &[&str]) -> Value {
    let output = run_kin(repo, home, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Kin stdout should be JSON")
}

fn entry_origin_oid(entry: &Value) -> String {
    assert_eq!(entry["origin"]["type"], "git_commit");
    assert_eq!(entry["origin"]["oid"]["algorithm"], "sha1");
    entry["origin"]["oid"]["bytes"]
        .as_array()
        .expect("Git object ID bytes")
        .iter()
        .map(|byte| format!("{:02x}", byte.as_u64().expect("object ID byte")))
        .collect()
}

#[cfg(unix)]
#[test]
fn log_walks_exact_merge_dag_and_ignores_git_and_checkout_drift() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    require_git(&repo, &["init", "--initial-branch=main"]);
    require_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(&repo, &["config", "user.name", "Kin"]);
    require_git(&repo, &["config", "commit.gpgsign", "false"]);

    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    fs::write(repo.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
    fs::write(repo.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42]).expect("write binary");
    fs::write(repo.join("tool"), b"#!/bin/sh\nexit 0\n").expect("write executable");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(repo.join("tool"), permissions).expect("mark executable");
    symlink("compose.yaml", repo.join("compose-link")).expect("create symlink");
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "admit exact non-code tree"]);
    let base_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    require_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n  worker:\n    image: scratch\n",
    )
    .expect("change Compose file");
    fs::write(
        repo.join("policy.unsupported"),
        b"arbitrary bytes stay authoritative\n",
    )
    .expect("write unsupported artifact");
    require_git(&repo, &["add", "--all"]);
    require_git(
        &repo,
        &["commit", "-m", "change compose and unsupported policy"],
    );
    let feature_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    require_git(&repo, &["switch", "main"]);
    fs::write(repo.join("Dockerfile"), b"FROM scratch\nLABEL lane=main\n")
        .expect("change Dockerfile");
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "change container build"]);
    let main_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    require_git(
        &repo,
        &[
            "merge",
            "--no-ff",
            "feature",
            "-m",
            "merge exact artifact histories",
        ],
    );
    let merge_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let before = require_kin_json(&repo, &home, &["log", "--json", "--count", "10"]);
    assert_eq!(before["schema"], "kin.log.v1");
    assert_eq!(before["authority"], "repository-v6");
    assert_eq!(before["authority_generation"], 1);
    assert_eq!(before["requested_count"], 10);
    assert_eq!(before["truncated"], false);
    let entries = before["entries"].as_array().expect("log entries");
    assert_eq!(entries.len(), 4);
    assert_eq!(entry_origin_oid(&entries[0]), merge_oid);
    assert_eq!(entry_origin_oid(&entries[1]), main_oid);
    assert_eq!(entry_origin_oid(&entries[2]), feature_oid);
    assert_eq!(entry_origin_oid(&entries[3]), base_oid);
    assert_eq!(entries[0]["depth"], 0);
    assert_eq!(entries[1]["depth"], 1);
    assert_eq!(entries[2]["depth"], 1);
    assert_eq!(entries[3]["depth"], 2);
    assert_eq!(
        entries[0]["parents"],
        Value::Array(vec![
            entries[1]["change_id"].clone(),
            entries[2]["change_id"].clone()
        ]),
        "merge parent order was not preserved"
    );
    assert_eq!(
        entries[1]["parents"],
        Value::Array(vec![entries[3]["change_id"].clone()])
    );
    assert_eq!(
        entries[2]["parents"],
        Value::Array(vec![entries[3]["change_id"].clone()])
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry["tree_delta_count"].as_u64().unwrap() > 0),
        "every fixture commit should carry exact non-code tree deltas"
    );

    let bounded = require_kin_json(&repo, &home, &["log", "--json", "--count", "2"]);
    assert_eq!(bounded["entries"].as_array().unwrap().len(), 2);
    assert_eq!(bounded["truncated"], true);
    let zero = require_kin_json(&repo, &home, &["log", "--json", "--count", "0"]);
    assert!(zero["entries"].as_array().unwrap().is_empty());
    assert_eq!(zero["truncated"], true);

    let human = run_kin(&repo, &home, &["log", "--count", "1"]);
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout.contains(&merge_oid));
    assert!(human_stdout.contains("merge exact artifact histories"));

    // Make both compatibility surfaces lie. The exact log must remain
    // byte-for-byte stable because its only history authority is the admitted
    // repository-v6 graph and source CAS.
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::create_dir_all(repo.join(".git/refs/heads")).expect("create misleading Git refs");
    fs::write(repo.join(".git/refs/heads/main"), b"not an object id\n")
        .expect("write fake Git history");
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("drift Compose file");
    fs::remove_file(repo.join("Dockerfile")).expect("delete Dockerfile");
    fs::remove_file(repo.join("payload.bin")).expect("delete binary");
    fs::remove_file(repo.join("compose-link")).expect("delete symlink");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(repo.join("tool"), permissions).expect("remove executable bit");
    fs::write(repo.join("unrelated.after-admission"), b"not history\n")
        .expect("add unrelated file");

    let after = require_kin_json(&repo, &home, &["log", "--json", "--count", "10"]);
    assert_eq!(
        after, before,
        "Git or checkout drift influenced immutable repository-v6 log"
    );
}

/// A detached annotated tag has no repository default ref. Admission keeps the
/// raw tag target as external Git authority while the material workspace and
/// semantic history start at its CAS-verified peeled commit.
#[test]
fn log_peels_detached_annotated_tag_only_through_admitted_cas() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    require_git(&repo, &["init", "--initial-branch=main"]);
    require_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(&repo, &["config", "user.name", "Kin"]);
    require_git(&repo, &["config", "commit.gpgsign", "false"]);
    require_git(&repo, &["config", "tag.gpgsign", "false"]);
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("write exact artifact");
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "tagged artifact"]);
    let commit_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);
    require_git(
        &repo,
        &["tag", "-a", "release-v1", "-m", "annotated release"],
    );
    let tag_oid = git_stdout(&repo, &["rev-parse", "refs/tags/release-v1"]);

    // Preserve the exact annotated tag as the detached raw HEAD target. The
    // workspace tree is materialized from its peeled commit, but log must keep
    // and resolve the tag-shaped authority target.
    fs::write(repo.join(".git/HEAD"), format!("{tag_oid}\n")).expect("detach HEAD at tag object");
    assert_eq!(
        git_stdout(&repo, &["rev-parse", "HEAD^{commit}"]),
        commit_oid
    );

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let init_payload: Value =
        serde_json::from_slice(&init.stdout).expect("detached tag init stdout should be JSON");
    assert_eq!(init_payload["schema"], "kin.init-result.v4");
    assert!(init_payload["default_ref"].is_null());
    assert_eq!(init_payload["raw_git_head"]["type"], "direct");
    assert_eq!(
        init_payload["raw_git_head"]["object"]["kind"],
        "tag",
        "raw detached tag identity was not preserved"
    );
    let before = require_kin_json(&repo, &home, &["log", "--json"]);
    assert_eq!(before["workspace_head"]["type"], "detached");
    assert_eq!(before["start_target"]["type"], "external_object");
    assert_eq!(before["start_target"]["object"]["kind"], "commit");
    let entries = before["entries"].as_array().expect("log entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entry_origin_oid(&entries[0]), commit_oid);
    assert_eq!(before["start_change"], entries[0]["change_id"]);

    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::remove_file(repo.join("compose.yaml")).expect("delete checkout artifact");
    let after = require_kin_json(&repo, &home, &["log", "--json"]);
    assert_eq!(
        after, before,
        "annotated tag resolution fell back to Git or checkout state"
    );
}
