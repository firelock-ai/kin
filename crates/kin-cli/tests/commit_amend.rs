// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_cli::commands::log::LogReport;
use std::fs;
use std::path::Path;

mod common;

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    let output = common::Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let output = runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "kin {args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn log(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> LogReport {
    serde_json::from_slice(&kin(runtime, repo, &["log", "--json", "--count", "20"]).stdout).unwrap()
}

#[test]
fn native_amend_replaces_imported_and_native_heads_through_matching_binaries() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    git(&repo, &["init", "--initial-branch=main"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    git(&repo, &["config", "user.name", "Original Author"]);
    git(&repo, &["config", "user.email", "original@example.invalid"]);
    fs::write(repo.join("value.txt"), b"original\n").unwrap();
    git(&repo, &["add", "--all"]);
    git(&repo, &["commit", "-m", "imported message"]);
    git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("feature.txt"), b"feature contribution\n").unwrap();
    git(&repo, &["add", "--all"]);
    git(&repo, &["commit", "-m", "feature contribution"]);
    git(&repo, &["switch", "main"]);
    fs::write(repo.join("main-only.txt"), b"main contribution\n").unwrap();
    git(&repo, &["add", "--all"]);
    git(&repo, &["commit", "-m", "main contribution"]);
    git(
        &repo,
        &["merge", "--no-ff", "feature", "-m", "imported merge"],
    );
    let git_head = git(&repo, &["rev-parse", "HEAD"]).stdout;
    kin(&runtime, &repo, &["init", ".", "--json"]);
    let imported = log(&runtime, &repo);
    assert!(matches!(
        imported.start_target,
        Some(kin_model::RefTarget::ExternalObject { .. })
    ));
    let original = imported.entries[0].clone();
    assert_eq!(
        original.parents.len(),
        2,
        "the imported head must be a real divergent merge"
    );

    git(&repo, &["config", "user.name", "Current Actor"]);
    git(&repo, &["config", "user.email", "actor@example.invalid"]);
    fs::write(repo.join("value.txt"), b"amended import\n").unwrap();
    kin(
        &runtime,
        &repo,
        &["commit", "--amend", "-m", "corrected import"],
    );
    let amended_import = log(&runtime, &repo).entries[0].clone();
    assert_ne!(amended_import.change_id, original.change_id);
    assert_eq!(amended_import.parents, original.parents);
    assert_eq!(amended_import.author, original.author);
    assert_eq!(amended_import.message, "corrected import");

    fs::write(repo.join("native.txt"), b"native content\n").unwrap();
    kin(&runtime, &repo, &["commit", "-m", "native message"]);
    let native = log(&runtime, &repo).entries[0].clone();
    assert_eq!(native.parents, vec![amended_import.change_id]);
    assert_eq!(
        native.author,
        kin_model::AuthorId::new("Current Actor <actor@example.invalid>")
    );
    fs::write(repo.join("pending.bin"), [0, 255, 1]).unwrap();
    kin(&runtime, &repo, &["commit", "--amend"]);
    let amended_native = log(&runtime, &repo).entries[0].clone();
    assert_ne!(amended_native.change_id, native.change_id);
    assert_eq!(amended_native.parents, native.parents);
    assert_eq!(amended_native.message, native.message);
    assert_eq!(amended_native.author, native.author);

    kin(&runtime, &repo, &["daemon", "stop"]);
    kin(
        &runtime,
        &repo,
        &["commit", "--amend", "--message", "after reopen"],
    );
    let reopened = log(&runtime, &repo);
    assert_eq!(reopened.entries[0].parents, native.parents);
    assert_eq!(reopened.entries[0].message, "after reopen");
    assert_eq!(
        reopened.entries.len(),
        imported.entries.len() + 1,
        "replaced heads must not become extra ancestors"
    );
    assert_eq!(fs::read(repo.join("pending.bin")).unwrap(), [0, 255, 1]);
    assert_eq!(
        fs::read(repo.join("value.txt")).unwrap(),
        b"amended import\n"
    );
    assert_eq!(
        fs::read(repo.join("feature.txt")).unwrap(),
        b"feature contribution\n"
    );
    assert_eq!(
        fs::read(repo.join("main-only.txt")).unwrap(),
        b"main contribution\n"
    );
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]).stdout, git_head);
}
