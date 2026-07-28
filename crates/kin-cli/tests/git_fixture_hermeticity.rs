// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tempfile::tempdir;

mod common;

use common::Command;

#[test]
fn integration_git_fixtures_ignore_command_scope_config() {
    let temp = tempdir().unwrap();
    let output = Command::new("git")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "hostile-command-scope-hooks")
        .env("GIT_CONFIG_PARAMETERS", "malformed hostile fixture config")
        .args(["config", "--get", "core.hooksPath"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "isolated Git should report a missing value: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn integration_git_fixtures_ignore_global_hooks() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let hooks = temp.path().join("hooks");
    let repository = temp.path().join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("[core]\n\thooksPath = {}\n", hooks.display()),
    )
    .unwrap();
    let pre_commit = hooks.join("pre-commit");
    std::fs::write(&pre_commit, b"#!/bin/sh\nexit 91\n").unwrap();
    let mut permissions = std::fs::metadata(&pre_commit).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&pre_commit, permissions).unwrap();

    let run = |args: &[&str]| {
        let output = Command::new("git")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .args(args)
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["init", "--initial-branch=main"]);
    run(&["config", "user.email", "kin@example.invalid"]);
    run(&["config", "user.name", "Kin Test"]);
    std::fs::write(repository.join("README.md"), b"fixture\n").unwrap();
    run(&["add", "README.md"]);
    run(&["commit", "-m", "fixture"]);
}
