// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use tempfile::tempdir;

mod common;

use common::Command;

#[test]
fn integration_git_fixtures_ignore_global_hooks() {
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
