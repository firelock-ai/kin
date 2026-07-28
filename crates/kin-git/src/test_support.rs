// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Test-only subprocess isolation for temporary Git repositories.

use std::process::Command;

/// Build a Git command without inheriting the developer's repository or
/// configuration authority.
///
/// In particular, fixture commits must never execute real user hooks.
/// Production Git commands intentionally do not use this helper.
pub(crate) fn fixture_git() -> Command {
    let mut command = Command::new("git");
    isolate_fixture_git(&mut command);
    command
}

fn isolate_fixture_git(command: &mut Command) {
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");

    for inherited in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
    ] {
        command.env_remove(inherited);
    }
    let explicit_config = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|_| key.to_os_string()))
        .filter(|key| is_git_command_config(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_git_command_config(key))
        .chain(explicit_config)
    {
        command.env_remove(key);
    }
}

fn is_git_command_config(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    label == "GIT_CONFIG_COUNT"
        || label.starts_with("GIT_CONFIG_KEY_")
        || label.starts_with("GIT_CONFIG_VALUE_")
}

#[cfg(unix)]
#[test]
fn fixture_git_ignores_global_and_inherited_config_hooks() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
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
        let mut command = Command::new("git");
        command
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.hooksPath")
            .env("GIT_CONFIG_VALUE_0", &hooks)
            .env("GIT_CONFIG_PARAMETERS", "malformed hostile fixture config");
        isolate_fixture_git(&mut command);
        let output = command
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
