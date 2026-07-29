// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Test-only subprocess isolation for temporary Git repositories.

use std::path::Path;
use std::process::Command;

/// Build a Git command without inheriting the developer's repository or
/// configuration authority.
///
/// In particular, fixture commits must never execute real user hooks.
/// Production Git commands intentionally do not use this helper.
pub fn fixture_git() -> Command {
    let mut command = Command::new("git");
    isolate_fixture_git(&mut command);
    command
}

/// Build an isolated Git command already bound to `repository`.
pub fn fixture_git_in(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(repository);
    isolate_fixture_git(&mut command);
    command
}

/// Remove repository, configuration, and Kin VFS authority from a fixture Git
/// command.
///
/// This function is intentionally reapplied immediately before launch by
/// wrappers that allow later `.env(...)` calls. That makes an accidental
/// command-local override fail closed too.
pub fn isolate_fixture_git(command: &mut Command) {
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");
    #[cfg(not(any(unix, windows)))]
    command.env(
        "GIT_CONFIG_GLOBAL",
        command
            .get_current_dir()
            .unwrap_or_else(|| Path::new("."))
            .join(".kin-test-global-gitconfig"),
    );

    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_fixture_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_fixture_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command.env("KIN_VFS_DISABLE", "1");
}

fn is_git_command_config(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_eq(&label, "GIT_CONFIG_COUNT")
        || env_name_starts_with(&label, "GIT_CONFIG_KEY_")
        || env_name_starts_with(&label, "GIT_CONFIG_VALUE_")
}

fn is_kin_vfs_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_VFS_")
        || env_name_eq(&label, "KIN_NO_VFS")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
}

fn is_loader_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "DYLD_")
        || env_name_eq(&label, "LD_PRELOAD")
        || env_name_eq(&label, "LD_AUDIT")
        || env_name_eq(&label, "LD_LIBRARY_PATH")
}

fn is_fixture_authority(key: &std::ffi::OsStr) -> bool {
    const GIT_REPOSITORY_AUTHORITY: &[&str] = &[
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_NAMESPACE",
        "GIT_SHALLOW_FILE",
        "GIT_GRAFT_FILE",
        "GIT_REPLACE_REF_BASE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_QUARANTINE_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
    ];

    is_git_command_config(key)
        || is_kin_vfs_authority(key)
        || is_loader_authority(key)
        || GIT_REPOSITORY_AUTHORITY
            .iter()
            .any(|expected| env_os_name_eq(key, expected))
}

fn env_os_name_eq(actual: &std::ffi::OsStr, expected: &str) -> bool {
    env_name_eq(&actual.to_string_lossy(), expected)
}

#[cfg(windows)]
fn env_name_eq(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

#[cfg(not(windows))]
fn env_name_eq(actual: &str, expected: &str) -> bool {
    actual == expected
}

#[cfg(windows)]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

#[test]
fn fixture_git_ignores_command_scope_config() {
    let temp = tempfile::tempdir().unwrap();
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "hostile-command-scope-hooks")
        .env("GIT_CONFIG_PARAMETERS", "malformed hostile fixture config");
    isolate_fixture_git(&mut command);
    let output = command
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

#[test]
fn fixture_git_removes_hostile_vfs_and_loader_authority() {
    let mut command = Command::new("git");
    command
        .env("DYLD_INSERT_LIBRARIES", "/hostile/libkin_vfs.dylib")
        .env("DYLD_LIBRARY_PATH", "/hostile/dyld")
        .env("LD_PRELOAD", "/hostile/libkin_vfs.so")
        .env("LD_AUDIT", "/hostile/libaudit.so")
        .env("LD_LIBRARY_PATH", "/hostile/ld")
        .env("KIN_VFS_WORKSPACE", "/hostile/workspace")
        .env("KIN_VFS_SOCK", "/hostile/vfs.sock")
        .env("KIN_VFS_DISABLE", "0")
        .env("GIT_CEILING_DIRECTORIES", "/hostile/ceiling")
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "0")
        .env("GIT_NAMESPACE", "hostile")
        .env("_KIN_VFS_LAST_DIR", "/hostile/workspace/src");

    isolate_fixture_git(&mut command);

    let configured = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for removed in [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "KIN_VFS_WORKSPACE",
        "KIN_VFS_SOCK",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_NAMESPACE",
        "_KIN_VFS_LAST_DIR",
    ] {
        assert_eq!(
            configured.get(removed),
            Some(&None),
            "{removed} remained in the fixture environment"
        );
    }
    assert_eq!(
        configured.get("KIN_VFS_DISABLE"),
        Some(&Some("1".to_string()))
    );
}

#[cfg(windows)]
#[test]
fn fixture_git_treats_windows_environment_names_case_insensitively() {
    for hostile in [
        "git_dir",
        "Git_Config_Count",
        "git_config_key_0",
        "git_ceiling_directories",
        "git_discovery_across_filesystem",
        "git_namespace",
        "kin_vfs_workspace",
        "Dyld_Library_Path",
        "ld_preload",
    ] {
        assert!(
            is_fixture_authority(std::ffi::OsStr::new(hostile)),
            "{hostile} bypassed Windows environment-name isolation"
        );
    }
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
