// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared subprocess isolation for daemon integration tests.

use std::process::ExitStatus;
use std::time::Duration;
use tokio::process::{Child, Command};

const DAEMON_REAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Remove all inherited Kin authority and loader injection before a scratch
/// daemon applies its intentional test environment.
///
/// Production daemon launches retain their supported environment. This helper
/// is compiled only into integration-test binaries.
pub fn isolate_daemon_test_command(command: &mut Command) {
    let explicit_authority = command
        .as_std_mut()
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_daemon_test_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_daemon_test_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command.env("KIN_VFS_DISABLE", "1");
}

fn is_daemon_test_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "KIN_")
        || env_name_eq(&label, "_KIN_VFS_LAST_DIR")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_eq(&label, "LD_PRELOAD")
        || env_name_eq(&label, "LD_AUDIT")
        || env_name_eq(&label, "LD_LIBRARY_PATH")
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

#[cfg(windows)]
#[test]
fn daemon_isolation_treats_windows_environment_names_case_insensitively() {
    for hostile in [
        "kin_registry_path",
        "_kin_vfs_last_dir",
        "Dyld_Library_Path",
        "ld_preload",
    ] {
        assert!(
            is_daemon_test_authority(std::ffi::OsStr::new(hostile)),
            "{hostile} bypassed Windows environment-name isolation"
        );
    }
}

/// Force a directly spawned test daemon down and explicitly reap it within a
/// fixed wall-clock budget.
///
/// Callers also enable Tokio's `kill_on_drop` backstop so an assertion panic
/// before this helper is reached still terminates the live child.
pub async fn terminate_daemon(child: &mut Child, label: &str) -> Result<ExitStatus, String> {
    if let Some(status) = child
        .try_wait()
        .map_err(|error| format!("poll {label} before termination: {error}"))?
    {
        return Ok(status);
    }
    child
        .start_kill()
        .map_err(|error| format!("signal {label}: {error}"))?;
    tokio::time::timeout(DAEMON_REAP_TIMEOUT, child.wait())
        .await
        .map_err(|_| format!("{label} was not reaped within {DAEMON_REAP_TIMEOUT:?}"))?
        .map_err(|error| format!("reap {label}: {error}"))
}
