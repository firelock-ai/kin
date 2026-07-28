// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared subprocess isolation for daemon integration tests.

use tokio::process::Command;

/// Remove all inherited Kin authority and loader injection before a scratch
/// daemon applies its intentional test environment.
///
/// Production daemon launches retain their supported environment. This helper
/// is compiled only into integration-test binaries.
pub fn isolate_daemon_test_command(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("KIN_") {
            command.env_remove(key);
        }
    }
    for inherited in ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "_KIN_VFS_LAST_DIR"] {
        command.env_remove(inherited);
    }
    command.env("KIN_VFS_DISABLE", "1");
}
