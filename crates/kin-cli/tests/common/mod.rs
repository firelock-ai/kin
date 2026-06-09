// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

static BUILD_DAEMON: OnceLock<()> = OnceLock::new();

fn daemon_compat_ok(path: &Path) -> bool {
    let Ok(output) = Command::new(path).arg("--compat-json").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    payload["graph_snapshot_version"].as_u64()
        == Some(kin_db::GraphSnapshot::CURRENT_VERSION as u64)
}

pub fn fresh_daemon_bin() -> PathBuf {
    let kin_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"));
    let daemon_bin = kin_bin.with_file_name("kin-daemon");
    if daemon_compat_ok(&daemon_bin) {
        return daemon_bin;
    }

    BUILD_DAEMON.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.ancestors().nth(2).expect("kin workspace root");
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "kin-daemon", "--bin", "kin-daemon"])
            .current_dir(workspace_root)
            .status()
            .expect("build kin-daemon");
        assert!(status.success(), "cargo build -p kin-daemon failed");
    });

    assert!(
        daemon_compat_ok(&daemon_bin),
        "kin-daemon at {} is missing or incompatible after rebuild",
        daemon_bin.display()
    );
    daemon_bin
}
