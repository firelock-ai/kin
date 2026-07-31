// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

mod common;

use common::Command;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn unsafe_authority() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry.toml");
    let lock = root.path().join("registry.lock");
    std::fs::write(&registry, "repos = []\n").unwrap();
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    (root, registry, lock)
}

fn kin(root: &Path, registry: &Path) -> Command<'static> {
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .current_dir(root)
        .env("HOME", &home)
        .env("KIN_HOME", home.join(".kin"))
        .env("KIN_REGISTRY_PATH", registry)
        .env("PATH", "/usr/bin:/bin");
    command
}

#[test]
fn registry_authority_json_fails_closed_without_reading_or_repairing() {
    let (root, registry, lock) = unsafe_authority();
    let private_sentinel = "FIR_1481_CONTENT_MUST_NOT_ESCAPE";
    std::fs::write(
        &registry,
        format!("repos = []\nprivate = \"{private_sentinel}\"\n"),
    )
    .unwrap();
    let output = kin(root.path(), &registry)
        .args(["registry", "authority", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(private_sentinel));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(private_sentinel));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["state"] == "repairable_permissions"
            && check["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("expected 0600"))
    }));
    assert_eq!(mode(&registry), 0o644);
    assert_eq!(mode(&lock), 0o644);
}

#[test]
fn doctor_json_and_human_report_the_same_read_only_contract() {
    let (root, registry, lock) = unsafe_authority();
    let json = kin(root.path(), &registry)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "registry_authority")
        .unwrap();
    assert_eq!(check["status"], "misconfigured");
    assert_eq!(check["fixable"], true);

    let human = kin(root.path(), &registry).arg("doctor").output().unwrap();
    assert!(human.status.success());
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("Registry authority"));
    assert!(stdout.contains("expected 0600"));
    assert!(stdout.contains("kin doctor --fix"));
    assert_eq!(mode(&registry), 0o644);
    assert_eq!(mode(&lock), 0o644);
}

#[test]
fn doctor_fix_is_the_explicit_permission_only_repair() {
    let (root, registry, lock) = unsafe_authority();
    let output = kin(root.path(), &registry)
        .args(["doctor", "--fix"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(mode(&registry), 0o600);
    assert_eq!(mode(&lock), 0o600);
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("repaired registry authority permissions to 0600"));
}
