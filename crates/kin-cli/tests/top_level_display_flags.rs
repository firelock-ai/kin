// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use tempfile::TempDir;

mod common;

use common::Command;

fn nested_repository_without_own_store() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("create tempdir");
    let parent = temp.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(parent.join(".kin")).expect("create parent store marker");
    std::fs::create_dir_all(&child).expect("create nested repository");

    let output = Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(&child)
        .output()
        .expect("initialize nested repository");
    assert!(
        output.status.success(),
        "git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    (temp, child)
}

#[test]
fn top_level_help_and_version_skip_parent_store_boundary_warning() {
    let (_temp, child) = nested_repository_without_own_store();

    for flag in ["--help", "-h", "--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kin"))
            .arg(flag)
            .current_dir(&child)
            .output()
            .expect("run kin display flag");
        assert!(
            output.status.success(),
            "kin {flag} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.stdout.is_empty(),
            "kin {flag} should print its display output"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("refusing to bind the parent store"),
            "kin {flag} should not warn before display output: {stderr}"
        );
    }
}

#[test]
fn subcommand_help_still_runs_repository_boundary_check() {
    let (_temp, child) = nested_repository_without_own_store();

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["resolve", "--help"])
        .current_dir(&child)
        .output()
        .expect("run kin subcommand help");
    assert!(
        output.status.success(),
        "kin resolve --help failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to bind the parent store"),
        "non-bare help should preserve the repository boundary warning: {stderr}"
    );
}
