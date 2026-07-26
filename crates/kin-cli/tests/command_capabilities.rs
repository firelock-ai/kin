// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::collections::BTreeSet;
use tempfile::tempdir;

mod common;

use common::Command;

fn kin_command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command.env("HOME", home);
    command
}

#[test]
fn capability_json_keeps_the_bounded_dogfood_bar_explicit() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let output = kin_command(&home)
        .args(["capabilities", "--json"])
        .output()
        .expect("run kin capabilities");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("capability stdout should be JSON");
    assert_eq!(report["schema"], "kin.git-replacement-capabilities.v1");
    assert_eq!(report["substrate"], "repository-v6");
    assert_eq!(report["git_replacement_ready"], false);
    assert_eq!(report["required_ready"], 10);
    assert_eq!(report["required_total"], 11);

    let commands = report["commands"]
        .as_array()
        .expect("commands should be an array");
    let required = commands
        .iter()
        .filter(|command| command["required_for_bounded_dogfood"] == true)
        .map(|command| {
            command["command"]
                .as_str()
                .expect("command should be a string")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required,
        BTreeSet::from([
            "branch create",
            "branch delete",
            "branch list",
            "branch switch",
            "commit",
            "diff",
            "eject",
            "git export",
            "init",
            "log",
            "status",
        ])
    );

    for command in commands {
        let status = command["status"]
            .as_str()
            .expect("status should be a string");
        let exposure = command["exposure"]
            .as_str()
            .expect("exposure should be a string");
        match status {
            "ready" => assert_eq!(exposure, "enabled"),
            "open_gate" => {
                assert_eq!(exposure, "fail_closed");
                assert!(
                    !command["acceptance_spec"]
                        .as_array()
                        .expect("acceptance spec should be an array")
                        .is_empty(),
                    "{} lost its acceptance specification",
                    command["command"]
                );
            }
            other => panic!("unexpected capability status {other}"),
        }
    }
}

#[test]
fn open_gate_commands_fail_before_repository_discovery() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let output = kin_command(&home)
        .args(["commit", "--message", "still gated"])
        .current_dir(root.path())
        .output()
        .expect("run gated commit");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`kin commit` is fail-closed on repository-v6"));
    assert!(stderr.contains("kin capabilities --json"));
}

#[test]
fn top_level_help_marks_open_git_replacement_surfaces() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let output = kin_command(&home)
        .arg("--help")
        .output()
        .expect("run kin --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("Show coherent repository-v6 workspace status"));
    assert!(stdout.contains("[OPEN GATE] Create an exact semantic and artifact commit"));
    assert!(stdout.contains("Show exact repository-v6 artifact and semantic changes"));
}
