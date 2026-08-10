// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::collections::BTreeSet;
use tempfile::tempdir;

mod common;

use common::Command;

fn kin_command(home: &std::path::Path) -> Command<'static> {
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
    assert_eq!(report["bounded_dogfood_ready"], true);
    assert_eq!(report["bounded_dogfood_required_ready"], 12);
    assert_eq!(report["bounded_dogfood_required_total"], 12);
    assert_eq!(report["all_declared_command_surfaces_enabled"], true);
    assert_eq!(report["enabled_commands"], 33);
    assert_eq!(report["full_git_replacement_ready"], false);
    // Exact counts, so a silent re-seal cannot pass. They are also the reason
    // two lanes must never flip a gate in the same wave: both bumps merge
    // without conflict and main goes red with every pull request green.
    // Recount from the merged fixture rather than from either branch.
    assert_eq!(report["ready_commands"], 32);
    assert_eq!(report["command_total"], 33);

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
            "checkout",
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
            "ready" | "ready_bounded" => assert_eq!(exposure, "enabled"),
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
fn exposed_mutation_commands_reach_repository_discovery() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let output = kin_command(&home)
        // Checkout is exposed now, so it must fail on repository discovery rather
        // than on the capability gate. Asserting the gate message is absent keeps a
        // silent re-seal from passing as a discovery failure.
        .args(["checkout", "src/lib.rs"])
        .current_dir(root.path())
        .output()
        .expect("run exposed checkout outside a repository");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("is fail-closed on repository-v6"),
        "checkout must no longer answer from the capability gate: {stderr}"
    );
    assert!(stderr.contains("not a Kin repository"), "{stderr}");

    let output = kin_command(&home)
        .args(["rename", "before", "after"])
        .current_dir(root.path())
        .output()
        .expect("run exposed rename outside a repository");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("is fail-closed on repository-v6"),
        "rename must no longer answer from the capability gate: {stderr}"
    );
    assert!(stderr.contains("not a Kin repository"), "{stderr}");
}

/// Both transfer verbs are wired to the transfer surface, not to the gate.
///
/// The flip that exposed each one is a fixture edit, so nothing in the fixture
/// can prove the dispatch arm reaches anything. Driving the real binary is what
/// proves it: the gate message must be absent and the transfer surface's own
/// discovery failure must be present. Asserting the discovery message, and not
/// merely the absence of the gate message, is what keeps a gate that stopped
/// refusing anything at all from passing this as a connected command.
#[test]
fn push_and_pull_reach_the_transfer_surface_instead_of_the_capability_gate() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let output = kin_command(&home)
        .args(["push"])
        .current_dir(root.path())
        .output()
        .expect("run exposed push outside a repository");
    assert!(
        !output.status.success(),
        "push must fail outside a repository"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("is fail-closed on repository-v6"),
        "push must no longer answer from the capability gate: {stderr}"
    );
    assert!(
        stderr.contains("not a Kin repository"),
        "push must reach the transfer surface and fail on discovery: {stderr}"
    );

    let output = kin_command(&home)
        .args(["pull"])
        .current_dir(root.path())
        .output()
        .expect("run exposed pull outside a repository");
    assert!(
        !output.status.success(),
        "pull must fail outside a repository"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("is fail-closed on repository-v6"),
        "pull must no longer answer from the capability gate: {stderr}"
    );
    assert!(
        stderr.contains("not a Kin repository"),
        "pull must reach the transfer surface and fail on discovery: {stderr}"
    );
}

/// The session cluster is wired to the session surface, not to the gate.
///
/// Each command is driven through the real binary and must fail on repository
/// discovery. Asserting the gate message is absent is what catches a silent
/// re-seal, and asserting the discovery message is present is what catches a
/// dispatch arm that was flipped ready without being connected to anything.
#[test]
fn session_commands_reach_the_session_surface_instead_of_the_capability_gate() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    for args in [
        &["exec", "--", "true"][..],
        &["shell"][..],
        &["open", "code"][..],
        &["with", "claude"][..],
    ] {
        let output = kin_command(&home)
            .args(args)
            .current_dir(root.path())
            .output()
            .unwrap_or_else(|error| panic!("run kin {args:?}: {error}"));
        assert!(
            !output.status.success(),
            "kin {args:?} must fail outside a repository"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("is fail-closed on repository-v6"),
            "kin {args:?} must no longer answer from the capability gate: {stderr}"
        );
        assert!(
            stderr.contains("not a Kin repository"),
            "kin {args:?} must reach the session surface and fail on discovery: {stderr}"
        );
    }

    // The discontinued native-fork flags are gone rather than refused. A flag
    // clap accepts and the body then rejects is advertised in help as though it
    // works, which is what these four did: `--session` even described the
    // current default, so its page sold an opt-in for something already true.
    // Removal makes the parser the only answer, and it answers before launch.
    for args in [
        &["shell", "--restrict-discovery"][..],
        &["open", "code", "--restrict-filesystem"][..],
        &["with", "claude", "--passive-guidance"][..],
        &["with", "claude", "--session"][..],
    ] {
        let output = kin_command(&home)
            .args(args)
            .current_dir(root.path())
            .output()
            .unwrap_or_else(|error| panic!("run kin {args:?}: {error}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "kin {args:?} must exit 2 through clap, not 1 from a command body: {stderr}"
        );
        assert!(
            stderr.contains("unexpected argument"),
            "kin {args:?} must be refused by the parser: {stderr}"
        );
        assert!(
            !stderr.contains("fail-closed"),
            "kin {args:?} must no longer be advertised then refused: {stderr}"
        );
    }

    // And they are absent from the pages that used to advertise them, which is
    // the half a caller reads before typing anything.
    for (command, gone) in [
        (
            &["shell", "--help"][..],
            &["--restrict-discovery", "--restrict-filesystem"][..],
        ),
        (
            &["open", "--help"][..],
            &["--restrict-discovery", "--restrict-filesystem"][..],
        ),
        (
            &["with", "--help"][..],
            &[
                "--session",
                "--passive-guidance",
                "--restrict-discovery",
                "--restrict-filesystem",
            ][..],
        ),
    ] {
        let output = kin_command(&home)
            .args(command)
            .output()
            .unwrap_or_else(|error| panic!("run kin {command:?}: {error}"));
        let help = String::from_utf8_lossy(&output.stdout);
        for flag in gone {
            assert!(
                !help.contains(flag),
                "kin {command:?} must not advertise {flag}: {help}"
            );
        }
        // A positive control: the page still renders the flags it does carry,
        // so an empty or failed render cannot pass this as an absence.
        assert!(
            help.contains("--help"),
            "kin {command:?} must still render its options: {help}"
        );
    }

    // An unknown launcher target is refused rather than executed.
    let output = kin_command(&home)
        .args(["open", "rm"])
        .current_dir(root.path())
        .output()
        .expect("run kin open rm");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown editor"));
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
    assert!(stdout.contains("Create an exact semantic and artifact commit"));
    assert!(stdout.contains("Show exact repository-v6 artifact and semantic changes"));
    assert!(stdout.contains("Bounded graph-native rename; unsupported cases fail closed"));
}
