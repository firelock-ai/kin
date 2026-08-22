// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin doctor --install-language-servers` says what it did (FIR-2502).
//!
//! Both stranger arms on v0.5.43 typed this flag, were told nothing, and
//! converted a large repository with no enrichment at all. Two silences caused
//! it: the flag was dead without `--fix`, and with `--fix` it declined to
//! install through branches that printed nothing. Neither is reachable from a
//! unit test, because both are about what a stranger sees on a terminal, so the
//! cheap half of that surface is driven here against the real binary.
//!
//! Nothing below needs a daemon, a network or a repository.

use serde_json::Value;
use tempfile::tempdir;

mod common;

use common::Command;

/// A `kin` invocation with its own `HOME`, so a `--fix` run repairs a temporary
/// directory rather than the machine running the suite.
fn kin_command(home: &std::path::Path, cwd: &std::path::Path) -> Command<'static> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command.env("HOME", home);
    command.current_dir(cwd);
    command
}

/// A `HOME` and a working directory that is definitely not a Kin repository.
fn scratch() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let cwd = root.path().join("elsewhere");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&cwd).expect("create cwd");
    (root, home, cwd)
}

/// Hole one, end to end. The flag used to be bound at `doctor`'s signature and
/// first read past the `--fix` early return, so this exact command printed an
/// ordinary health report and exited 0 having installed nothing.
#[test]
fn the_flag_without_fix_says_what_it_needs_instead_of_exiting_quietly() {
    let (_root, home, cwd) = scratch();

    let output = kin_command(&home, &cwd)
        .args(["doctor", "--install-language-servers"])
        .output()
        .expect("run kin doctor --install-language-servers");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        stderr.contains("Nothing installed."),
        "the no-op has to be stated. stderr={stderr} stdout={stdout}"
    );
    assert!(
        stderr.contains("only runs under `--fix`"),
        "the reason has to name the missing flag. stderr={stderr}"
    );
    assert!(
        stderr.contains("kin doctor --fix --install-language-servers"),
        "the refusal has to name the command that works. stderr={stderr}"
    );
}

/// A plain `kin doctor` must not gain a line about a repair nobody asked for.
/// Without this, the fix for a silent no-op becomes noise on every run, and the
/// assertion above could pass on a message that always prints.
#[test]
fn a_doctor_run_that_did_not_ask_says_nothing_about_language_servers() {
    let (_root, home, cwd) = scratch();

    let output = kin_command(&home, &cwd)
        .args(["doctor"])
        .output()
        .expect("run kin doctor");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !stderr.contains("Nothing installed."),
        "a run that never asked was told anyway. stderr={stderr}"
    );
    assert!(
        !stderr.contains("--install-language-servers"),
        "a run that never asked was told anyway. stderr={stderr}"
    );
}

/// The notice is a diagnostic, not part of the report. `kin doctor --json`
/// promises parseable stdout, so a fix for one silent failure must not become
/// the cause of an unparseable one.
#[test]
fn the_notice_leaves_json_stdout_parseable() {
    let (_root, home, cwd) = scratch();

    let output = kin_command(&home, &cwd)
        .args(["doctor", "--install-language-servers", "--json"])
        .output()
        .expect("run kin doctor --install-language-servers --json");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("doctor --json stdout must parse: {e}. stdout={stdout}"));
    assert!(
        report["checks"].is_array(),
        "the report is still the report. stdout={stdout}"
    );
    assert!(
        stderr.contains("only runs under `--fix`"),
        "the notice still has to reach the operator. stderr={stderr}"
    );
}

/// Hole two, the half a stranger can reach without building a scratch repo.
/// Outside a repository the coverage row reads `Unsupported`, the gate stays
/// shut, and this command used to download nothing and print not one word.
#[test]
fn outside_a_repository_the_fix_run_says_where_to_run_it_instead() {
    let (_root, home, cwd) = scratch();

    let output = kin_command(&home, &cwd)
        .args(["doctor", "--fix", "--install-language-servers"])
        .output()
        .expect("run kin doctor --fix --install-language-servers");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        stderr.contains("not inside a Kin repository"),
        "the reader has to be told which state they are in. stderr={stderr} stdout={stdout}"
    );
    // The scoping nuance the stranger had to reverse-engineer with a scratch
    // repository: the servers install per host, the gap is measured per repo.
    assert!(
        stderr.contains("per repository") && stderr.contains("per host"),
        "both scopes have to be named or the reader guesses. stderr={stderr}"
    );
    assert!(
        stderr.contains("rust, python, typescript, javascript"),
        "it has to name what it would have checked. stderr={stderr}"
    );
}
