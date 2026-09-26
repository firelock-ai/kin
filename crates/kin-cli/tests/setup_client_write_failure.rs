// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin setup` fails when a client it set out to configure could not be
//! configured.
//!
//! A failed client write used to be one red line in the middle of a long run
//! while setup still exited 0, so an install that lost its Claude Code entry
//! read as a success to the person and to every script that ran it. These drive
//! the real wizard, because the defect was in what the whole run reported rather
//! than in any one config writer.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

mod common;

/// Wall-clock cap for one scripted `kin setup` run, which takes seconds.
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);

/// An isolated home whose `~/.claude.json` holds `claude_config`, and a
/// directory outside any repository to run setup from.
///
/// The file is Claude Code's own install evidence, so the client is detected
/// and setup tries to configure it on every host, whether or not Claude Code is
/// installed there.
fn fixture(claude_config: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("setup root");
    let home = root.path().join("home");
    let cwd = root.path().join("outside-repository");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&cwd).expect("create cwd");
    std::fs::write(home.join(".claude.json"), claude_config).expect("seed Claude Code config");
    (root, home, cwd)
}

fn run_agent_setup(home: &Path, cwd: &Path) -> Output {
    agent_setup_command(home, cwd)
        .output_within(SETUP_TIMEOUT)
        .expect("run kin setup --intent agent")
}

fn agent_setup_command(home: &Path, cwd: &Path) -> common::Command<'static> {
    let mut command = common::Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .args([
            "setup",
            "--no-interactive",
            "--intent",
            "agent",
            "--skip-mcp-check",
        ])
        .current_dir(cwd)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("KIN_HOME", home.join(".kin"))
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_NO_DAEMON", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .env_remove("KIN_DIR")
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_MCP_REPO");
    command
}

/// Put an inert `codex` first on the PATH `command` launches with, so Codex CLI
/// is detected on every host whether or not Codex is installed there.
///
/// Two things have to be right, and the first version of this fixture got both
/// wrong without noticing, because it passed on a host with Codex installed and
/// failed on every runner without it.
///
/// - Where the file lives. Detection asks whether the file is executable, and
///   the system temporary directory can sit on a filesystem mounted `noexec`,
///   where no file is. So it lives under Cargo's per-target scratch directory,
///   in the same tree the test binary is already executing from.
/// - How the directory reaches the child. Launch rebinds `PATH` to the host's,
///   so an explicit `PATH` never arrives, and the host's own `codex`, if it has
///   one, answered instead. [`common::Command::fixture_path_prefix`] is the
///   surface that survives the rebinding.
///
/// The returned directory has to outlive the run.
#[cfg(unix)]
fn put_inert_codex_first_on_path(
    command: &mut common::Command<'static>,
    cwd: &Path,
) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let bin = tempfile::Builder::new()
        .prefix("codex-shim-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("create the shim directory under the target tree");
    let codex = bin.path().join("codex");
    std::fs::write(&codex, b"#!/bin/sh\nexit 0\n").expect("write inert codex");
    std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755))
        .expect("make inert codex executable");
    command.fixture_path_prefix(bin.path());

    // Resolve `codex` against the exact PATH the child will launch with, the
    // way detection does, so a host's own Codex cannot pass this run for it.
    command.prepare_for_launch_for_test();
    let launched_path = command
        .configured_env_for_test(std::ffi::OsStr::new("PATH"))
        .flatten()
        .expect("launch preparation sets PATH");
    assert_eq!(
        which::which_in("codex", Some(&launched_path), cwd).ok(),
        Some(codex),
        "the launched PATH must resolve codex to the fixture's shim: {launched_path:?}"
    );
    bin
}

#[test]
fn setup_fails_and_names_a_detected_client_whose_config_it_could_not_write() {
    // Present, so Claude Code is detected, and not JSON, so Kin refuses to merge
    // its entry in rather than overwrite a file it cannot read.
    let unmergeable: &[u8] = b"{ this is not json\n";
    let (_root, home, cwd) = fixture(unmergeable);

    let output = run_agent_setup(&home, &cwd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "setup reported success though Claude Code was not configured:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("kin setup could not configure Claude Code")
            && stderr.contains("not valid JSON"),
        "the run must end naming the client and the reason:\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(home.join(".claude.json")).expect("read Claude Code config"),
        unmergeable,
        "a config Kin refused to merge into must be left exactly as it was"
    );
    // The failure is the last word, not the only one: the rest of the run
    // still happened before it.
    assert!(
        stdout.contains("=== Health checklist ==="),
        "setup stopped before finishing the rest of the run:\n{stdout}"
    );
}

/// The control for the case above. The same run with a config Kin can merge
/// into succeeds, so the failure there is the unwritable config and nothing
/// else about the fixture.
///
/// On Unix the run also carries a deferral: an inert `codex` on `PATH` makes
/// Codex CLI detected, and its entry has to name a repository that does not
/// exist yet. That is the ordinary order of a first install, so it must not
/// fail setup, and the install scripts depend on exactly that.
#[test]
fn setup_succeeds_when_the_same_client_config_can_be_written() {
    let (_root, home, cwd) = fixture(b"{}");
    let mut command = agent_setup_command(&home, &cwd);
    #[cfg(unix)]
    let _codex_shim = put_inert_codex_first_on_path(&mut command, &cwd);

    let output = command
        .output_within(SETUP_TIMEOUT)
        .expect("run kin setup --intent agent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "setup failed with a writable Claude Code config:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if cfg!(unix) {
        assert!(
            stdout.contains("Codex CLI is not configured yet"),
            "the run carried no deferral, so it proves nothing about one:\n{stdout}"
        );
    }
    let written: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.join(".claude.json")).expect("read Claude Code config"),
    )
    .expect("Claude Code config is JSON");
    assert!(
        written["mcpServers"]["kin"].is_object(),
        "setup succeeded without writing the Kin entry: {written}"
    );
}
