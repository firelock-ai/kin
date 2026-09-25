// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin setup` finishes configuring clients when it cannot write a shell
//! profile.
//!
//! The shell-profile step used to run first and return its first refused
//! write, so on a machine whose dotfiles are read-only, which is what Nix
//! home-manager does by linking them out of a read-only store, setup ended
//! before any AI client was configured. These drive the real wizard in an
//! isolated home, because the defect was in how the whole run was ordered and
//! what it reported, not in any one writer.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

mod common;

/// Wall-clock cap for one scripted `kin setup` run, which takes seconds.
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);

/// An isolated home that Claude Code is detected in, with a managed bin
/// directory so the PATH line is part of the plan, and a directory outside any
/// repository to run setup from.
struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("setup root");
    let home = root.path().join("home");
    let cwd = root.path().join("outside-repository");
    std::fs::create_dir_all(home.join(".kin").join("bin")).expect("create managed bin");
    std::fs::create_dir_all(&cwd).expect("create cwd");
    std::fs::write(home.join(".claude.json"), b"{}").expect("seed Claude Code config");
    Fixture {
        _root: root,
        home,
        cwd,
    }
}

fn run_agent_setup(home: &Path, cwd: &Path) -> Output {
    common::Command::new(env!("CARGO_BIN_EXE_kin"))
        .args([
            "setup",
            "--no-interactive",
            "--intent",
            "agent",
            "--skip-mcp-check",
            "--shell",
            "zsh",
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
        .env_remove("KIN_MCP_REPO")
        .output_within(SETUP_TIMEOUT)
        .expect("run kin setup --intent agent")
}

fn claude_has_kin_entry(home: &Path) -> bool {
    let written: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.join(".claude.json")).expect("read Claude Code config"),
    )
    .expect("Claude Code config is JSON");
    written["mcpServers"]["kin"].is_object()
}

/// A read-only `.zshrc`, linked the way home-manager links one out of its
/// store. The client is still configured, the refusal is named with the file
/// and the reason, the PATH line still lands in the writable `.zshenv`, and the
/// block that could not be written is printed for the person to add.
#[cfg(unix)]
#[test]
fn a_read_only_shell_profile_still_leaves_the_clients_configured() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = fixture();
    let store = fixture.home.join("store");
    std::fs::create_dir_all(&store).expect("create store");
    let managed = store.join("zshrc");
    let managed_text = "# managed by home-manager\n";
    std::fs::write(&managed, managed_text).expect("write managed zshrc");
    std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o444))
        .expect("make managed zshrc read-only");
    std::os::unix::fs::symlink(&managed, fixture.home.join(".zshrc")).expect("link .zshrc");
    if std::fs::OpenOptions::new()
        .append(true)
        .open(&managed)
        .is_ok()
    {
        eprintln!("skipped: this user can write a mode 0444 file, so no refusal exists");
        return;
    }

    let output = run_agent_setup(&fixture.home, &fixture.cwd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "a refused shell profile must not fail a run whose client was configured:\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        claude_has_kin_entry(&fixture.home),
        "Claude Code was not configured:\nstdout:\n{stdout}"
    );
    let zshrc = fixture.home.join(".zshrc");
    assert!(
        stdout.contains(&format!(
            "Shell integration was not written: failed to update {}",
            zshrc.display()
        )),
        "the refusal must name the file:\n{stdout}"
    );
    assert!(
        stdout.contains("Permission denied"),
        "the refusal must carry the reason:\n{stdout}"
    );
    let by_hand = stdout
        .find("To finish it by hand")
        .expect("the closing summary must say what to add by hand");
    let tail = &stdout[by_hand..];
    assert!(
        tail.contains(&format!("to {}:", zshrc.display())) && tail.contains("source "),
        "the missing hook line must be printed against .zshrc:\n{tail}"
    );
    assert!(
        !tail.contains(".zshenv"),
        ".zshenv was written, so it owes nothing by hand:\n{tail}"
    );
    assert_eq!(
        std::fs::read_to_string(&managed).expect("read managed zshrc"),
        managed_text,
        "a read-only profile must be left exactly as it was"
    );
    let zshenv = std::fs::read_to_string(fixture.home.join(".zshenv"))
        .expect("the writable .zshenv must still be written");
    assert!(
        zshenv.contains(".kin/bin"),
        "the PATH line must land in the file that accepted it:\n{zshenv}"
    );
    let clients = stdout
        .find("AI client MCP configuration:")
        .expect("the client section must run");
    let shell = stdout
        .find("Shell integration:")
        .expect("the shell section must run");
    assert!(
        clients < shell,
        "clients are configured before the step that can be refused:\n{stdout}"
    );
    assert!(
        stdout.contains("=== Health checklist ==="),
        "setup stopped before finishing the rest of the run:\n{stdout}"
    );
}

/// The same refusal without relying on file modes, so it runs for every user
/// including root: a directory where `.zshrc` should be cannot be read or
/// written by anyone.
#[test]
fn an_unusable_shell_profile_path_is_reported_and_setup_finishes() {
    let fixture = fixture();
    let zshrc = fixture.home.join(".zshrc");
    std::fs::create_dir_all(&zshrc).expect("put a directory at .zshrc");

    let output = run_agent_setup(&fixture.home, &fixture.cwd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "setup failed on an unusable shell profile:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        claude_has_kin_entry(&fixture.home),
        "Claude Code was not configured:\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "Shell integration was not written: failed to read {}",
            zshrc.display()
        )),
        "the refusal must name the file it could not use:\n{stdout}"
    );
    assert!(
        stdout.contains("To finish it by hand"),
        "the closing summary must say what to add by hand:\n{stdout}"
    );
    assert!(
        !stdout.contains("Open a new shell session to load the shell hook"),
        "a hook that was not written must not be announced as loadable:\n{stdout}"
    );
}
