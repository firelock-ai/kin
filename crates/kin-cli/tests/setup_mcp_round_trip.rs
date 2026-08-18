// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin setup` proves each client's MCP entry before claiming it works
//! (FIR-1882).
//!
//! Setup used to finish at the file level: the right JSON landed in the right
//! config and setup reported the client configured. These tests drive the real
//! binary through the real wizard and read the section it prints, because the
//! defect this closes is invisible at the file level by construction. A
//! recorded launcher that cannot run leaves a config file that parses, matches
//! its ledger fingerprint, and points at nothing.

use std::path::{Path, PathBuf};
use std::time::Duration;

mod common;

/// Wall-clock cap for one scripted `kin setup` run.
///
/// Setup itself is a couple of seconds; the round trip adds one launch per
/// configured client, each bounded by the check's own budget. This is well
/// above both and far below a run that is not going to finish.
const SETUP_TIMEOUT: Duration = Duration::from_secs(240);

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
    plain: PathBuf,
}

impl Fixture {
    /// An isolated home with one initialized repository and one directory that
    /// is not a repository.
    ///
    /// `~/.claude.json` is seeded because that is Claude Code's own install
    /// evidence: without it, a runner with no AI client installed configures
    /// nothing, and a test that asserts on a client section would pass by
    /// asserting on an empty one.
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::write(home.join(".claude.json"), "{}").expect("seed Claude Code evidence");

        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).expect("create repo dir");
        let init = common::Command::new(env!("CARGO_BIN_EXE_kin"))
            .arg("init")
            .arg(&repo)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("KIN_VFS_DISABLE", "1")
            .env("KIN_NO_DAEMON", "1")
            .output_within(SETUP_TIMEOUT)
            .expect("kin init");
        assert!(
            init.status.success(),
            "kin init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );

        let plain = root.path().join("not-a-repo");
        std::fs::create_dir_all(&plain).expect("create plain dir");

        Self {
            _root: root,
            home,
            repo,
            plain,
        }
    }

    /// Run the scripted agent-intent wizard from `dir`.
    ///
    /// `KIN_NO_DAEMON` is set for the same reason the MCP stdio contract tests
    /// set it: it guarantees that nothing this test starts can spawn or find a
    /// repo daemon, so the tool call is answered by the transport under test
    /// rather than by whatever daemon happens to be running on the machine.
    fn setup(&self, dir: &Path, extra: &[&str]) -> String {
        let output = common::Command::new(env!("CARGO_BIN_EXE_kin"))
            .args(["setup", "--no-interactive", "--intent", "agent"])
            .args(extra)
            .current_dir(dir)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("KIN_HOME", self.home.join(".kin"))
            .env("KIN_VFS_DISABLE", "1")
            .env("KIN_NO_DAEMON", "1")
            .env("KIN_MCP_SCAN_ROOT", dir)
            .env("KIN_REGISTRY_PATH", self.home.join("registry.toml"))
            .env_remove("KIN_DIR")
            .env_remove("KIN_DAEMON_URL")
            .env_remove("KIN_MCP_REPO")
            .output_within(SETUP_TIMEOUT)
            .expect("kin setup");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        // The verification is reported, never fatal: the config it exercised
        // may be exactly right and the machine simply not ready.
        assert!(
            output.status.success(),
            "kin setup exited with {}; stdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
    }
}

/// The line the round-trip section printed for one client.
fn round_trip_line(stdout: &str, client: &str) -> String {
    assert!(
        stdout.contains("MCP round trip"),
        "setup printed no round-trip section:\n{stdout}"
    );
    let needle = format!("{client}: ");
    stdout
        .lines()
        .skip_while(|line| !line.contains("MCP round trip"))
        .find(|line| line.contains(&needle))
        .unwrap_or_else(|| panic!("no round-trip line for {client}:\n{stdout}"))
        .trim()
        .to_string()
}

/// The whole point: the entry setup wrote is launched, handshakes, serves its
/// tool list, and answers one real call, and what it answered is reported.
///
/// With no daemon reachable the answer is that none is serving, and that answer
/// IS the proof. It is read off the `_kin` degraded flag on a real tool result,
/// which nothing but a completed spawn, `initialize`, `tools/list` and
/// `tools/call` could have produced.
#[test]
fn setup_reports_what_the_configured_client_s_own_server_answered() {
    let fixture = Fixture::new();
    let stdout = fixture.setup(&fixture.repo, &[]);
    let line = round_trip_line(&stdout, "Claude Code");
    assert!(
        line.contains("the entry answered"),
        "the recorded entry did not complete a round trip: {line}\n\n{stdout}"
    );
    assert!(
        line.contains("kin_graph_status"),
        "the round trip must name the tool it called: {line}"
    );
    assert!(
        line.contains("no repo daemon is serving"),
        "the tool's own answer must reach the report: {line}"
    );
    assert!(
        !stdout.contains("were not shown to work"),
        "a working entry with no daemon behind it is not an unproven entry:\n{stdout}"
    );
}

/// The failure mode the ticket was filed for, end to end: a recorded launcher
/// that a version upgrade moved out from under the config.
///
/// `$KIN_HOME/bin/kin` is what a managed install owns and what setup records
/// when it exists, so a file that is present, regular and executable but is not
/// a Kin binary reproduces the brew-upgrade shape exactly. The config file it
/// produces is perfectly well formed, which is why nothing short of launching
/// it can tell.
#[test]
fn setup_refuses_to_claim_a_client_whose_recorded_launcher_cannot_run() {
    let fixture = Fixture::new();
    let bin = fixture.home.join(".kin").join("bin");
    std::fs::create_dir_all(&bin).expect("create the managed bin directory");
    let launcher = bin.join(if cfg!(windows) { "kin.exe" } else { "kin" });
    std::fs::write(&launcher, b"this is not a Kin binary\n").expect("write the broken launcher");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
            .expect("make the broken launcher executable");
    }

    let stdout = fixture.setup(&fixture.repo, &[]);
    let line = round_trip_line(&stdout, "Claude Code");
    assert!(
        line.contains("the round trip failed at"),
        "a launcher that cannot run must be reported as a failure: {line}\n\n{stdout}"
    );
    assert!(
        !line.contains("declined to answer") && !line.contains("kin_graph_status answered"),
        "nothing may be claimed for a client whose entry never answered: {line}"
    );
    assert!(
        line.contains(&launcher.to_string_lossy().into_owned()),
        "the failure must name the launcher it could not run: {line}"
    );
    assert!(
        stdout.contains("were not shown to work"),
        "setup must say the entries it wrote were not proven:\n{stdout}"
    );
}

/// A scripted install may genuinely have no repository yet. The skip is
/// printed per client, because a section that simply disappeared would read
/// exactly like a run that proved something.
#[test]
fn the_check_is_skippable_and_the_skip_is_printed() {
    let fixture = Fixture::new();
    let stdout = fixture.setup(&fixture.repo, &["--skip-mcp-check"]);
    let line = round_trip_line(&stdout, "Claude Code");
    assert!(
        line.contains("not exercised") && line.contains("--skip-mcp-check"),
        "a skipped check must name itself: {line}\n\n{stdout}"
    );
}

/// `kin mcp start` resolves its repository from the working directory, so a
/// setup run outside one has nothing for a tool call to answer about. That is
/// not a broken config, and reporting it as one would teach a stranger to
/// distrust a check that was right.
#[test]
fn a_setup_run_outside_a_repository_degrades_instead_of_reporting_a_failure() {
    let fixture = Fixture::new();
    let stdout = fixture.setup(&fixture.plain, &[]);
    let line = round_trip_line(&stdout, "Claude Code");
    assert!(
        line.contains("not exercised") && line.contains("no initialized Kin repository"),
        "a run with no repository must degrade honestly: {line}\n\n{stdout}"
    );
    assert!(
        !line.contains("failed at"),
        "a missing repository is not a broken config: {line}"
    );
}
