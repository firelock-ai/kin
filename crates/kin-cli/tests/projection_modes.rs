// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin vfs status` and the projection health rows, driven as a user drives
//! them.
//!
//! The unit tests cover the probes over explicit paths. These run the real
//! binary against three machines built on disk: one with no projection at all,
//! one with a driver carrying both mount features, and one where a mode is
//! recorded and nothing is installed to run it. The third is the one that
//! matters most, because it is the shape of overclaim this surface keeps
//! producing: a health row that says nothing is missing on a machine where a
//! projection was configured and does not work.

// Unix only, and the whole file rather than test by test. Every fixture here is
// about a projection the POSIX platforms have: a shim injected through
// DYLD_INSERT_LIBRARIES or LD_PRELOAD, a mount point compared by device id, and
// a driver carrying `nfs-start` or `mount`. Windows projects through ProjFS,
// `fallback_order` there offers the shim alone, and the two mount rows these
// tests read do not exist, so they would panic rather than fail honestly.
#![cfg(unix)]

use serde_json::Value;
use tempfile::tempdir;

mod common;

use common::Command;

/// A clap help listing from a driver built with both mount features.
const FEATURED_HELP: &str = "\
Virtual filesystem daemon for Kin

Usage: kin-vfs <COMMAND>

Commands:
  start        Start the VFS daemon for a workspace
  status       Show VFS daemon status
  mount        Mount the VFS as a FUSE filesystem
  unmount      Unmount a FUSE virtual filesystem
  fuse-status  Check if FUSE is available on this system
  nfs-start    Start the NFS server and mount at ~/.kin/mnt/
  nfs-stop     Stop the NFS server and unmount
  nfs-status   Show NFS server status
  workspaces   Manage registered workspaces
  exec         Run a command with VFS file interception active

Options:
  -h, --help  Print help
";

/// The name the platform's shim library carries.
fn shim_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkin_vfs_shim.dylib"
    } else {
        "libkin_vfs_shim.so"
    }
}

/// The object-file magic a shim has to start with to be classified as valid.
fn shim_bytes() -> Vec<u8> {
    let mut bytes = if cfg!(target_os = "macos") {
        vec![0xCFu8, 0xFA, 0xED, 0xFE]
    } else {
        b"\x7fELF".to_vec()
    };
    bytes.extend_from_slice(&[0u8; 64]);
    bytes
}

/// A machine: an isolated `KIN_HOME`, an isolated `PATH`, and a working
/// directory outside any repository.
struct Host {
    _root: tempfile::TempDir,
    kin_home: std::path::PathBuf,
    bin: std::path::PathBuf,
    cwd: std::path::PathBuf,
}

impl Host {
    fn new() -> Self {
        let root = tempdir().expect("temp root");
        let kin_home = root.path().join("kin-home");
        let bin = root.path().join("bin");
        let cwd = root.path().join("work");
        for dir in [&kin_home, &bin, &cwd] {
            std::fs::create_dir_all(dir).expect("create host directory");
        }
        Self {
            _root: root,
            kin_home,
            bin,
            cwd,
        }
    }

    /// Run `kin` with nothing ambient: `~/.kin` is this host's directory and
    /// the projection driver is pinned to this host's path, whether or not a
    /// file is there.
    ///
    /// The pin is what makes these fixtures mean anything. PATH cannot be used
    /// for it: the shared fixture harness reapplies the developer's real PATH
    /// immediately before every launch, on purpose, so a `.env("PATH", ...)`
    /// here is overwritten and the machine's own `kin-vfs` answers instead.
    /// That is not hypothetical. It is what the first run of this file did, and
    /// a Homebrew driver at /opt/homebrew/bin/kin-vfs decided four assertions.
    fn kin(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command
            .env("KIN_HOME", &self.kin_home)
            .env("HOME", &self.kin_home)
            .env("KIN_VFS_BIN", self.bin.join("kin-vfs"))
            .current_dir(&self.cwd)
            .args(args);
        command.output().expect("run kin")
    }

    /// Install an executable stand-in for the projection driver on this host's
    /// PATH. `help` is what it prints for `--help`.
    fn install_driver(&self, help: &str, fuse_status: &str, nfs_status: &str) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  fuse-status) printf '%s\\n' {};;\n  nfs-status) printf '%s\\n' {};;\n  *) printf '%s' {};;\nesac\n",
            shell_quote(fuse_status),
            shell_quote(nfs_status),
            shell_quote(help)
        );
        let path = self.bin.join("kin-vfs");
        std::fs::write(&path, script).expect("write driver");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make driver executable");
    }

    fn install_shim(&self) {
        let lib = self.kin_home.join("lib");
        std::fs::create_dir_all(&lib).expect("create lib");
        std::fs::write(lib.join(shim_filename()), shim_bytes()).expect("write shim");
    }

    fn record_mode(&self, mode: &str) {
        let config = self.kin_home.join("config");
        std::fs::create_dir_all(&config).expect("create config");
        std::fs::write(
            config.join("setup.toml"),
            format!("# Generated by: kin setup\n[projection]\nmode = \"{mode}\"\n"),
        )
        .expect("write setup.toml");
    }

    /// Run `kin vfs status` from `cwd`, with the binding a shell hook would
    /// have exported into the process, and return what a user reads.
    fn vfs_status_text(
        &self,
        cwd: &std::path::Path,
        workspace: Option<&std::path::Path>,
    ) -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command
            .env("KIN_HOME", &self.kin_home)
            .env("HOME", &self.kin_home)
            .env("KIN_VFS_BIN", self.bin.join("kin-vfs"))
            .env_remove("KIN_VFS_SOCK")
            .current_dir(cwd)
            .args(["vfs", "status"]);
        match workspace {
            Some(root) => command.env("KIN_VFS_WORKSPACE", root),
            None => command.env_remove("KIN_VFS_WORKSPACE"),
        };
        let output = command.output().expect("run kin vfs status");
        assert!(
            output.status.success(),
            "kin vfs status failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn vfs_status(&self) -> Value {
        let output = self.kin(&["vfs", "status", "--json"]);
        assert!(
            output.status.success(),
            "kin vfs status failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("vfs status stdout should be JSON")
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Find one mode's row in a `kin vfs status --json` payload.
fn mode_row<'a>(report: &'a Value, mode: &str) -> &'a Value {
    report["modes"]
        .as_array()
        .expect("modes is an array")
        .iter()
        .find(|row| row["mode"] == mode)
        .unwrap_or_else(|| panic!("no {mode} row in {report}"))
}

fn evidence(report: &Value, mode: &str) -> String {
    mode_row(report, mode)["evidence"]
        .as_str()
        .expect("evidence is a string")
        .to_string()
}

/// A machine with no driver and no shim offers nothing, and says why for each
/// mode rather than reporting one blanket failure.
#[test]
fn a_host_with_no_projection_reports_every_mode_unavailable_with_a_reason() {
    let host = Host::new();
    let report = host.vfs_status();

    for mode in ["shim", "nfs", "fuse"] {
        assert_eq!(
            mode_row(&report, mode)["available"],
            Value::Bool(false),
            "{mode} must be unavailable on a bare host: {report}"
        );
    }
    assert!(
        evidence(&report, "shim").contains("no shim library at"),
        "the shim row must name the library it looked for: {}",
        evidence(&report, "shim")
    );
    for mode in ["nfs", "fuse"] {
        assert!(
            evidence(&report, mode).contains("no kin-vfs driver was found"),
            "the {mode} row must name the absent driver: {}",
            evidence(&report, mode)
        );
    }
    assert_eq!(report["recorded"], Value::Null);
    assert_eq!(report["live"]["degraded"], Value::Bool(true));
}

/// The same host, now carrying a driver built with both mount features and an
/// installed shim. Every row has to move, and the mount rows have to move for
/// the reason the driver actually gave rather than because something exists.
#[test]
fn a_featured_driver_and_an_installed_shim_change_every_row() {
    let host = Host::new();
    let bare = host.vfs_status();
    host.install_driver(
        FEATURED_HELP,
        "FUSE available: fuse-t",
        "NFS server:  stopped",
    );
    host.install_shim();
    let equipped = host.vfs_status();

    assert_eq!(
        mode_row(&equipped, "shim")["available"],
        Value::Bool(true),
        "an installed shim beside a driver that runs is available: {equipped}"
    );
    assert_eq!(
        mode_row(&equipped, "fuse")["available"],
        Value::Bool(true),
        "the driver said FUSE is available: {equipped}"
    );
    assert!(
        evidence(&equipped, "fuse").contains("FUSE available: fuse-t"),
        "the driver's own words must reach the row: {}",
        evidence(&equipped, "fuse")
    );

    // Whether an NFS mount is available depends on this host having an NFS
    // client, which a CI runner may not. What must be true either way is that
    // the driver is no longer the reason: the row moved from "does not carry
    // nfs-start" to an answer about the host.
    let nfs = evidence(&equipped, "nfs");
    assert!(
        nfs.contains("carries `nfs-start`"),
        "the nfs row must read the driver's subcommand list: {nfs}"
    );
    assert!(
        !nfs.contains("built without the nfs feature"),
        "a featured driver must not read as unfeatured: {nfs}"
    );

    for mode in ["shim", "nfs", "fuse"] {
        assert_ne!(
            evidence(&bare, mode),
            evidence(&equipped, mode),
            "the {mode} row must change when the machine changes"
        );
    }
}

/// A driver that carries neither mount feature is the one every user has today.
/// It has to be told apart from an absent driver, and it has to name the build
/// that would carry the feature.
#[test]
fn the_shipped_driver_is_told_apart_from_an_absent_one() {
    let shipped_help = "\
Virtual filesystem daemon for Kin

Usage: kin-vfs <COMMAND>

Commands:
  start   Start the VFS daemon for a workspace
  status  Show VFS daemon status
  exec    Run a command with VFS file interception active

Options:
  -h, --help  Print help
";
    let host = Host::new();
    host.install_driver(shipped_help, "", "");
    let report = host.vfs_status();

    for mode in ["nfs", "fuse"] {
        let row = mode_row(&report, mode);
        assert_eq!(row["available"], Value::Bool(false));
        let evidence = row["evidence"].as_str().unwrap();
        assert!(
            evidence.contains("was built without"),
            "the {mode} row must say the driver lacks the feature, not that it is absent: {evidence}"
        );
        assert!(
            !evidence.contains("no kin-vfs driver was found"),
            "a present driver must not read as absent: {evidence}"
        );
        assert!(
            row["remedy"]
                .as_str()
                .is_some_and(|remedy| remedy.contains("--features")),
            "the {mode} row must name the build that carries it: {row}"
        );
    }
}

/// The container case, end to end. A `kin-vfs` the loader refuses is what a
/// container, a wrong-architecture archive, or a glibc floor miss produces, and
/// it leaves no mode available, which is the same shape as a machine that
/// shipped without projection. The two must not read the same: one is fine and
/// the other is every process on the box reading raw disk.
#[test]
fn a_driver_the_loader_refuses_never_reads_as_healthy() {
    use std::os::unix::fs::PermissionsExt;

    let host = Host::new();
    let bare = host.kin(&["setup", "status", "--json"]);
    let before: Value = serde_json::from_slice(&bare.stdout).expect("health JSON");

    // 127 with a loader complaint on stderr is exactly what ld.so does when it
    // cannot satisfy a library the binary needs.
    let driver = host.bin.join("kin-vfs");
    std::fs::write(
        &driver,
        "#!/bin/sh\necho 'kin-vfs: /lib/libc.so.6: version GLIBC_2.39 not found' >&2\nexit 127\n",
    )
    .expect("write refusing driver");
    std::fs::set_permissions(&driver, std::fs::Permissions::from_mode(0o755))
        .expect("make driver executable");
    host.install_shim();

    let broken = host.kin(&["setup", "status", "--json"]);
    let after: Value = serde_json::from_slice(&broken.stdout).expect("health JSON");

    let row = |report: &Value, id: &str| -> Value {
        report["checks"]
            .as_array()
            .expect("checks is an array")
            .iter()
            .find(|check| check["id"] == id)
            .unwrap_or_else(|| panic!("no {id} row in {report}"))
            .clone()
    };

    let live = row(&after, "projection_mode");
    assert_eq!(
        live["status"], "misconfigured",
        "a projection installed and dead must fail: {live}"
    );
    assert_eq!(
        after["healthy"],
        Value::Bool(false),
        "a container whose loader strips the shim is not a healthy machine"
    );

    // The control that makes the assertion above mean something: with nothing
    // installed at all, the same absence of available modes stays a skip.
    assert_eq!(
        row(&before, "projection_mode")["status"],
        "unsupported",
        "an install that ships without projection stays skipped: {before}"
    );
    assert_ne!(
        row(&before, "projection_mode")["status"],
        live["status"],
        "the two must not produce the same row"
    );

    let nfs = evidence(&host.vfs_status(), "nfs");
    assert!(
        nfs.contains("GLIBC_2.39"),
        "the loader's own words must reach the mode rows: {nfs}"
    );
}

/// The overclaim this surface exists to remove. With a mode recorded and
/// nothing installed to run it, neither health row may report that nothing is
/// missing, and the report may not claim readiness.
#[test]
fn a_recorded_mode_with_nothing_installed_never_reads_as_healthy() {
    let host = Host::new();
    let unconfigured = host.kin(&["setup", "status", "--json"]);
    assert!(
        unconfigured.status.success(),
        "kin setup status failed: {}",
        String::from_utf8_lossy(&unconfigured.stderr)
    );
    let before: Value = serde_json::from_slice(&unconfigured.stdout).expect("health JSON");

    host.record_mode("nfs");
    let configured = host.kin(&["setup", "status", "--json"]);
    let after: Value = serde_json::from_slice(&configured.stdout).expect("health JSON");

    let row = |report: &Value, id: &str| -> Value {
        report["checks"]
            .as_array()
            .expect("checks is an array")
            .iter()
            .find(|check| check["id"] == id)
            .unwrap_or_else(|| panic!("no {id} row in {report}"))
            .clone()
    };

    // Before: the installer's sanctioned outcome, and it is allowed to say so.
    let before_install = row(&before, "vfs_projection");
    assert_eq!(before_install["status"], "unsupported");
    assert!(
        before_install["platform_note"]
            .as_str()
            .is_some_and(|note| note.contains("nothing is missing")),
        "the sanctioned row is the one that says nothing is missing: {before_install}"
    );

    // After: the same machine, one recorded mode, and that sentence is gone.
    let after_install = row(&after, "vfs_projection");
    assert_eq!(
        after_install["status"], "missing",
        "a recorded mode with nothing installed must fail: {after_install}"
    );
    let rendered = serde_json::to_string(&after_install).unwrap();
    assert!(
        !rendered.contains("nothing is missing"),
        "a configured projection must never report nothing missing: {rendered}"
    );
    assert!(
        after_install["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("nfs is recorded")),
        "the row must name the mode that was configured: {after_install}"
    );

    let after_live = row(&after, "projection_mode");
    assert_eq!(
        after_live["status"], "misconfigured",
        "the live row must fail too: {after_live}"
    );
    assert!(
        after_live["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("mode=") && detail.contains("degraded=yes")),
        "the live row must carry the probe result: {after_live}"
    );
    assert_eq!(
        after["healthy"],
        Value::Bool(false),
        "a machine with a configured, broken projection is not ready"
    );
}

/// FIR-2552 and FIR-2554, as a user reads them. A shim bound to a root that
/// does not hold this repository, or to one no daemon answers, must not report
/// a projection in force, and the report must name the root and the socket it
/// is talking about rather than a verdict alone.
#[test]
fn vfs_status_names_the_bound_root_and_refuses_to_call_an_unserved_one_in_force() {
    let host = Host::new();
    host.install_shim();
    let repo = host.cwd.join("notekeeper");
    std::fs::create_dir_all(repo.join(".kin")).expect("create repo");
    std::fs::write(
        repo.join(".kin").join("manifest.json"),
        br#"{"repo_id":"00000000-0000-4000-8000-000000000000"}"#,
    )
    .expect("write manifest");
    let elsewhere = host.cwd.join("home");
    std::fs::create_dir_all(&elsewhere).expect("create home");

    // The container's shape: the hook bound a directory that is not this
    // repository, and nothing is serving it.
    let mismatched = host.vfs_status_text(&repo, Some(&elsewhere));
    assert!(
        mismatched.contains(&format!(
            "the projection root bound here is {}",
            elsewhere.display()
        )),
        "the report must name the root it is bound to:\n{mismatched}"
    );
    assert!(
        mismatched.contains("does not contain this directory"),
        "the report must say the bound root does not hold this repository:\n{mismatched}"
    );
    assert!(
        mismatched.contains(&format!(
            "its socket is {}",
            elsewhere.join(".kin").join("vfs.sock").display()
        )) && mismatched.contains("there is no socket there"),
        "the report must name the socket it probed and what the probe found:\n{mismatched}"
    );
    assert!(
        mismatched.contains("degraded=yes"),
        "a root nothing serves is not a projection in force:\n{mismatched}"
    );

    // The control that keeps this from being a permanently pessimistic row:
    // the same command, the repository itself bound, and a listener answering
    // its socket. A socket file alone proves nothing, so the listener is real.
    let socket = repo.join(".kin").join("vfs.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind fixture socket");
    let served = host.vfs_status_text(&repo, Some(&repo));
    assert!(
        served.contains(&format!("its socket is {}", socket.display()))
            && served.contains("a daemon answered it"),
        "an answered connect must be reported as one, naming the socket:\n{served}"
    );
    for absent in [
        "does not contain this directory",
        "there is no socket there",
    ] {
        assert!(
            !served.contains(absent),
            "a bound, answered repository must not carry `{absent}`:\n{served}"
        );
    }

    // FIR-2572: shim mode declares what it cannot project, in the same block,
    // and that is a binary with no libc call to interpose rather than Node.
    assert!(
        served.contains("A binary that reaches the kernel without libc is not projected"),
        "shim mode must declare the raw-syscall gap:\n{served}"
    );
    assert!(
        !served.contains("Node is not projected"),
        "Node is projected under the shim since FIR-2572:\n{served}"
    );
}

/// FIR-2501, as a user reads it, against the real binary.
///
/// Kin's own shell hook wraps the control plane as
/// `kin() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin "$@"; }`, so `kin
/// doctor` is the one process on a correctly installed machine that is
/// guaranteed NOT to be running under the shim. The projection row measured
/// exactly that, called a correct install STALE, and printed a fix that asked
/// for a new shell the hook would strip the preload from all over again. Since
/// FIR-2547 made the readiness line require zero attention rows, that denied
/// "First-run ready" on every hook-installed machine, and both arms of the
/// v0.5.43 stranger run hit it.
///
/// This builds the machine that was failing: a valid shim, a hook file, a
/// repository bound as the projection root with a listener answering its
/// socket, and no preload in `kin`'s own environment, which is precisely what
/// the hook produces. The row must be green, and the two controls below must
/// take it off green again.
#[test]
fn a_correctly_hooked_shell_reads_the_projection_row_green() {
    let host = Host::new();
    host.install_shim();

    // The hook file. Existence is all this arm needs: the bound root below is
    // the measurement, and it is what proves the hook's activate path ran here.
    let shell_dir = host.kin_home.join("shell");
    std::fs::create_dir_all(&shell_dir).expect("create shell dir");
    std::fs::write(
        shell_dir.join("kin-vfs.bash"),
        "# kin-vfs bash integration (fixture)\n",
    )
    .expect("write hook");
    std::fs::write(
        host.kin_home.join(".bashrc"),
        "source \"$HOME/.kin/shell/kin-vfs.bash\"\n",
    )
    .expect("write rc");

    // The repository the hook would have bound, with something answering its
    // socket. A socket file outlives its daemon, so the listener is real.
    let repo = host.cwd.join("notekeeper");
    std::fs::create_dir_all(repo.join(".kin")).expect("create repo");
    std::fs::write(
        repo.join(".kin").join("manifest.json"),
        br#"{"repo_id":"00000000-0000-4000-8000-000000000000"}"#,
    )
    .expect("write manifest");
    let socket = repo.join(".kin").join("vfs.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind fixture socket");

    // `kin` as the hook runs it: the binding exported, the preload stripped.
    let doctor = |extra: &[(&str, &str)], hook_present: bool| -> Value {
        let hook = shell_dir.join("kin-vfs.bash");
        if hook_present {
            if !hook.exists() {
                std::fs::write(&hook, "# kin-vfs bash integration (fixture)\n").expect("hook");
            }
        } else {
            let _ = std::fs::remove_file(&hook);
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command
            .env("KIN_HOME", &host.kin_home)
            .env("HOME", &host.kin_home)
            .env("SHELL", "/bin/bash")
            .env("KIN_VFS_BIN", host.bin.join("kin-vfs"))
            .env("KIN_VFS_WORKSPACE", &repo)
            .env("KIN_VFS_SOCK", &socket)
            .env_remove("KIN_VFS_DISABLE")
            .env_remove("DYLD_INSERT_LIBRARIES")
            .env_remove("LD_PRELOAD")
            .current_dir(&repo)
            .args(["setup", "status", "--json"]);
        for (key, value) in extra {
            command.env(key, value);
        }
        let output = command.output().expect("run kin setup status");
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "health JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    };

    let projection_row = |report: &Value| -> Value {
        report["checks"]
            .as_array()
            .expect("checks is an array")
            .iter()
            .find(|check| check["id"] == "projection_mode")
            .unwrap_or_else(|| panic!("no projection_mode row in {report}"))
            .clone()
    };

    let green = projection_row(&doctor(&[], true));
    assert_eq!(
        green["status"], "healthy",
        "a shim injected by a live hook into everything but `kin` itself is a healthy \
         projection: {green}"
    );
    let detail = green["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("IS injected into the processes this shell starts")
            && detail.contains("correctly NOT injected into `kin` itself"),
        "the row must not claim this process is shimmed; it must say the opposite and say it is \
         correct: {detail}"
    );
    assert!(
        green["manual_fix"].is_null(),
        "a green row must not ask for a repair, least of all a new shell: {green}"
    );

    // Control one: the hook's own kill switch. It survives the `kin` wrapper
    // exactly as the binding does, and it proves nothing was injected.
    let disabled = projection_row(&doctor(&[("KIN_VFS_DISABLE", "1")], true));
    assert_ne!(
        disabled["status"], "healthy",
        "a shell with the projection switched off has no projection in force: {disabled}"
    );

    // Control two: the container. Same shim, same repository, no hook file, so
    // nothing in this shell is injected and the row is advisory again with the
    // new-shell fix that is right for that machine.
    let container = projection_row(&doctor(&[], false));
    assert_eq!(
        container["status"], "stale",
        "a shim installed with no hook to inject it is still the container case: {container}"
    );
    assert!(
        container["manual_fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("interactive shell")),
        "the container is the machine a new shell actually helps: {container}"
    );
}
