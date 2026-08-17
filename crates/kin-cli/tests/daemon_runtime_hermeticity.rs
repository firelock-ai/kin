// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serial_test::serial;
use tempfile::tempdir;

mod common;

use common::Command;
use kin_core::test_env::EnvVarGuard;

struct KillAndReapChild {
    child: Child,
}

impl KillAndReapChild {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn terminate_and_reap(&mut self) -> Result<(), String> {
        let probe_error = match self.child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => None,
            Err(error) => Some(error),
        };
        let kill_error = self.child.kill().err();
        let deadline = Instant::now() + Duration::from_secs(5);
        let reap_result = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => break Err("guarded child was not reaped within 5s".to_string()),
                Err(error) => break Err(format!("reap guarded child: {error}")),
            }
        };
        if probe_error.is_none() && kill_error.is_none() && reap_result.is_ok() {
            Ok(())
        } else {
            Err(format!(
                "guarded-child cleanup failed: initial probe={probe_error:?}; \
                 kill={kill_error:?}; reap={reap_result:?}"
            ))
        }
    }
}

impl std::ops::Deref for KillAndReapChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for KillAndReapChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for KillAndReapChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .expect("run Git fixture command");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn publish_marker_atomically(marker: &Path, contents: impl AsRef<[u8]>) {
    let mut staged_name = marker.as_os_str().to_os_string();
    staged_name.push(".staged");
    let staged = PathBuf::from(staged_name);
    std::fs::write(&staged, contents).expect("write staged runtime marker");
    std::fs::rename(staged, marker).expect("publish runtime marker");
}

fn try_recorded_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.trim().parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}

fn recorded_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pid) = try_recorded_pid(path) {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "parseable pid was not published at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn process_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

const GENERIC_AUTHORITY_WORKER: &str = "KIN_TEST_GENERIC_AUTHORITY_WORKER";
const GENERIC_INTENTIONAL_OVERRIDE: &str = "KIN_TEST_GENERIC_INTENTIONAL_OVERRIDE";
const GENERIC_INTENTIONAL_GIT_DATE: &str = "KIN_TEST_GENERIC_INTENTIONAL_GIT_DATE";
const GENERIC_INTENTIONAL_DAEMON_URL: &str = "KIN_TEST_GENERIC_INTENTIONAL_DAEMON_URL";

#[test]
#[serial]
fn generic_authority_worker() {
    let Some(marker) = std::env::var_os(GENERIC_AUTHORITY_WORKER) else {
        return;
    };
    for removed in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG_COUNT",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_NAMESPACE",
        "KIN_GCS_BUCKET",
        "LD_AUDIT",
    ] {
        assert!(
            std::env::var_os(removed).is_none(),
            "{removed} reached a generic test subprocess"
        );
    }
    match std::env::var_os(GENERIC_INTENTIONAL_GIT_DATE) {
        Some(expected) => {
            for key in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
                assert_eq!(
                    std::env::var_os(key).as_deref(),
                    Some(expected.as_os_str()),
                    "{key} did not carry the explicit fixture date"
                );
            }
        }
        None => {
            for key in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
                assert!(
                    std::env::var_os(key).is_none(),
                    "generic {key} override bypassed fixture isolation"
                );
            }
        }
    }
    match std::env::var_os(GENERIC_INTENTIONAL_DAEMON_URL) {
        Some(expected) => assert_eq!(
            std::env::var_os("KIN_DAEMON_URL").as_deref(),
            Some(expected.as_os_str()),
            "typed fixture daemon URL was not preserved"
        ),
        None => assert!(
            std::env::var_os("KIN_DAEMON_URL").is_none(),
            "generic runtime-bound daemon URL override bypassed isolation"
        ),
    }
    assert_eq!(
        std::env::var(GENERIC_INTENTIONAL_OVERRIDE).as_deref(),
        Ok("preserved"),
        "an intentional test override was not preserved"
    );
    assert_eq!(
        std::env::var("KIN_VFS_DISABLE").as_deref(),
        Ok("1"),
        "generic test subprocess did not fail closed against VFS injection"
    );
    std::fs::write(marker, b"hermetic").expect("write generic authority marker");
}

#[test]
#[serial]
fn generic_command_scrubs_ambient_and_command_local_authority() {
    let root = tempdir().expect("temp root");
    let marker = root.path().join("generic-authority.marker");
    let _ambient_git = EnvVarGuard::set("GIT_DIR", std::ffi::OsStr::new("/ambient/git"));
    let _ambient_kin = EnvVarGuard::set(
        "KIN_GCS_BUCKET",
        std::ffi::OsStr::new("ambient-production-bucket"),
    );
    let _ambient_loader =
        EnvVarGuard::set("LD_AUDIT", std::ffi::OsStr::new("/ambient/libaudit.so"));

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "generic_authority_worker", "--nocapture"])
        .env(GENERIC_AUTHORITY_WORKER, &marker)
        .env(GENERIC_INTENTIONAL_OVERRIDE, "preserved")
        .env("GIT_WORK_TREE", "/command-local/worktree")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CEILING_DIRECTORIES", "/command-local/ceiling")
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "0")
        .env("GIT_NAMESPACE", "command-local")
        .env("GIT_AUTHOR_DATE", "hostile author date")
        .env("GIT_COMMITTER_DATE", "hostile committer date")
        .env("LD_AUDIT", "/command-local/libaudit.so")
        .output()
        .expect("run generic authority worker");
    assert!(
        output.status.success(),
        "generic authority worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&marker).expect("read generic authority marker"),
        b"hermetic"
    );
}

#[test]
#[serial]
fn typed_fixture_git_dates_survive_the_final_authority_scrub() {
    let root = tempdir().expect("temp root");
    let marker = root.path().join("fixture-date.marker");
    let date = "1600000000 +0000";
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "generic_authority_worker", "--nocapture"])
        .env(GENERIC_AUTHORITY_WORKER, &marker)
        .env(GENERIC_INTENTIONAL_OVERRIDE, "preserved")
        .env(GENERIC_INTENTIONAL_GIT_DATE, date)
        .fixture_git_commit_dates(date)
        .output()
        .expect("run fixture-date authority worker");
    assert!(
        output.status.success(),
        "fixture-date authority worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&marker).expect("read fixture-date marker"),
        b"hermetic"
    );
}

#[test]
#[serial]
fn typed_fixture_daemon_url_survives_while_generic_override_fails_closed() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(&repository).expect("create repository");
    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_sleeper_worker"),
            OsString::from("--nocapture"),
        ],
        Vec::new(),
        Duration::from_secs(1),
    );
    for (label, typed) in [("generic", false), ("typed", true)] {
        let marker = root.path().join(format!("{label}-daemon-url.marker"));
        let expected_url = "http://127.0.0.1:9";
        let mut command = runtime
            .process_command_for_test(std::env::current_exe().expect("current test executable"));
        command
            .args(["--exact", "generic_authority_worker", "--nocapture"])
            .env(GENERIC_AUTHORITY_WORKER, &marker)
            .env(GENERIC_INTENTIONAL_OVERRIDE, "preserved")
            .env("KIN_DAEMON_URL", "http://127.0.0.1:8");
        if typed {
            command
                .env(GENERIC_INTENTIONAL_DAEMON_URL, expected_url)
                .fixture_daemon_url(expected_url);
        }
        let output = command.output().expect("run daemon-URL authority worker");
        assert!(
            output.status.success(),
            "{label} daemon-URL authority worker failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&marker).expect("read daemon-URL authority marker"),
            b"hermetic"
        );
    }
}

#[test]
#[serial]
fn isolated_runtime_lifecycle_does_not_claim_product_control_state() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(&repository).expect("create fresh repository");
    let _git_dir = EnvVarGuard::set("GIT_DIR", std::ffi::OsStr::new("/hostile/git-dir"));
    let _git_config_count = EnvVarGuard::set("GIT_CONFIG_COUNT", std::ffi::OsStr::new("1"));
    let _git_default_hash = EnvVarGuard::set("GIT_DEFAULT_HASH", std::ffi::OsStr::new("sha256"));
    let _ld_custom = EnvVarGuard::set(
        "LD_CUSTOM_INJECTION",
        std::ffi::OsStr::new("/hostile/custom-loader"),
    );
    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_sleeper_worker"),
            OsString::from("--nocapture"),
        ],
        Vec::new(),
        Duration::from_secs(1),
    );
    assert!(
        !repository.join(".kin").exists(),
        "runtime construction claimed the product control directory"
    );

    drop(runtime);

    assert!(
        !repository.join(".kin").exists(),
        "runtime cleanup claimed the product control directory"
    );
}

/// A runtime-bound command carries the operator's background-embedding opt-out,
/// and still drops a name it does not know.
///
/// The launch binding scrubs every inherited `KIN_*` value and then replays only
/// the allowlisted overrides, so a variable missing from that list is dropped
/// with no error and no output. A test that sets the opt-out and watches the
/// child embed anyway would read that as the product ignoring an operator, which
/// is exactly how this toggle was first reported dead on the CLI spawn path. The
/// fabricated name is the control: if it survived, this assertion would be
/// measuring nothing.
#[test]
#[serial]
fn runtime_command_carries_the_background_embed_opt_out_and_still_drops_an_unknown_name() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let runtime = common::IsolatedDaemonRuntime::new(&repository);

    let mut command = runtime.kin_command();
    command
        .arg("--version")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_NOT_A_REAL_KNOB", "0");
    command.prepare_for_launch_for_test();

    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_AUTO_EMBED")),
        Some(Some(OsString::from("0"))),
        "the launch binding dropped the operator's background-embedding opt-out, so any test \
         asserting the daemon honours it would prove the opposite"
    );
    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_NOT_A_REAL_KNOB")),
        Some(None),
        "a fabricated Kin variable survived the launch binding, so surviving proves nothing"
    );
}

#[test]
#[serial]
fn runtime_command_rebinds_git_and_kin_authority_at_launch() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let _ambient_git = EnvVarGuard::set("GIT_DIR", std::ffi::OsStr::new("/ambient/git"));
    let _ambient_worktree =
        EnvVarGuard::set("GIT_WORK_TREE", std::ffi::OsStr::new("/ambient/worktree"));
    let _ambient_config = EnvVarGuard::set("GIT_CONFIG_COUNT", std::ffi::OsStr::new("1"));
    let _ambient_ceiling = EnvVarGuard::set(
        "GIT_CEILING_DIRECTORIES",
        std::ffi::OsStr::new("/ambient/ceiling"),
    );
    let _ambient_discovery =
        EnvVarGuard::set("GIT_DISCOVERY_ACROSS_FILESYSTEM", std::ffi::OsStr::new("0"));
    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_sleeper_worker"),
            OsString::from("--nocapture"),
        ],
        Vec::new(),
        Duration::from_secs(1),
    );
    let mut command = runtime.kin_command();
    command
        .arg("--version")
        .env("GIT_DIR", "/command-local/git")
        .env("GIT_WORK_TREE", "/command-local/worktree")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/command-local/hooks")
        .env("GIT_CEILING_DIRECTORIES", "/command-local/ceiling")
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "0")
        .env("GIT_NAMESPACE", "command-local")
        .env("KIN_REGISTRY_PATH", "/command-local/registry.toml")
        .env("KIN_TEST_RUNTIME_OWNER_TOKEN", "hostile-owner")
        .env("KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP", "1");
    command.prepare_for_launch_for_test();
    for removed in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_NAMESPACE",
    ] {
        assert_eq!(
            command.configured_env_for_test(std::ffi::OsStr::new(removed)),
            Some(None),
            "{removed} survived the runtime launch binding"
        );
    }
    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new("KIN_REGISTRY_PATH")),
        Some(Some(runtime.registry_path().as_os_str().to_os_string())),
        "command-local registry authority replaced the isolated runtime"
    );
    assert_ne!(
        command.configured_env_for_test(std::ffi::OsStr::new("KIN_TEST_RUNTIME_OWNER_TOKEN")),
        Some(Some(OsString::from("hostile-owner"))),
        "command-local owner capability replaced the isolated runtime"
    );
    assert_ne!(
        command.configured_env_for_test(std::ffi::OsStr::new(
            "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP"
        )),
        Some(Some(OsString::from("1"))),
        "command-local process-group capability replaced the isolated runtime"
    );
    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_SHUTDOWN_GRACE_SECS")),
        Some(Some(OsString::from("3"))),
        "isolated runtime lost its bounded daemon shutdown grace"
    );
    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new(
            "KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS"
        )),
        Some(Some(OsString::from("1"))),
        "isolated runtime lost its bounded tokio shutdown grace"
    );
    let output = command.output().expect("run runtime authority probe");
    assert!(
        output.status.success(),
        "kin --version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[serial]
fn runtime_launch_keeps_the_exact_safe_git_environment_after_final_scrub() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(&repository).expect("create repository");
    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_sleeper_worker"),
            OsString::from("--nocapture"),
        ],
        Vec::new(),
        Duration::from_secs(1),
    );
    let mut command = runtime.process_command_for_test("unused-fixture-program");
    command
        .env("GIT_DIR", "/hostile/repository")
        .env("GIT_CONFIG_NOSYSTEM", "0")
        .env("GIT_ATTR_NOSYSTEM", "0")
        .env("GIT_TERMINAL_PROMPT", "1")
        .env("GIT_PAGER", "hostile-pager")
        .env("GIT_ALLOW_PROTOCOL", "ext")
        .env("GIT_PROTOCOL_FROM_USER", "1")
        .env("GIT_CONFIG_GLOBAL", "/hostile/global.gitconfig");

    command.prepare_for_launch_for_test();

    assert_eq!(
        command.configured_env_for_test(std::ffi::OsStr::new("GIT_DIR")),
        Some(None),
        "repository authority survived the final launch binding"
    );
    for (key, expected) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_PAGER", "cat"),
        ("GIT_ALLOW_PROTOCOL", "file"),
        ("GIT_PROTOCOL_FROM_USER", "0"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ] {
        assert_eq!(
            command.configured_env_for_test(std::ffi::OsStr::new(key)),
            Some(Some(OsString::from(expected))),
            "{key} did not retain the exact safe fixture value after final preparation"
        );
    }
}

#[test]
#[serial]
fn isolated_runtime_scrubs_ambient_authority_and_reaps_every_process() {
    let root = tempdir().expect("temp root");
    let sentinel_home = root.path().join("sentinel-home");
    let sentinel_kin = sentinel_home.join(".kin");
    let sentinel_registry = sentinel_kin.join("registry.toml");
    let sentinel_supervisor_log = sentinel_kin.join("supervisor.log");
    std::fs::create_dir_all(&sentinel_kin).expect("create sentinel Kin home");
    std::fs::write(&sentinel_registry, b"repos = []\n").expect("write sentinel registry");
    std::fs::write(&sentinel_supervisor_log, b"sentinel supervisor log\n")
        .expect("write sentinel supervisor log");
    std::fs::set_permissions(&sentinel_registry, std::fs::Permissions::from_mode(0o600))
        .expect("secure sentinel registry");
    let sentinel_registry_before =
        std::fs::read(&sentinel_registry).expect("read sentinel registry before");
    let sentinel_log_before =
        std::fs::read(&sentinel_supervisor_log).expect("read sentinel log before");

    // These values model a developer shell already bound to real runtime and
    // VFS authority. The fixture launcher must remove them from every child.
    let _home = EnvVarGuard::set("HOME", sentinel_home.as_os_str());
    let _registry = EnvVarGuard::set("KIN_REGISTRY_PATH", sentinel_registry.as_os_str());
    let _daemon_url =
        EnvVarGuard::set("KIN_DAEMON_URL", std::ffi::OsStr::new("http://127.0.0.1:9"));
    let _supervisor_url = EnvVarGuard::set(
        "KIN_SUPERVISOR_URL",
        std::ffi::OsStr::new("http://127.0.0.1:9"),
    );
    let _daemon_bind_host =
        EnvVarGuard::set("KIN_DAEMON_BIND_HOST", std::ffi::OsStr::new("192.0.2.1"));
    let _daemon_auth = EnvVarGuard::set(
        "KIN_DAEMON_AUTH_TOKEN",
        std::ffi::OsStr::new("ambient-token"),
    );
    let _daemon_require_token =
        EnvVarGuard::set("KIN_DAEMON_REQUIRE_TOKEN", std::ffi::OsStr::new("true"));
    let _supervisor_bind_host = EnvVarGuard::set(
        "KIN_SUPERVISOR_BIND_HOST",
        std::ffi::OsStr::new("192.0.2.1"),
    );
    let _supervisor_auth = EnvVarGuard::set(
        "KIN_SUPERVISOR_AUTH_TOKEN",
        std::ffi::OsStr::new("ambient-token"),
    );
    let _supervisor_require_token =
        EnvVarGuard::set("KIN_SUPERVISOR_REQUIRE_TOKEN", std::ffi::OsStr::new("true"));
    let _vfs_workspace = EnvVarGuard::set("KIN_VFS_WORKSPACE", sentinel_home.as_os_str());
    let _storage = EnvVarGuard::set("KIN_STORAGE", std::ffi::OsStr::new("gcs"));
    let _gcs_bucket = EnvVarGuard::set(
        "KIN_GCS_BUCKET",
        std::ffi::OsStr::new("must-never-be-contacted"),
    );
    let _gcs_prefix = EnvVarGuard::set("KIN_GCS_PREFIX", std::ffi::OsStr::new("hostile-prefix"));
    let _unknown_kin = EnvVarGuard::set(
        "KIN_TEST_HOSTILE_UNKNOWN_AUTHORITY",
        std::ffi::OsStr::new("must-be-scrubbed"),
    );
    let _git_dir = EnvVarGuard::set("GIT_DIR", std::ffi::OsStr::new("/hostile/git-dir"));
    let _git_config_count = EnvVarGuard::set("GIT_CONFIG_COUNT", std::ffi::OsStr::new("1"));
    let _git_config_key =
        EnvVarGuard::set("GIT_CONFIG_KEY_0", std::ffi::OsStr::new("core.hooksPath"));
    let _git_config_value =
        EnvVarGuard::set("GIT_CONFIG_VALUE_0", std::ffi::OsStr::new("/hostile/hooks"));
    let _git_default_hash = EnvVarGuard::set("GIT_DEFAULT_HASH", std::ffi::OsStr::new("sha256"));
    let _dyld = EnvVarGuard::set(
        "DYLD_INSERT_LIBRARIES",
        std::ffi::OsStr::new("/hostile/libkin_vfs.dylib"),
    );
    let _dyld_library_path =
        EnvVarGuard::set("DYLD_LIBRARY_PATH", std::ffi::OsStr::new("/hostile/dyld"));
    let _ld_preload =
        EnvVarGuard::set("LD_PRELOAD", std::ffi::OsStr::new("/hostile/libkin_vfs.so"));
    let _ld_audit = EnvVarGuard::set("LD_AUDIT", std::ffi::OsStr::new("/hostile/libaudit.so"));
    let _ld_library_path = EnvVarGuard::set("LD_LIBRARY_PATH", std::ffi::OsStr::new("/hostile/ld"));
    let _ld_custom = EnvVarGuard::set(
        "LD_CUSTOM_INJECTION",
        std::ffi::OsStr::new("/hostile/custom-loader"),
    );
    let _last_vfs_dir = EnvVarGuard::set(
        "_KIN_VFS_LAST_DIR",
        std::ffi::OsStr::new("/hostile/workspace/src"),
    );

    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join("src")).expect("create fixture source dir");
    git(&repository, &["init", "--initial-branch=main"]);
    git(
        &repository,
        &["config", "user.email", "kin@example.invalid"],
    );
    git(&repository, &["config", "user.name", "Kin Test"]);
    std::fs::write(
        repository.join("src/lib.rs"),
        "pub fn hermetic_runtime_probe() {}\n",
    )
    .expect("write fixture source");
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repository);
    assert!(
        !repository.join(".kin").exists(),
        "constructing the isolated runtime created product control state before kin init"
    );
    let isolated_command = runtime.kin_command();
    for removed in [
        "KIN_STORAGE",
        "KIN_GCS_BUCKET",
        "KIN_GCS_PREFIX",
        "KIN_TEST_HOSTILE_UNKNOWN_AUTHORITY",
        "GIT_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_DEFAULT_HASH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_CUSTOM_INJECTION",
        "_KIN_VFS_LAST_DIR",
    ] {
        assert_eq!(
            isolated_command.configured_env_for_test(std::ffi::OsStr::new(removed)),
            Some(None),
            "{removed} remained in the isolated command environment"
        );
    }
    let mut launch_bound = runtime.kin_command();
    launch_bound
        .arg("--version")
        .env("KIN_REGISTRY_PATH", "/hostile/registry.toml")
        .env("KIN_DAEMON_URL", "http://127.0.0.1:9")
        .env("KIN_TEST_RUNTIME_OWNER_TOKEN", "hostile-owner")
        .env("KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP", "1")
        .env("GIT_DEFAULT_HASH", "sha256")
        .env("LD_AUDIT", "/hostile/libaudit.so")
        .env("LD_CUSTOM_INJECTION", "/hostile/custom-loader")
        .env("KIN_DAEMON_BIN", "/intentional/test-daemon");
    launch_bound.prepare_for_launch_for_test();
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("KIN_REGISTRY_PATH")),
        Some(Some(runtime.registry_path().as_os_str().to_os_string())),
        "command-local registry authority bypassed the launch-time binding"
    );
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_URL")),
        Some(None),
        "command-local daemon URL survived the launch-time binding"
    );
    assert_ne!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("KIN_TEST_RUNTIME_OWNER_TOKEN")),
        Some(Some(OsString::from("hostile-owner"))),
        "command-local owner token replaced the runtime capability"
    );
    assert_ne!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new(
            "KIN_TEST_RUNTIME_CONTAINMENT_PROCESS_GROUP"
        )),
        Some(Some(OsString::from("1"))),
        "command-local process-group capability replaced the runtime binding"
    );
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("LD_AUDIT")),
        Some(None),
        "command-local loader injection survived the launch-time binding"
    );
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("LD_CUSTOM_INJECTION")),
        Some(None),
        "command-local wildcard loader injection survived the launch-time binding"
    );
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("GIT_DEFAULT_HASH")),
        Some(None),
        "command-local Git authority survived the launch-time binding"
    );
    assert_eq!(
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_BIN")),
        Some(Some(OsString::from("/intentional/test-daemon"))),
        "intentional safe daemon override was not preserved"
    );
    let version = launch_bound
        .output()
        .expect("run launch-time authority regression");
    assert!(
        version.status.success(),
        "kin --version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    let init = runtime
        .kin_command()
        .args(["init", "."])
        .current_dir(&repository)
        .output()
        .expect("run isolated Kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let locate = runtime
        .kin_command()
        .args(["locate", "--json", "hermetic runtime probe"])
        .current_dir(&repository)
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "30")
        .env("KIN_SUPERVISOR_IDLE_TIMEOUT_SECS", "30")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1")
        .output()
        .expect("run isolated Kin locate");
    assert!(
        locate.status.success(),
        "kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );

    let worker_pid_path = repository.join(".kin/daemon.pid");
    let supervisor_pid_path = runtime
        .registry_path()
        .parent()
        .expect("runtime registry parent")
        .join("supervisor.pid");
    let worker_pid = recorded_pid(&worker_pid_path);
    let supervisor_pid = recorded_pid(&supervisor_pid_path);
    assert!(
        process_alive(worker_pid),
        "fixture worker never became live"
    );
    assert!(
        process_alive(supervisor_pid),
        "fixture supervisor never became live"
    );
    let expected_group = runtime.process_group_for_test();
    for (label, pid) in [("worker", worker_pid), ("supervisor", supervisor_pid)] {
        let pid = libc::pid_t::try_from(pid).expect("fixture pid fits pid_t");
        assert_eq!(
            unsafe { libc::getpgid(pid) },
            expected_group,
            "fixture {label} escaped runtime containment before cleanup"
        );
    }

    drop(runtime);

    assert!(
        !process_alive(worker_pid),
        "isolated runtime leaked worker pid {worker_pid}"
    );
    assert!(
        !process_alive(supervisor_pid),
        "isolated runtime leaked supervisor pid {supervisor_pid}"
    );
    assert!(
        !worker_pid_path.exists(),
        "worker pid file survived cleanup"
    );
    assert!(
        !supervisor_pid_path.exists(),
        "supervisor pid file survived cleanup"
    );
    assert_eq!(
        std::fs::read(&sentinel_registry).expect("read sentinel registry after"),
        sentinel_registry_before,
        "isolated runtime changed ambient registry bytes"
    );
    assert_eq!(
        std::fs::read(&sentinel_supervisor_log).expect("read sentinel log after"),
        sentinel_log_before,
        "isolated runtime changed ambient supervisor log bytes"
    );
}

const CLEANUP_SLEEPER: &str = "KIN_TEST_CLEANUP_SLEEPER_WORKER";
const CLEANUP_TRIGGER: &str = "KIN_TEST_CLEANUP_TRIGGER";
const CLEANUP_WAIT_FOR_MARKER: &str = "KIN_TEST_CLEANUP_WAIT_FOR_MARKER";
const TREE_PARENT: &str = "KIN_TEST_PROCESS_TREE_PARENT";
const TREE_PARENT_READY: &str = "KIN_TEST_PROCESS_TREE_PARENT_READY";
const TREE_DESCENDANT: &str = "KIN_TEST_PROCESS_TREE_DESCENDANT";
const TREE_WAIT_FOR_TRIGGER: &str = "KIN_TEST_PROCESS_TREE_WAIT_FOR_TRIGGER";
const PARENT_DEATH_WORKER: &str = "KIN_TEST_PARENT_DEATH_WORKER";
const PARENT_DEATH_READY: &str = "KIN_TEST_PARENT_DEATH_READY";

#[test]
#[serial]
fn cleanup_sleeper_worker() {
    if std::env::var_os(CLEANUP_SLEEPER).is_none() {
        return;
    }
    if let Some(trigger) = std::env::var_os(CLEANUP_TRIGGER) {
        std::fs::write(PathBuf::from(trigger), b"cleanup started").expect("write cleanup trigger");
    }
    if let Some(marker) = std::env::var_os(CLEANUP_WAIT_FOR_MARKER) {
        let marker = PathBuf::from(marker);
        let _ = recorded_pid(&marker);
    }
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[serial]
fn containment_process_tree_worker() {
    if let Some(marker) = std::env::var_os(TREE_DESCENDANT) {
        publish_marker_atomically(&PathBuf::from(marker), std::process::id().to_string());
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let Some(marker) = std::env::var_os(TREE_PARENT) else {
        return;
    };
    let descendant_marker = PathBuf::from(marker);
    if let Some(ready) = std::env::var_os(TREE_PARENT_READY) {
        std::fs::write(PathBuf::from(ready), b"parent ready").expect("write parent readiness");
    }
    if let Some(trigger) = std::env::var_os(TREE_WAIT_FOR_TRIGGER) {
        let trigger = PathBuf::from(trigger);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !trigger.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            trigger.is_file(),
            "containment parent never received its spawn trigger"
        );
    }
    let mut descendant = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_DESCENDANT, &descendant_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn contained descendant");
    let _ = descendant.wait();
}

#[test]
#[serial]
// The outer test kills this worker process to prove that hard parent death
// terminates the owned descendant tree. Waiting here would defeat that test.
#[allow(clippy::zombie_processes)]
fn parent_death_runtime_worker() {
    let Some(root) = std::env::var_os(PARENT_DEATH_WORKER) else {
        return;
    };
    let root = PathBuf::from(root);
    let repository = root.join("repository");
    let descendant_marker = root.join("parent-death-descendant.pid");
    let ready = std::env::var_os(PARENT_DEATH_READY)
        .map(PathBuf::from)
        .expect("parent-death readiness path");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let runtime = common::IsolatedDaemonRuntime::new(&repository);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_DESCENDANT, &descendant_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _descendant = runtime
        .spawn_owned_process_for_test(command)
        .expect("spawn parent-death descendant");
    let descendant = recorded_pid(&descendant_marker);
    publish_marker_atomically(&ready, descendant.to_string());
    let _runtime = runtime;
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
#[serial]
fn hard_parent_death_terminates_the_guarded_process_group() {
    let root = tempdir().expect("temp root");
    let ready = root.path().join("parent-death.ready");
    let mut parent = KillAndReapChild::new(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "parent_death_runtime_worker", "--nocapture"])
            .env(PARENT_DEATH_WORKER, root.path())
            .env(PARENT_DEATH_READY, &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn parent-death runtime worker"),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let descendant = loop {
        if let Some(pid) = try_recorded_pid(&ready) {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "parent-death worker never published a parseable descendant pid"
        );
        assert!(
            parent
                .try_wait()
                .expect("poll parent-death worker")
                .is_none(),
            "parent-death worker exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    parent
        .terminate_and_reap()
        .expect("kill and reap parent-death runtime worker");

    wait_for_process_exit(descendant);
}

fn spawn_contained_process_tree(
    root: &Path,
    runtime: &common::IsolatedDaemonRuntime,
) -> (common::RuntimeOwnedChild, u32) {
    let marker = root.join("descendant.pid");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_PARENT, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = runtime
        .spawn_owned_process_for_test(command)
        .expect("spawn contained process tree");
    let descendant = recorded_pid(&marker);
    (child, descendant)
}

fn timeout_cleanup_runtime(repository: &Path) -> common::IsolatedDaemonRuntime {
    timeout_cleanup_runtime_with(repository, Vec::new(), Duration::from_millis(100))
}

fn timeout_cleanup_runtime_with(
    repository: &Path,
    mut env: Vec<(OsString, OsString)>,
    timeout: Duration,
) -> common::IsolatedDaemonRuntime {
    env.push((OsString::from(CLEANUP_SLEEPER), OsString::from("1")));
    common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        repository,
        std::env::current_exe().expect("current integration test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_sleeper_worker"),
            OsString::from("--nocapture"),
        ],
        env,
        timeout,
    )
}

fn wait_for_process_exit(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_alive(pid), "process {pid} survived cleanup");
}

#[test]
#[serial]
fn bounded_command_timeout_reaps_its_contained_descendants() {
    let root = tempdir().expect("temp root");
    let marker = root.path().join("bounded-command-descendant.pid");
    let mut command = common::Command::new(std::env::current_exe().unwrap());
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        command
            .args(["--exact", "containment_process_tree_worker", "--nocapture"])
            .env(TREE_PARENT, &marker)
            .output_after_path_ready_within(
                &marker,
                Duration::from_secs(5),
                Duration::from_millis(100),
            )
    }));
    assert!(
        cleanup.is_err(),
        "the bounded command must expose its forced timeout"
    );
    let descendant = recorded_pid(&marker);
    wait_for_process_exit(descendant);
}

#[test]
#[serial]
fn cleanup_timeout_terminates_the_stable_runtime_containment() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let runtime = timeout_cleanup_runtime(&repository);
    let (mut parent, descendant) = spawn_contained_process_tree(root.path(), &runtime);
    let parent_pid = parent.id();
    std::fs::write(repository.join(".kin/daemon.pid"), parent_pid.to_string())
        .expect("write stale endpoint pid");

    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runtime)));
    assert!(
        cleanup.is_err(),
        "the forced product-cleanup timeout must remain visible"
    );
    let _ = parent.wait();
    wait_for_process_exit(parent_pid);
    wait_for_process_exit(descendant);
}

#[test]
#[serial]
fn stale_endpoint_pid_does_not_authorize_killing_an_unowned_process() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let runtime = timeout_cleanup_runtime(&repository);
    let mut unowned = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cleanup_sleeper_worker", "--nocapture"])
        .env(CLEANUP_SLEEPER, "1")
        .env_remove("KIN_TEST_RUNTIME_OWNER_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn unowned endpoint process");
    std::fs::write(repository.join(".kin/daemon.pid"), unowned.id().to_string())
        .expect("write stale endpoint pid");

    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runtime)));
    assert!(
        cleanup.is_err(),
        "the forced product-cleanup timeout must remain visible"
    );
    let survived_runtime_cleanup = unowned.try_wait().expect("poll unowned process").is_none();
    let _ = unowned.kill();
    let _ = unowned.wait();

    assert!(
        survived_runtime_cleanup,
        "a stale endpoint pid authorized killing a process without the runtime owner token"
    );
}

#[test]
#[serial]
fn descendant_spawned_during_graceful_cleanup_is_still_reaped() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let trigger = root.path().join("spawn-descendant.trigger");
    let descendant_marker = root.path().join("late-descendant.pid");
    let parent_ready = root.path().join("late-parent.ready");
    let runtime = timeout_cleanup_runtime_with(
        &repository,
        vec![
            (
                OsString::from(CLEANUP_TRIGGER),
                trigger.as_os_str().to_os_string(),
            ),
            (
                OsString::from(CLEANUP_WAIT_FOR_MARKER),
                descendant_marker.as_os_str().to_os_string(),
            ),
        ],
        Duration::from_secs(1),
    );
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_PARENT, &descendant_marker)
        .env(TREE_PARENT_READY, &parent_ready)
        .env(TREE_WAIT_FOR_TRIGGER, &trigger)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut parent = runtime
        .spawn_owned_process_for_test(command)
        .expect("spawn delayed contained process tree");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !parent_ready.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        parent_ready.is_file(),
        "containment parent was not ready before graceful cleanup"
    );
    let parent_pid = parent.id();
    std::fs::write(repository.join(".kin/daemon.pid"), parent_pid.to_string())
        .expect("write stale endpoint pid");

    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runtime)));
    assert!(
        cleanup.is_err(),
        "the forced product-cleanup timeout must remain visible"
    );
    assert!(
        trigger.is_file(),
        "graceful cleanup never triggered the late descendant"
    );
    let descendant = recorded_pid(&descendant_marker);
    let _ = parent.wait();
    wait_for_process_exit(parent_pid);
    wait_for_process_exit(descendant);
}

#[test]
#[serial]
fn panic_unwind_still_reaps_the_stable_runtime_containment() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let mut parent = None;
    let mut parent_pid = 0;
    let mut descendant = 0;

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = timeout_cleanup_runtime(&repository);
        let (child, child_descendant) = spawn_contained_process_tree(root.path(), &runtime);
        parent_pid = child.id();
        descendant = child_descendant;
        std::fs::write(repository.join(".kin/daemon.pid"), parent_pid.to_string())
            .expect("write stale endpoint pid");
        parent = Some(child);
        let _runtime = runtime;
        panic!("intentional primary test panic");
    }));

    assert!(panic.is_err(), "the primary panic must propagate");
    let _ = parent.as_mut().expect("contained process parent").wait();
    wait_for_process_exit(parent_pid);
    wait_for_process_exit(descendant);
}
