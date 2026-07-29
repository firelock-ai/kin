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

struct EnvGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
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

fn recorded_pid(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read recorded pid at {}: {error}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("parse recorded pid at {}: {error}", path.display()))
}

fn process_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

const GENERIC_AUTHORITY_WORKER: &str = "KIN_TEST_GENERIC_AUTHORITY_WORKER";
const GENERIC_INTENTIONAL_OVERRIDE: &str = "KIN_TEST_GENERIC_INTENTIONAL_OVERRIDE";

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
    let _ambient_git = EnvGuard::set("GIT_DIR", std::ffi::OsStr::new("/ambient/git"));
    let _ambient_kin = EnvGuard::set(
        "KIN_GCS_BUCKET",
        std::ffi::OsStr::new("ambient-production-bucket"),
    );
    let _ambient_loader = EnvGuard::set("LD_AUDIT", std::ffi::OsStr::new("/ambient/libaudit.so"));

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "generic_authority_worker", "--nocapture"])
        .env(GENERIC_AUTHORITY_WORKER, &marker)
        .env(GENERIC_INTENTIONAL_OVERRIDE, "preserved")
        .env("GIT_WORK_TREE", "/command-local/worktree")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CEILING_DIRECTORIES", "/command-local/ceiling")
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "0")
        .env("GIT_NAMESPACE", "command-local")
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
fn runtime_command_rebinds_git_and_kin_authority_at_launch() {
    let root = tempdir().expect("temp root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(repository.join(".kin")).expect("create Kin control dir");
    let _ambient_git = EnvGuard::set("GIT_DIR", std::ffi::OsStr::new("/ambient/git"));
    let _ambient_worktree =
        EnvGuard::set("GIT_WORK_TREE", std::ffi::OsStr::new("/ambient/worktree"));
    let _ambient_config = EnvGuard::set("GIT_CONFIG_COUNT", std::ffi::OsStr::new("1"));
    let _ambient_ceiling = EnvGuard::set(
        "GIT_CEILING_DIRECTORIES",
        std::ffi::OsStr::new("/ambient/ceiling"),
    );
    let _ambient_discovery =
        EnvGuard::set("GIT_DISCOVERY_ACROSS_FILESYSTEM", std::ffi::OsStr::new("0"));
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
    let output = command.output().expect("run runtime authority probe");
    assert!(
        output.status.success(),
        "kin --version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
    let _home = EnvGuard::set("HOME", sentinel_home.as_os_str());
    let _registry = EnvGuard::set("KIN_REGISTRY_PATH", sentinel_registry.as_os_str());
    let _daemon_url = EnvGuard::set("KIN_DAEMON_URL", std::ffi::OsStr::new("http://127.0.0.1:9"));
    let _supervisor_url = EnvGuard::set(
        "KIN_SUPERVISOR_URL",
        std::ffi::OsStr::new("http://127.0.0.1:9"),
    );
    let _daemon_bind_host =
        EnvGuard::set("KIN_DAEMON_BIND_HOST", std::ffi::OsStr::new("192.0.2.1"));
    let _daemon_auth = EnvGuard::set(
        "KIN_DAEMON_AUTH_TOKEN",
        std::ffi::OsStr::new("ambient-token"),
    );
    let _daemon_require_token =
        EnvGuard::set("KIN_DAEMON_REQUIRE_TOKEN", std::ffi::OsStr::new("true"));
    let _supervisor_bind_host = EnvGuard::set(
        "KIN_SUPERVISOR_BIND_HOST",
        std::ffi::OsStr::new("192.0.2.1"),
    );
    let _supervisor_auth = EnvGuard::set(
        "KIN_SUPERVISOR_AUTH_TOKEN",
        std::ffi::OsStr::new("ambient-token"),
    );
    let _supervisor_require_token =
        EnvGuard::set("KIN_SUPERVISOR_REQUIRE_TOKEN", std::ffi::OsStr::new("true"));
    let _vfs_workspace = EnvGuard::set("KIN_VFS_WORKSPACE", sentinel_home.as_os_str());
    let _storage = EnvGuard::set("KIN_STORAGE", std::ffi::OsStr::new("gcs"));
    let _gcs_bucket = EnvGuard::set(
        "KIN_GCS_BUCKET",
        std::ffi::OsStr::new("must-never-be-contacted"),
    );
    let _gcs_prefix = EnvGuard::set("KIN_GCS_PREFIX", std::ffi::OsStr::new("hostile-prefix"));
    let _unknown_kin = EnvGuard::set(
        "KIN_TEST_HOSTILE_UNKNOWN_AUTHORITY",
        std::ffi::OsStr::new("must-be-scrubbed"),
    );
    let _dyld = EnvGuard::set(
        "DYLD_INSERT_LIBRARIES",
        std::ffi::OsStr::new("/hostile/libkin_vfs.dylib"),
    );
    let _dyld_library_path =
        EnvGuard::set("DYLD_LIBRARY_PATH", std::ffi::OsStr::new("/hostile/dyld"));
    let _ld_preload = EnvGuard::set("LD_PRELOAD", std::ffi::OsStr::new("/hostile/libkin_vfs.so"));
    let _ld_audit = EnvGuard::set("LD_AUDIT", std::ffi::OsStr::new("/hostile/libaudit.so"));
    let _ld_library_path = EnvGuard::set("LD_LIBRARY_PATH", std::ffi::OsStr::new("/hostile/ld"));
    let _last_vfs_dir = EnvGuard::set(
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
    let isolated_command = runtime.kin_command();
    for removed in [
        "KIN_STORAGE",
        "KIN_GCS_BUCKET",
        "KIN_GCS_PREFIX",
        "KIN_TEST_HOSTILE_UNKNOWN_AUTHORITY",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
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
        .env("LD_AUDIT", "/hostile/libaudit.so")
        .env("KIN_DAEMON_BIN", "/intentional/test-daemon");
    let version = launch_bound
        .output()
        .expect("run launch-time authority regression");
    assert!(
        version.status.success(),
        "kin --version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
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
        launch_bound.configured_env_for_test(std::ffi::OsStr::new("KIN_DAEMON_BIN")),
        Some(Some(OsString::from("/intentional/test-daemon"))),
        "intentional safe daemon override was not preserved"
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
    let supervisor_pid_path = repository.join(".kin/test-runtime/supervisor.pid");
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
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[serial]
fn containment_process_tree_worker() {
    if let Some(marker) = std::env::var_os(TREE_DESCENDANT) {
        std::fs::write(PathBuf::from(marker), std::process::id().to_string())
            .expect("write descendant pid");
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
    runtime.mark_owned_process_for_test(&mut command);
    let _descendant = command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_DESCENDANT, &descendant_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn parent-death descendant");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !descendant_marker.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        descendant_marker.is_file(),
        "parent-death descendant did not become ready"
    );
    std::fs::write(ready, b"parent ready").expect("write parent-death readiness");
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
    let descendant_marker = root.path().join("parent-death-descendant.pid");
    let mut parent = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "parent_death_runtime_worker", "--nocapture"])
        .env(PARENT_DEATH_WORKER, root.path())
        .env(PARENT_DEATH_READY, &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn parent-death runtime worker");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.is_file() && Instant::now() < deadline {
        assert!(
            parent
                .try_wait()
                .expect("poll parent-death worker")
                .is_none(),
            "parent-death worker exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready.is_file(), "parent-death worker never became ready");
    let descendant = recorded_pid(&descendant_marker);

    parent.kill().expect("kill parent-death runtime worker");
    parent.wait().expect("reap parent-death runtime worker");

    wait_for_process_exit(descendant);
}

fn spawn_contained_process_tree(
    root: &Path,
    runtime: &common::IsolatedDaemonRuntime,
) -> (Child, u32) {
    let marker = root.join("descendant.pid");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    runtime.mark_owned_process_for_test(&mut command);
    let child = command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_PARENT, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn contained process tree");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
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
            .output_within(Duration::from_millis(100))
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
    runtime.mark_owned_process_for_test(&mut command);
    let mut parent = command
        .args(["--exact", "containment_process_tree_worker", "--nocapture"])
        .env(TREE_PARENT, &descendant_marker)
        .env(TREE_PARENT_READY, &parent_ready)
        .env(TREE_WAIT_FOR_TRIGGER, &trigger)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
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
