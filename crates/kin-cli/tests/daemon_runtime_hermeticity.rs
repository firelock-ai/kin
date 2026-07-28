// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

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

#[test]
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
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
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
