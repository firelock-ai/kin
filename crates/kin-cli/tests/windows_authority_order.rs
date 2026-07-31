// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(any(unix, windows))]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use serial_test::serial;
use tempfile::tempdir;

mod common;

const WORKER_ENV: &str = "KIN_TEST_WINDOWS_AUTHORITY_WORKER";
const MARKER_ENV: &str = "KIN_TEST_WINDOWS_AUTHORITY_MARKER";
const EXPECTED_REGISTRY_ENV: &str = "KIN_TEST_WINDOWS_EXPECTED_REGISTRY";
const EXPECTED_GIT_DATE_ENV: &str = "KIN_TEST_WINDOWS_EXPECTED_GIT_DATE";
const EXPECTED_DAEMON_URL_ENV: &str = "KIN_TEST_WINDOWS_EXPECTED_DAEMON_URL";
const INTENTIONAL_OVERRIDE_ENV: &str = "KIN_TEST_WINDOWS_INTENTIONAL_OVERRIDE";

#[cfg(windows)]
const AMBIENT_GIT_DIR: &str = "gIt_dIr";
#[cfg(not(windows))]
const AMBIENT_GIT_DIR: &str = "GIT_DIR";
#[cfg(windows)]
const AMBIENT_KIN_BUCKET: &str = "kIn_gCs_bUcKeT";
#[cfg(not(windows))]
const AMBIENT_KIN_BUCKET: &str = "KIN_GCS_BUCKET";
#[cfg(windows)]
const AMBIENT_DYLD_INJECTION: &str = "dYlD_cUsToM_iNjEcTiOn";
#[cfg(not(windows))]
const AMBIENT_DYLD_INJECTION: &str = "DYLD_CUSTOM_INJECTION";
#[cfg(windows)]
const AMBIENT_LD_INJECTION: &str = "lD_cUsToM_iNjEcTiOn";
#[cfg(not(windows))]
const AMBIENT_LD_INJECTION: &str = "LD_CUSTOM_INJECTION";

#[cfg(windows)]
const COMMAND_GIT_WORK_TREE: &str = "gIt_wOrK_tReE";
#[cfg(not(windows))]
const COMMAND_GIT_WORK_TREE: &str = "GIT_WORK_TREE";
#[cfg(windows)]
const COMMAND_GIT_CONFIG_COUNT: &str = "gIt_cOnFiG_cOuNt";
#[cfg(not(windows))]
const COMMAND_GIT_CONFIG_COUNT: &str = "GIT_CONFIG_COUNT";
#[cfg(windows)]
const COMMAND_KIN_BUCKET: &str = "kIn_gCs_bUcKeT";
#[cfg(not(windows))]
const COMMAND_KIN_BUCKET: &str = "KIN_GCS_BUCKET";
#[cfg(windows)]
const COMMAND_LAST_VFS_DIR: &str = "_kIn_vFs_lAsT_dIr";
#[cfg(not(windows))]
const COMMAND_LAST_VFS_DIR: &str = "_KIN_VFS_LAST_DIR";
#[cfg(windows)]
const COMMAND_DYLD_INJECTION: &str = "dYlD_iNsErT_lIbRaRiEs";
#[cfg(not(windows))]
const COMMAND_DYLD_INJECTION: &str = "DYLD_INSERT_LIBRARIES";
#[cfg(windows)]
const COMMAND_LD_INJECTION: &str = "lD_pReLoAd";
#[cfg(not(windows))]
const COMMAND_LD_INJECTION: &str = "LD_PRELOAD";
#[cfg(windows)]
const COMMAND_REGISTRY: &str = "kIn_rEgIsTrY_pAtH";
#[cfg(not(windows))]
const COMMAND_REGISTRY: &str = "KIN_REGISTRY_PATH";
#[cfg(windows)]
const COMMAND_OWNER_TOKEN: &str = "kIn_TeSt_RuNtImE_oWnEr_ToKeN";
#[cfg(not(windows))]
use kin_core::test_env::EnvVarGuard;

const COMMAND_OWNER_TOKEN: &str = "KIN_TEST_RUNTIME_OWNER_TOKEN";
#[cfg(windows)]
const COMMAND_GIT_CONFIG_NOSYSTEM: &str = "gIt_cOnFiG_nOsYsTeM";
#[cfg(not(windows))]
const COMMAND_GIT_CONFIG_NOSYSTEM: &str = "GIT_CONFIG_NOSYSTEM";

#[test]
fn authority_order_worker() {
    if std::env::var_os(WORKER_ENV).is_none() {
        return;
    }
    let marker = std::env::var_os(MARKER_ENV).expect("authority-order marker path");
    for removed in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG_COUNT",
        "KIN_GCS_BUCKET",
        "_KIN_VFS_LAST_DIR",
        "DYLD_CUSTOM_INJECTION",
        "DYLD_INSERT_LIBRARIES",
        "LD_CUSTOM_INJECTION",
        "LD_PRELOAD",
    ] {
        assert!(
            std::env::var_os(removed).is_none(),
            "{removed} reached the spawned authority worker"
        );
    }

    let expected_registry =
        std::env::var_os(EXPECTED_REGISTRY_ENV).expect("expected isolated registry path");
    assert_eq!(
        std::env::var_os("KIN_REGISTRY_PATH").as_deref(),
        Some(expected_registry.as_os_str()),
        "the command-local registry replaced runtime-owned authority"
    );
    let owner_token = std::env::var_os("KIN_TEST_RUNTIME_OWNER_TOKEN")
        .expect("runtime owner capability reached the child");
    assert_ne!(
        owner_token,
        OsString::from("hostile-owner"),
        "the command-local owner token replaced the runtime capability"
    );

    for (key, expected) in [
        ("KIN_VFS_DISABLE", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_PAGER", "cat"),
        ("GIT_ALLOW_PROTOCOL", "file"),
        ("GIT_PROTOCOL_FROM_USER", "0"),
    ] {
        assert_eq!(
            std::env::var(key).as_deref(),
            Ok(expected),
            "{key} did not retain its final safe binding"
        );
    }
    #[cfg(windows)]
    assert_eq!(std::env::var("GIT_CONFIG_GLOBAL").as_deref(), Ok("NUL"));
    #[cfg(unix)]
    assert_eq!(
        std::env::var("GIT_CONFIG_GLOBAL").as_deref(),
        Ok("/dev/null")
    );

    let expected_git_date =
        std::env::var(EXPECTED_GIT_DATE_ENV).expect("expected fixture Git date");
    for key in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
        assert_eq!(
            std::env::var(key).as_deref(),
            Ok(expected_git_date.as_str()),
            "{key} was not replayed after the final Git scrub"
        );
    }
    let expected_daemon_url =
        std::env::var(EXPECTED_DAEMON_URL_ENV).expect("expected fixture daemon URL");
    assert_eq!(
        std::env::var("KIN_DAEMON_URL").as_deref(),
        Ok(expected_daemon_url.as_str()),
        "the typed daemon URL was not replayed after runtime binding"
    );
    assert_eq!(
        std::env::var(INTENTIONAL_OVERRIDE_ENV).as_deref(),
        Ok("preserved"),
        "the explicit test override was not replayed"
    );

    std::fs::write(PathBuf::from(marker), b"authority-order-proven")
        .expect("write authority-order marker");
}

#[test]
fn cleanup_worker() {}

#[test]
#[serial]
fn spawned_child_observes_case_insensitive_authority_order() {
    let root = tempdir().expect("temporary authority root");
    let repository = root.path().join("repository");
    std::fs::create_dir_all(&repository).expect("create repository");
    let marker = root.path().join("authority-order.marker");
    let git_date = "1600000000 +0000";
    let daemon_url = "http://127.0.0.1:9";

    let _ambient_git = EnvVarGuard::set(AMBIENT_GIT_DIR, OsStr::new("ambient-git-authority"));
    let _ambient_kin =
        EnvVarGuard::set(AMBIENT_KIN_BUCKET, OsStr::new("ambient-production-bucket"));
    let _ambient_dyld =
        EnvVarGuard::set(AMBIENT_DYLD_INJECTION, OsStr::new("ambient-dyld-injection"));
    let _ambient_ld = EnvVarGuard::set(AMBIENT_LD_INJECTION, OsStr::new("ambient-ld-injection"));

    let runtime = common::IsolatedDaemonRuntime::with_cleanup_command_for_test(
        &repository,
        std::env::current_exe().expect("current test executable"),
        vec![
            OsString::from("--exact"),
            OsString::from("cleanup_worker"),
            OsString::from("--nocapture"),
        ],
        Vec::new(),
        Duration::from_secs(5),
    );
    let expected_registry = runtime.registry_path().to_path_buf();
    let mut command =
        runtime.process_command_for_test(std::env::current_exe().expect("current test executable"));
    command
        .args(["--exact", "authority_order_worker", "--nocapture"])
        .env(WORKER_ENV, "1")
        .env(MARKER_ENV, &marker)
        .env(EXPECTED_REGISTRY_ENV, &expected_registry)
        .env(EXPECTED_GIT_DATE_ENV, git_date)
        .env(EXPECTED_DAEMON_URL_ENV, daemon_url)
        .env(INTENTIONAL_OVERRIDE_ENV, "preserved")
        .env(COMMAND_GIT_WORK_TREE, "command-git-authority")
        .env(COMMAND_GIT_CONFIG_COUNT, "1")
        .env(COMMAND_KIN_BUCKET, "command-production-bucket")
        .env(COMMAND_LAST_VFS_DIR, "command-vfs-authority")
        .env(COMMAND_DYLD_INJECTION, "command-dyld-injection")
        .env(COMMAND_LD_INJECTION, "command-ld-injection")
        .env(COMMAND_REGISTRY, "command-registry-authority")
        .env(COMMAND_OWNER_TOKEN, "hostile-owner")
        .env(COMMAND_GIT_CONFIG_NOSYSTEM, "0")
        .fixture_git_commit_dates(git_date)
        .fixture_daemon_url(daemon_url);

    let output = command.output().expect("run spawned authority worker");
    assert!(
        output.status.success(),
        "spawned authority worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&marker).expect("read authority-order marker"),
        b"authority-order-proven"
    );
}
