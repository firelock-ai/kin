// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

#[test]
#[serial]
fn locate_json_keeps_tracing_warnings_off_stdout() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(".")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let kindb_dir = repo.path().join(".kin/kindb");
    fs::write(kindb_dir.join("graph.kvec"), []).expect("write stale vector index");
    fs::write(
        kindb_dir.join("graph.kvec.meta.json"),
        serde_json::json!({
            "version": 1,
            "graph_root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "dimensions": 1,
            "indexed": 1
        })
        .to_string(),
    )
    .expect("write stale vector metadata");

    let locate = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .current_dir(repo.path())
        .output()
        .expect("run kin locate");
    assert!(
        locate.status.success(),
        "kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );

    let stdout = String::from_utf8_lossy(&locate.stdout);
    let stderr = String::from_utf8_lossy(&locate.stderr);

    assert!(
        !stdout.contains("vector index") && !stdout.contains("stale"),
        "warning leaked to stdout: {stdout}"
    );
    serde_json::from_slice::<serde_json::Value>(&locate.stdout)
        .expect("locate --json stdout should remain parseable");
}

#[test]
#[serial]
fn locate_autostarts_daemon_when_available() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(".")
        .arg("--no-lsp")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let daemon_bin = PathBuf::from(env!("CARGO_BIN_EXE_kin"))
        .parent()
        .expect("kin binary dir")
        .join("kin-daemon");
    assert!(daemon_bin.exists(), "kin-daemon test binary path");
    let daemon_dir = daemon_bin.parent().expect("daemon bin dir");
    let mut path_entries =
        env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    path_entries.insert(0, daemon_dir.to_path_buf());
    let path = env::join_paths(path_entries).expect("join PATH");

    let locate = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .env("PATH", path)
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .current_dir(repo.path())
        .output()
        .expect("run kin locate");
    assert!(
        locate.status.success(),
        "kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );

    let daemon_port = repo.path().join(".kin/daemon.port");
    let daemon_pid = repo.path().join(".kin/daemon.pid");
    assert!(daemon_port.exists(), "locate did not auto-start a daemon");
    assert!(daemon_pid.exists(), "locate did not record daemon pid");

    #[cfg(unix)]
    if let Some(pid) = fs::read_to_string(&daemon_pid)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
    {
        unsafe {
            let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
}

#[test]
#[serial]
fn locate_can_require_daemon_instead_of_falling_back_to_local() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(".")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let locate = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .env("KIN_DAEMON_URL", "http://127.0.0.1:9")
        .env("KIN_LOCATE_REQUIRE_DAEMON", "1")
        .current_dir(repo.path())
        .output()
        .expect("run kin locate");

    assert!(
        !locate.status.success(),
        "kin locate unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );

    let stderr = String::from_utf8_lossy(&locate.stderr);
    assert!(
        stderr.contains("daemon locate failed and local fallback is disabled"),
        "missing daemon-required failure message: {stderr}"
    );
}

#[test]
#[serial]
fn locate_ref_can_resolve_historical_files_from_the_public_cli() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.py"),
        "def legacy_handler(value):\n    return value + 1\n",
    )
    .expect("write initial source");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(".")
        .arg("--no-lsp")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let log = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("log")
        .arg("-n")
        .arg("1")
        .current_dir(repo.path())
        .output()
        .expect("run kin log");
    assert!(
        log.status.success(),
        "kin log failed: stdout={} stderr={}",
        String::from_utf8_lossy(&log.stdout),
        String::from_utf8_lossy(&log.stderr)
    );
    let init_head = String::from_utf8_lossy(&log.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("Head: "))
        .expect("log should print branch head")
        .to_string();

    fs::remove_file(repo.path().join("src/lib.py")).expect("remove old source");
    fs::write(
        repo.path().join("src/current.py"),
        "def current_handler(payload):\n    return payload * 2\n",
    )
    .expect("write renamed source");

    let commit = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("commit")
        .arg("-m")
        .arg("rename handler")
        .arg("--quiet")
        .current_dir(repo.path())
        .output()
        .expect("run kin commit");
    assert!(
        commit.status.success(),
        "kin commit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );

    let query = "Investigate legacy_handler in src/lib.py";

    let historical = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg("--ref")
        .arg(&init_head)
        .arg(query)
        .current_dir(repo.path())
        .output()
        .expect("run historical kin locate");
    assert!(
        historical.status.success(),
        "historical kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&historical.stdout),
        String::from_utf8_lossy(&historical.stderr)
    );

    let current = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg(query)
        .current_dir(repo.path())
        .output()
        .expect("run current kin locate");
    assert!(
        current.status.success(),
        "current kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&current.stdout),
        String::from_utf8_lossy(&current.stderr)
    );

    let historical_json: serde_json::Value =
        serde_json::from_slice(&historical.stdout).expect("parse historical locate JSON");
    let current_json: serde_json::Value =
        serde_json::from_slice(&current.stdout).expect("parse current locate JSON");

    let historical_paths: Vec<_> = historical_json["files"]
        .as_array()
        .expect("historical files array")
        .iter()
        .filter_map(|entry| entry.get("path").and_then(|path| path.as_str()))
        .collect();
    let current_paths: Vec<_> = current_json["files"]
        .as_array()
        .expect("current files array")
        .iter()
        .filter_map(|entry| entry.get("path").and_then(|path| path.as_str()))
        .collect();

    assert!(
        historical_paths.iter().any(|path| *path == "src/lib.py"),
        "historical locate should surface src/lib.py, got {historical_paths:?}"
    );
    assert!(
        current_paths.iter().all(|path| *path != "src/lib.py"),
        "current locate should not surface removed src/lib.py, got {current_paths:?}"
    );
}

#[test]
#[serial]
fn locate_ref_hydrates_missing_imported_git_history_on_demand() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    fs::write(
        repo.path().join("src/lib.py"),
        "def legacy_handler(value):\n    return value + 1\n",
    )
    .expect("write initial source");
    let add_initial = Command::new("git")
        .args(["add", "."])
        .current_dir(repo.path())
        .output()
        .expect("git add initial");
    assert!(add_initial.status.success());
    let commit_initial = Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(repo.path())
        .output()
        .expect("git commit initial");
    assert!(commit_initial.status.success());
    let old_sha = String::from_utf8_lossy(
        &Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo.path())
            .output()
            .expect("git rev-parse initial")
            .stdout,
    )
    .trim()
    .to_string();

    fs::remove_file(repo.path().join("src/lib.py")).expect("remove old source");
    fs::write(
        repo.path().join("src/current.py"),
        "def current_handler(payload):\n    return payload * 2\n",
    )
    .expect("write renamed source");
    let add_current = Command::new("git")
        .args(["add", "."])
        .current_dir(repo.path())
        .output()
        .expect("git add current");
    assert!(add_current.status.success());
    let commit_current = Command::new("git")
        .args(["commit", "-m", "rename handler"])
        .current_dir(repo.path())
        .output()
        .expect("git commit current");
    assert!(commit_current.status.success());

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(".")
        .arg("--no-lsp")
        .arg("--git-history")
        .arg("off")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let historical = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("locate")
        .arg("--json")
        .arg("--ref")
        .arg(format!("git:{old_sha}"))
        .arg("Investigate legacy_handler in src/lib.py")
        .env("KIN_NO_DAEMON", "1")
        .current_dir(repo.path())
        .output()
        .expect("run historical kin locate");
    assert!(
        historical.status.success(),
        "historical kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&historical.stdout),
        String::from_utf8_lossy(&historical.stderr)
    );

    let historical_json: serde_json::Value =
        serde_json::from_slice(&historical.stdout).expect("parse historical locate json");
    let files = historical_json["files"]
        .as_array()
        .expect("files array")
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .collect::<Vec<_>>();
    assert!(
        files.iter().any(|path| *path == "src/lib.py"),
        "historical locate should surface hydrated imported Git file, got {:?}",
        files
    );
}
