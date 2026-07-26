// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serial_test::serial;
use std::env;
use std::fs;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;
use tempfile::tempdir;

mod common;

use common::Command;

#[cfg(unix)]
fn wait_for_pid_exit(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("process {pid} did not exit");
}

fn kin_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kin"));
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    cmd
}

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

    let init = kin_command()
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

    let locate = kin_command()
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

    // The whole stdout stream must be ONE JSON document: a tracing warning
    // interleaved before/inside/after it fails the parse. Degraded-state facts
    // are allowed on stdout only as structured fields of that document
    // (`semantic_coverage`, `degradations`), never as free-text lines.
    assert!(
        stdout.trim_start().starts_with('{'),
        "stdout must begin with the JSON document, got: {stdout}"
    );
    serde_json::from_slice::<serde_json::Value>(&locate.stdout)
        .expect("locate --json stdout should remain parseable (no interleaved log lines)");
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

    let init = kin_command()
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

    let daemon_bin = common::fresh_daemon_bin();
    assert!(daemon_bin.exists(), "kin-daemon test binary path");
    let daemon_dir = daemon_bin.parent().expect("daemon bin dir");
    let mut path_entries =
        env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    path_entries.insert(0, daemon_dir.to_path_buf());
    let path = env::join_paths(path_entries).expect("join PATH");

    let locate = kin_command()
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .env("PATH", path)
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
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
        wait_for_pid_exit(pid);
        assert!(
            !daemon_pid.exists() && !daemon_port.exists(),
            "idle daemon should remove endpoint files"
        );
    }
}

#[test]
#[serial]
fn locate_requires_daemon_by_default() {
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

    let init = kin_command()
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

    let locate = kin_command()
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .env("KIN_DAEMON_URL", "http://127.0.0.1:9")
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
        stderr.contains("daemon locate failed"),
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

    let init = kin_command()
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

    let log = kin_command()
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

    // Sleep briefly to ensure notify events propagate to the daemon before we run commit
    std::thread::sleep(Duration::from_millis(250));

    let commit = kin_command()
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

    let historical = kin_command()
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

    let current = kin_command()
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
        historical_paths.contains(&"src/lib.py"),
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
        .args([
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-m",
            "initial",
        ])
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
        .args([
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-m",
            "rename handler",
        ])
        .current_dir(repo.path())
        .output()
        .expect("git commit current");
    assert!(commit_current.status.success());

    let init = kin_command()
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

    let historical = kin_command()
        .arg("locate")
        .arg("--json")
        .arg("--ref")
        .arg(format!("git:{old_sha}"))
        .arg("Investigate legacy_handler in src/lib.py")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
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
        files.contains(&"src/lib.py"),
        "historical locate should surface hydrated imported Git file, got {:?}",
        files
    );
}

/// Full-history import admits every reachable Git change into graph authority.
/// Ref-scoped locate must resolve both the tip and the root without consulting
/// Git or fabricating missing ancestry.
#[test]
#[serial]
fn locate_ref_resolves_tip_and_root_after_full_history_init() {
    let repo = tempdir().expect("temp repo");

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

    // Neutralize any globally-configured hooks so this acceptance fixture stays
    // self-contained.
    let _ = Command::new("git")
        .args(["config", "core.hooksPath", "/dev/null"])
        .current_dir(repo.path())
        .output();

    let commit = |message: &str, seq: u32| {
        // Distinct, strictly increasing dates so the truncation window is
        // time-ordered and deterministic (the fixtures gotcha: equal timestamps
        // make the window oid-ordered instead, so "out of window" is ambiguous).
        let date = format!("{} +0000", 1_600_000_000 + seq);
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=kin-ci",
                "-c",
                "user.email=ci@kin.dev",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                message,
            ])
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date)
            .current_dir(repo.path())
            .output()
            .expect("git commit");
        assert!(
            out.status.success(),
            "git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let rev_parse = |rev: &str| -> String {
        String::from_utf8_lossy(
            &Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(repo.path())
                .output()
                .expect("git rev-parse")
                .stdout,
        )
        .trim()
        .to_string()
    };

    // Commit 1 carries real content and is the reachable root.
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.py"),
        "def legacy_handler(value):\n    return value + 1\n",
    )
    .expect("write source");
    let add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo.path())
        .output()
        .expect("git add");
    assert!(add.status.success());
    commit("c1 initial", 1);
    let root_sha = rev_parse("HEAD");

    for seq in 2..=4u32 {
        commit(&format!("c{seq}"), seq);
    }
    let head_sha = rev_parse("HEAD");

    let init = kin_command()
        .arg("init")
        .arg(".")
        .arg("--no-lsp")
        .args(["--git-history", "full"])
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    // The tip resolves strictly from imported graph history.
    let head_locate = kin_command()
        .arg("locate")
        .arg("--json")
        .arg("--ref")
        .arg(format!("git:{head_sha}"))
        .arg("legacy_handler")
        .current_dir(repo.path())
        .output()
        .expect("run head-ref locate");
    assert!(
        head_locate.status.success(),
        "locate --ref git:<HEAD> failed after full import: stdout={} stderr={}",
        String::from_utf8_lossy(&head_locate.stdout),
        String::from_utf8_lossy(&head_locate.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&head_locate.stdout)
        .expect("HEAD-ref locate stdout should be valid JSON");

    // The root resolves from the same complete imported DAG.
    let root_locate = kin_command()
        .arg("locate")
        .arg("--json")
        .arg("--ref")
        .arg(format!("git:{root_sha}"))
        .arg("Investigate legacy_handler in src/lib.py")
        .current_dir(repo.path())
        .output()
        .expect("run root-ref locate");
    assert!(
        root_locate.status.success(),
        "locate --ref git:<root> failed: stdout={} stderr={}",
        String::from_utf8_lossy(&root_locate.stdout),
        String::from_utf8_lossy(&root_locate.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&root_locate.stdout)
        .expect("root-ref locate stdout should be valid JSON");
}
