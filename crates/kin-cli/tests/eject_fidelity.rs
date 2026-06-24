// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end conviction tests for the "you can always leave" contract.
//!
//! These exercise the real Kin lifecycle through the public CLI and the daemon
//! runtime — `kin init`, an edit through the reconcile path, `kin commit`,
//! `kin eject --revert-files`, and `kin git export` — then prove, with no Kin
//! tooling present, that:
//!
//! 1. `kin eject --revert-files` restores the working tree byte-for-byte to its
//!    pre-init state, leaves `.git` and Git history untouched, and the restored
//!    tree still compiles and its tests pass under a plain toolchain.
//! 2. `kin git export` produces a plain Git repository whose history and file
//!    contents are usable with stock `git` and `rustc` alone. The semantic graph
//!    (entities, relations, reviews, provenance, work items, annotations,
//!    verification links, sessions, intents, and the per-change spec/evidence/
//!    risk metadata) is intentionally NOT round-tripped — Git has no
//!    representation for it. Code and Git history travel; the semantic layer is
//!    what Kin adds on top.
//! 3. A partial or corrupt snapshot makes `kin eject --revert-files` fail loudly
//!    with zero side effects, rather than silently restoring fewer files than
//!    promised and then deleting the graph.

use serial_test::serial;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::tempdir;

mod common;

const README: &str = "# eject fidelity demo\n\nA tiny repo used to prove the eject contract.\n";

const LIB_V0: &str = "pub fn greet(name: &str) -> String {\n\
\x20   format!(\"hello, {name}\")\n\
}\n\
\n\
#[cfg(test)]\n\
mod tests {\n\
\x20   use super::greet;\n\
\n\
\x20   #[test]\n\
\x20   fn greet_includes_name() {\n\
\x20       assert_eq!(greet(\"kin\"), \"hello, kin\");\n\
\x20   }\n\
}\n";

const LIB_V1: &str = "pub fn greet(name: &str) -> String {\n\
\x20   format!(\"hello, {name}!\")\n\
}\n\
\n\
pub fn farewell(name: &str) -> String {\n\
\x20   format!(\"goodbye, {name}\")\n\
}\n\
\n\
#[cfg(test)]\n\
mod tests {\n\
\x20   use super::{farewell, greet};\n\
\n\
\x20   #[test]\n\
\x20   fn greet_includes_name() {\n\
\x20       assert_eq!(greet(\"kin\"), \"hello, kin!\");\n\
\x20   }\n\
\n\
\x20   #[test]\n\
\x20   fn farewell_includes_name() {\n\
\x20       assert_eq!(farewell(\"kin\"), \"goodbye, kin\");\n\
\x20   }\n\
}\n";

const MAIN_RS: &str = "fn add(a: i32, b: i32) -> i32 {\n\
\x20   a + b\n\
}\n\
\n\
fn main() {\n\
\x20   println!(\"{}\", add(2, 2));\n\
}\n\
\n\
#[cfg(test)]\n\
mod tests {\n\
\x20   use super::add;\n\
\n\
\x20   #[test]\n\
\x20   fn add_works() {\n\
\x20       assert_eq!(add(2, 2), 4);\n\
\x20   }\n\
}\n";

/// Annotations that live only in the semantic graph and are intentionally NOT
/// carried by `kin git export` (Git has no representation for them).
const EXPORT_OUT_OF_SCOPE: &[&str] = &[
    "entities and relations",
    "reviews, decisions, notes, discussions",
    "provenance: actors, delegations, approvals, audit events",
    "work items and annotations",
    "verification: tests, assertions, runs, coverage, contracts",
    "sessions and intents",
    "per-change spec_link, evidence, risk_summary, entity/relation deltas",
];

fn kin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kin"));
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    cmd
}

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

fn git_stdout(repo: &Path, args: &[&str]) -> String {
    String::from_utf8_lossy(&git(repo, args).stdout)
        .trim()
        .to_string()
}

fn run_kin(repo: &Path, args: &[&str]) -> std::process::Output {
    let out = kin()
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("kin {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

/// Seed a git repository with a tiny, self-contained Rust project and commit it.
fn seed_repo(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create src dir");
    fs::write(repo.join("README.md"), README).expect("write README");
    fs::write(repo.join("src/lib.rs"), LIB_V0).expect("write lib.rs");
    fs::write(repo.join("src/main.rs"), MAIN_RS).expect("write main.rs");

    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "kin@example.com"]);
    git(repo, &["config", "user.name", "Kin"]);
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", "seed project"]);
}

/// rustc that cargo handed this test process, falling back to PATH.
fn rustc() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string())
}

/// Compile `src` as a test harness with a plain toolchain and run it.
/// Proves the file builds and its `#[test]`s pass with no Kin tooling present.
fn assert_builds_and_tests_pass(src: &Path, out_bin: &Path) {
    let compile = Command::new(rustc())
        .args(["--edition", "2021", "--test"])
        .arg(src)
        .arg("-o")
        .arg(out_bin)
        .output()
        .expect("spawn rustc --test");
    assert!(
        compile.status.success(),
        "rustc --test {} failed: {}",
        src.display(),
        String::from_utf8_lossy(&compile.stderr),
    );
    let run = Command::new(out_bin).output().expect("run test binary");
    assert!(
        run.status.success(),
        "tests in {} failed under a plain toolchain: stdout={} stderr={}",
        src.display(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
}

/// Compile `src` as a normal program and run it, returning trimmed stdout.
fn build_and_run_main(src: &Path, out_bin: &Path) -> String {
    let compile = Command::new(rustc())
        .args(["--edition", "2021"])
        .arg(src)
        .arg("-o")
        .arg(out_bin)
        .output()
        .expect("spawn rustc");
    assert!(
        compile.status.success(),
        "rustc {} failed: {}",
        src.display(),
        String::from_utf8_lossy(&compile.stderr),
    );
    let run = Command::new(out_bin).output().expect("run program");
    assert!(
        run.status.success(),
        "running {} failed: {}",
        src.display(),
        String::from_utf8_lossy(&run.stderr),
    );
    String::from_utf8_lossy(&run.stdout).trim().to_string()
}

fn has_eject_backup(repo: &Path) -> bool {
    fs::read_dir(repo)
        .map(|rd| {
            rd.filter_map(|e| e.ok()).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".kin-backup-eject-")
            })
        })
        .unwrap_or(false)
}

fn eject_backup_dir(repo: &Path) -> Option<PathBuf> {
    fs::read_dir(repo)
        .ok()?
        .filter_map(|e| e.ok())
        .find_map(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".kin-backup-eject-")
                .then(|| e.path())
        })
}

fn write_proof(name: &str, value: &serde_json::Value) {
    let dir = std::env::temp_dir().join("kin-eject-fidelity-proof");
    if fs::create_dir_all(&dir).is_ok() {
        let _ = fs::write(
            dir.join(name),
            serde_json::to_string_pretty(value).unwrap_or_default(),
        );
        eprintln!(
            "[eject-fidelity] proof written to {}",
            dir.join(name).display()
        );
    }
}

/// Wait until the repo's daemon has fully idle-exited (its endpoint files are
/// gone). `kin eject` only sends a best-effort SIGTERM and does not wait, so a
/// still-live daemon from a preceding `kin commit` could recreate `.kin/` right
/// after eject removes the directory. Quiescing first makes the eject assertion
/// deterministic — the same wait the daemon-autostart locate test relies on.
fn wait_for_daemon_gone(repo: &Path) {
    let pid = repo.join(".kin/daemon.pid");
    let port = repo.join(".kin/daemon.port");
    for _ in 0..150 {
        if !pid.exists() && !port.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `kin eject --revert-files` restores the working tree byte-for-byte to its
/// pre-init state, leaves `.git`/Git history untouched, and the restored tree
/// still builds and tests green under a plain toolchain.
#[test]
#[serial]
fn eject_revert_files_is_byte_faithful_and_leaves_git_intact() {
    let work = tempdir().expect("temp work dir");
    let repo = work.path().join("repo");
    let build = work.path().join("build");
    fs::create_dir_all(&build).expect("create build dir");

    seed_repo(&repo);
    let head_before = git_stdout(&repo, &["rev-parse", "HEAD"]);

    // Capture the exact pre-init bytes of every tracked file.
    let readme0 = fs::read(repo.join("README.md")).unwrap();
    let lib0 = fs::read(repo.join("src/lib.rs")).unwrap();
    let main0 = fs::read(repo.join("src/main.rs")).unwrap();

    // Adopt Kin.
    run_kin(&repo, &["init", "."]);
    assert!(repo.join(".kin/snapshot/manifest.json").exists());

    // Edit through the real reconcile path, then commit through the daemon.
    fs::write(repo.join("src/lib.rs"), LIB_V1).expect("edit lib.rs");
    std::thread::sleep(Duration::from_millis(400));
    run_kin(
        &repo,
        &["commit", "-m", "edit greet and add farewell", "--quiet"],
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        LIB_V1.as_bytes(),
        "edit must be present before eject",
    );

    // Quiesce the commit's daemon before leaving, so its endpoint files cannot
    // reappear under .kin/ after eject removes the directory.
    wait_for_daemon_gone(&repo);

    // Leave.
    run_kin(&repo, &["eject", "--revert-files", "--yes"]);

    // Kin is gone.
    assert!(!repo.join(".kin").exists(), ".kin/ must be removed");

    // Working tree is byte-for-byte the pre-init state.
    assert_eq!(
        fs::read(repo.join("README.md")).unwrap(),
        readme0,
        "README.md not byte-faithful"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        lib0,
        "src/lib.rs not restored to pre-init bytes",
    );
    assert_eq!(
        fs::read(repo.join("src/main.rs")).unwrap(),
        main0,
        "src/main.rs not byte-faithful"
    );

    // The pre-eject edit is recoverable from the mandatory backup (no data loss).
    let backup = eject_backup_dir(&repo).expect("eject must create a backup dir");
    assert_eq!(
        fs::read(backup.join("src/lib.rs")).unwrap(),
        LIB_V1.as_bytes(),
        "backup must hold the pre-eject edited content",
    );

    // Git history and .git are untouched: HEAD unchanged, tracked tree clean.
    assert!(repo.join(".git").is_dir(), ".git must remain intact");
    assert_eq!(
        git_stdout(&repo, &["rev-parse", "HEAD"]),
        head_before,
        "eject must not rewrite Git history",
    );
    let porcelain = git_stdout(&repo, &["status", "--porcelain", "--untracked-files=no"]);
    assert!(
        porcelain.is_empty(),
        "restored tree must match the committed Git state, got dirty: {porcelain}",
    );
    git(&repo, &["fsck", "--no-progress"]);

    // The restored tree builds and tests pass with stock rustc — no Kin present.
    assert_builds_and_tests_pass(&repo.join("src/lib.rs"), &build.join("lib_test"));
    assert_eq!(
        build_and_run_main(&repo.join("src/main.rs"), &build.join("main_bin")),
        "4",
        "restored program must run under a plain toolchain",
    );

    write_proof(
        "eject_byte_faithful.json",
        &serde_json::json!({
            "scenario": "init -> edit -> commit -> eject --revert-files",
            "kin_removed": true,
            "bytes_faithful": ["README.md", "src/lib.rs", "src/main.rs"],
            "git_head_before": head_before,
            "git_head_after": git_stdout(&repo, &["rev-parse", "HEAD"]),
            "tracked_tree_clean_after_eject": true,
            "pre_eject_edit_recoverable_from_backup": true,
            "restored_tree_builds_and_tests_pass": true,
        }),
    );
}

/// `kin git export` yields a plain Git repo usable with stock git + rustc, and
/// carries file contents and commit history but not the semantic graph.
#[test]
#[serial]
fn git_export_round_trips_to_plain_git() {
    let work = tempdir().expect("temp work dir");
    let repo = work.path().join("repo");
    let export = work.path().join("exported.git");
    let checkout = work.path().join("checkout");
    let build = work.path().join("build");
    fs::create_dir_all(&build).expect("create build dir");

    seed_repo(&repo);
    run_kin(&repo, &["init", "."]);

    fs::write(repo.join("src/lib.rs"), LIB_V1).expect("edit lib.rs");
    std::thread::sleep(Duration::from_millis(400));
    run_kin(
        &repo,
        &["commit", "-m", "edit greet and add farewell", "--quiet"],
    );

    // Export Kin's semantic history out to a plain Git repository.
    run_kin(
        &repo,
        &["git", "export", "--output", export.to_str().unwrap()],
    );
    assert!(export.exists(), "export must create a Git repository");
    assert!(
        !export.join(".kin").exists(),
        "exported repo must contain no Kin metadata",
    );

    // Stock git can read the exported history with no Kin tooling.
    let commits = git_stdout(&export, &["rev-list", "--count", "main"]);
    assert!(
        commits.parse::<u32>().unwrap_or(0) >= 1,
        "exported history must contain commits, got {commits}",
    );
    let log = git_stdout(&export, &["log", "--format=%s", "main"]);
    assert!(
        log.contains("edit greet and add farewell"),
        "exported history must carry the commit message, got: {log}",
    );

    // Exact committed bytes survived the round-trip.
    let exported_lib = git(&export, &["show", "main:src/lib.rs"]).stdout;
    assert_eq!(
        exported_lib,
        LIB_V1.as_bytes(),
        "exported src/lib.rs must match committed bytes"
    );
    let exported_main = git(&export, &["show", "main:src/main.rs"]).stdout;
    assert_eq!(
        exported_main,
        MAIN_RS.as_bytes(),
        "exported src/main.rs must match committed bytes"
    );

    // A stock clone is fully usable: build + tests pass with no Kin present.
    let clone = Command::new("git")
        .args([
            "clone",
            "-q",
            export.to_str().unwrap(),
            checkout.to_str().unwrap(),
        ])
        .output()
        .expect("git clone export");
    assert!(
        clone.status.success(),
        "plain git clone of the export failed: {}",
        String::from_utf8_lossy(&clone.stderr),
    );
    git(&checkout, &["checkout", "-q", "main"]);
    assert!(
        !checkout.join(".kin").exists(),
        "clone must contain no Kin metadata"
    );
    assert_eq!(
        fs::read(checkout.join("src/lib.rs")).unwrap(),
        LIB_V1.as_bytes(),
        "cloned tree must hold the exported edit",
    );
    assert_builds_and_tests_pass(&checkout.join("src/lib.rs"), &build.join("clone_lib_test"));
    assert_eq!(
        build_and_run_main(&checkout.join("src/main.rs"), &build.join("clone_main_bin")),
        "4",
        "exported program must run under a plain toolchain",
    );

    write_proof(
        "git_export_round_trip.json",
        &serde_json::json!({
            "scenario": "init -> edit -> commit -> git export -> plain git clone",
            "exported_commit_count": commits,
            "commit_messages_round_tripped": true,
            "file_bytes_round_tripped": ["src/lib.rs", "src/main.rs"],
            "clone_builds_and_tests_pass_without_kin": true,
            "semantic_graph_out_of_scope": EXPORT_OUT_OF_SCOPE,
        }),
    );
}

/// A partial/corrupt snapshot must make `kin eject --revert-files` fail loudly
/// with zero side effects — no partial restore, `.kin/` preserved, no backup.
#[test]
#[serial]
fn eject_fails_loud_on_partial_snapshot() {
    let work = tempdir().expect("temp work dir");
    let repo = work.path().join("repo");

    seed_repo(&repo);
    run_kin(&repo, &["init", "."]);

    let manifest_path = repo.join(".kin/snapshot/manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let declared = manifest["file_count"].as_u64().unwrap_or(0);
    assert!(declared > 0, "init snapshot must declare a file_count");

    // Corrupt the snapshot: drop a file the manifest still counts.
    let dropped = repo.join(".kin/snapshot/src/lib.rs");
    assert!(dropped.exists(), "snapshot should contain src/lib.rs");
    fs::remove_file(&dropped).unwrap();

    let working_lib_before = fs::read(repo.join("src/lib.rs")).unwrap();

    // Eject must refuse, loudly.
    let out = kin()
        .args(["eject", "--revert-files", "--yes"])
        .current_dir(&repo)
        .output()
        .expect("spawn kin eject");
    assert!(
        !out.status.success(),
        "eject must fail on an incomplete snapshot: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("integrity") && stderr.contains("incomplete snapshot"),
        "failure must name the integrity gap, got: {stderr}",
    );

    // Zero side effects: graph preserved, working file untouched, no backup.
    assert!(
        repo.join(".kin").exists(),
        ".kin/ must be preserved on a failed revert"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        working_lib_before,
        "no working file may be touched on a failed revert",
    );
    assert!(
        !has_eject_backup(&repo),
        "no backup dir may be created when failing fast"
    );

    write_proof(
        "eject_partial_snapshot_fails_loud.json",
        &serde_json::json!({
            "scenario": "init -> corrupt snapshot -> eject --revert-files",
            "manifest_file_count": declared,
            "exit_nonzero": true,
            "error_names_integrity_gap": true,
            "kin_dir_preserved": true,
            "working_tree_untouched": true,
            "no_backup_created": true,
        }),
    );
}
