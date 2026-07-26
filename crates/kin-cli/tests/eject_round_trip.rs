// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Eject conviction suite: "you can always leave".
//!
//! These tests drive the real `kin` binary end-to-end over a real Git repo to
//! prove the load-bearing adoption promise — a team can remove Kin any day and
//! be left with a plain, intact Git repository.
//!
//! What is proven here:
//! - `kin eject` (default) removes Kin and leaves every working file and the
//!   entire `.git` directory byte-for-byte intact.
//! - `kin eject --revert-files` restores the working tree to its exact pre-init
//!   bytes (a faithful round-trip), backs up the pre-eject files first, and
//!   leaves `.git` intact.
//! - A corrupt or partial snapshot fails loudly and mutates nothing — Kin never
//!   silently strands files.
//!
//! Honest scope: Kin may read Git at an explicit import boundary, but eject
//! never rewrites or restores the source Git repository. It snapshots the
//! working tree at init (excluding `.git`, `.kin*`, and ignored paths) and
//! restores those files only. These tests therefore assert `.git` is untouched
//! rather than re-imported.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Output;
use tempfile::tempdir;

mod common;

use common::Command;

/// Run a git command in `dir` and assert it succeeds.
fn git(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git command");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Run a git command in `dir` and return its exit status without asserting.
fn git_status_code(dir: &Path, args: &[&str]) -> i32 {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git command")
        .status
        .code()
        .unwrap_or(-1)
}

/// Run the real `kin` binary in `dir` with a fully hermetic environment:
/// an isolated registry file and the warm-init cache disabled, so the test
/// never touches `~/.kin` or any other global state.
fn run_kin(dir: &Path, registry: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .current_dir(dir)
        .env("KIN_REGISTRY_PATH", registry)
        .env("KIN_INIT_WARM_CACHE", "0")
        .output()
        .expect("run kin binary")
}

fn run_kin_ok(dir: &Path, registry: &Path, args: &[&str]) -> Output {
    let output = run_kin(dir, registry, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// `git rev-parse HEAD`.
fn head_sha(repo: &Path) -> String {
    String::from_utf8_lossy(&git(repo, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string()
}

/// The set of Git-tracked files mapped to their exact on-disk bytes. This is
/// the "original git checkout" baseline we round-trip against.
fn tracked_file_bytes(repo: &Path) -> BTreeMap<String, Vec<u8>> {
    let listing = git(repo, &["ls-files"]).stdout;
    let listing = String::from_utf8(listing).expect("git ls-files is utf-8 paths");
    let mut map = BTreeMap::new();
    for rel in listing.lines().filter(|line| !line.trim().is_empty()) {
        let bytes = fs::read(repo.join(rel)).unwrap_or_else(|e| panic!("read tracked {rel}: {e}"));
        map.insert(rel.to_string(), bytes);
    }
    assert!(!map.is_empty(), "seed repo should have tracked files");
    map
}

/// Build a small, real Git repo with text and binary content, all committed.
fn seed_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo dir");
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "kin@example.com"]);
    git(repo, &["config", "user.name", "Kin Test"]);
    git(repo, &["config", "commit.gpgsign", "false"]);

    fs::write(repo.join("README.md"), "# Demo\n\nHello, Kin.\n").unwrap();
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn greet(name: &str) -> String {\n    format!(\"hi {name}\")\n}\n",
    )
    .unwrap();
    fs::write(
        repo.join("src/main.rs"),
        "fn main() {\n    println!(\"{}\", demo::greet(\"world\"));\n}\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::write(repo.join("docs/guide.md"), "Guide.\n\n- one\n- two\n").unwrap();

    // A binary file with non-UTF-8 bytes proves byte-fidelity beyond text.
    fs::create_dir_all(repo.join("assets")).unwrap();
    let mut blob: Vec<u8> = (0u8..=255).collect();
    blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x10]);
    fs::write(repo.join("assets/blob.bin"), &blob).unwrap();

    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "seed repo"]);
    git(repo, &["branch", "-M", "main"]);
}

/// Assert `.git` is structurally intact and on the same commit as `before`.
fn assert_git_intact(repo: &Path, before_head: &str) {
    assert_eq!(
        head_sha(repo),
        before_head,
        "HEAD must be unchanged — Kin never rewrites Git history"
    );
    assert_eq!(
        git_status_code(repo, &["fsck", "--full", "--strict"]),
        0,
        "git fsck must pass — .git must be untouched and intact"
    );
    // The commit and its log are still readable as a plain Git repo.
    let log = git(repo, &["log", "--oneline"]).stdout;
    assert!(
        String::from_utf8_lossy(&log).contains("seed repo"),
        "commit history must survive eject"
    );
}

/// Default `kin eject` removes Kin and leaves the working tree and `.git`
/// byte-for-byte intact.
#[test]
fn default_eject_preserves_git_history_and_working_tree() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_repo(&repo);

    let head_before = head_sha(&repo);
    let bytes_before = tracked_file_bytes(&repo);

    run_kin_ok(&repo, &registry, &["init", "--no-lsp", "."]);
    assert!(repo.join(".kin").is_dir(), "init must create .kin/");
    assert!(
        repo.join(".kin/snapshot/manifest.json").is_file(),
        "init must write the pre-init snapshot manifest"
    );

    run_kin_ok(&repo, &registry, &["eject"]);

    assert!(
        !repo.join(".kin").exists(),
        ".kin/ must be removed by eject"
    );
    assert!(
        no_kin_residue(&repo),
        "no .kin* residue may remain after eject"
    );
    assert_eq!(
        tracked_file_bytes(&repo),
        bytes_before,
        "every working file must be byte-identical after default eject"
    );
    assert_git_intact(&repo, &head_before);
    // A clean working tree: default eject creates no backup and no stray files.
    assert!(
        git(&repo, &["status", "--porcelain"]).stdout.is_empty(),
        "working tree must be clean after default eject"
    );
}

/// `kin eject --revert-files` restores the working tree to its exact pre-init
/// bytes even after edits, backs up the pre-eject files, and leaves `.git`
/// intact.
#[test]
fn revert_files_round_trips_to_pre_init_bytes() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_repo(&repo);

    let head_before = head_sha(&repo);
    let bytes_before = tracked_file_bytes(&repo);

    run_kin_ok(&repo, &registry, &["init", "--no-lsp", "."]);

    // Simulate real work done while living in Kin: edit tracked files on disk.
    let edited_lib = "pub fn greet(name: &str) -> String {\n    format!(\"HELLO {name}!!!\")\n}\n";
    fs::write(repo.join("src/lib.rs"), edited_lib).unwrap();
    fs::write(repo.join("README.md"), "# Demo (edited under Kin)\n").unwrap();
    assert_ne!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        bytes_before["src/lib.rs"],
        "precondition: file was actually edited"
    );

    run_kin_ok(&repo, &registry, &["eject", "--revert-files", "--yes"]);

    assert!(
        !repo.join(".kin").exists(),
        ".kin/ must be removed by eject"
    );
    assert_eq!(
        tracked_file_bytes(&repo),
        bytes_before,
        "every working file must round-trip to its exact pre-init bytes"
    );
    assert_git_intact(&repo, &head_before);

    // The pre-eject (edited) content is preserved in a backup, never lost.
    let backup = find_backup_dir(&repo).expect("a backup dir must be created");
    assert_eq!(
        fs::read_to_string(backup.join("src/lib.rs")).unwrap(),
        edited_lib,
        "backup must hold the pre-eject edited content"
    );
}

/// A missing snapshot directory fails loudly and mutates nothing.
#[test]
fn revert_files_fails_loud_on_missing_snapshot() {
    let (root, repo, registry) = init_repo();
    fs::remove_dir_all(repo.join(".kin/snapshot")).unwrap();
    let head_before = head_sha(&repo);
    let bytes_before = tracked_file_bytes(&repo);

    let out = run_kin(&repo, &registry, &["eject", "--revert-files", "--yes"]);
    assert_refused(&out, "No snapshot found");
    assert!(
        repo.join(".kin").exists(),
        ".kin/ must remain after refusal"
    );
    assert_eq!(tracked_file_bytes(&repo), bytes_before, "files untouched");
    assert_git_intact(&repo, &head_before);
    drop(root);
}

/// A missing manifest fails loudly and mutates nothing.
#[test]
fn revert_files_fails_loud_on_missing_manifest() {
    let (root, repo, registry) = init_repo();
    fs::remove_file(repo.join(".kin/snapshot/manifest.json")).unwrap();
    let head_before = head_sha(&repo);
    let bytes_before = tracked_file_bytes(&repo);

    let out = run_kin(&repo, &registry, &["eject", "--revert-files", "--yes"]);
    assert_refused(&out, "manifest missing");
    assert!(
        repo.join(".kin").exists(),
        ".kin/ must remain after refusal"
    );
    assert_eq!(tracked_file_bytes(&repo), bytes_before, "files untouched");
    assert_git_intact(&repo, &head_before);
    drop(root);
}

/// A truncated/partial snapshot (fewer files than the manifest records) fails
/// loudly before any mutation: nothing restored, nothing deleted, no backup.
#[test]
fn revert_files_fails_loud_on_partial_snapshot() {
    let (root, repo, registry) = init_repo();
    // Delete one file's snapshot copy so the manifest count no longer matches.
    fs::remove_file(repo.join(".kin/snapshot/src/lib.rs")).unwrap();
    let head_before = head_sha(&repo);
    let bytes_before = tracked_file_bytes(&repo);

    let out = run_kin(&repo, &registry, &["eject", "--revert-files", "--yes"]);
    assert_refused(&out, "incomplete");
    assert!(
        repo.join(".kin").exists(),
        ".kin/ must remain after refusal"
    );
    assert_eq!(tracked_file_bytes(&repo), bytes_before, "files untouched");
    assert!(
        find_backup_dir(&repo).is_none(),
        "no backup may be created when revert is refused pre-mutation"
    );
    assert_git_intact(&repo, &head_before);
    drop(root);
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// Seed a repo and run `kin init`, returning (tempdir, repo, registry).
/// The tempdir is returned so it outlives the test body.
fn init_repo() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_repo(&repo);
    run_kin_ok(&repo, &registry, &["init", "--no-lsp", "."]);
    (root, repo, registry)
}

/// Assert an eject invocation was refused (non-zero exit) with a clear message.
fn assert_refused(out: &Output, expect_substr: &str) {
    assert!(
        !out.status.success(),
        "eject should have failed but succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined
            .to_lowercase()
            .contains(&expect_substr.to_lowercase()),
        "error message should mention {expect_substr:?}; got: {combined}"
    );
}

/// True when no `.kin*` entry remains in the repo root.
fn no_kin_residue(repo: &Path) -> bool {
    fs::read_dir(repo)
        .expect("read repo dir")
        .filter_map(|e| e.ok())
        .all(|e| !e.file_name().to_string_lossy().starts_with(".kin"))
}

/// Find the single `.kin-backup-eject-*` directory, if any.
fn find_backup_dir(repo: &Path) -> Option<std::path::PathBuf> {
    fs::read_dir(repo)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(".kin-backup-eject-"))
                .unwrap_or(false)
        })
}
