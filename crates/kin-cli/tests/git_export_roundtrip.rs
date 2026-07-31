// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end conviction test for the migration-out half of "you can always
//! leave": `kin git export`.
//!
//! It drives the real lifecycle through the public CLI and the daemon runtime —
//! a repository whose history Kin admitted exactly at `kin init`, then
//! `kin git export` — and proves, with no Kin tooling present, that the export
//! is a plain Git repository whose history and file contents are usable with
//! stock `git` and `rustc` alone: a stock `git clone` of the export builds and
//! its tests pass.
//!
//! The exported change is authored in the migration source rather than through
//! `kin commit`, which is fail-closed on repository-v6 (see `kin capabilities
//! --json`). What is under test is the export half of "you can always leave":
//! every byte it carries comes from admitted repository authority, so the
//! seam that authored the change does not change what export must prove.
//!
//! The semantic graph (entities, relations, reviews, provenance, work items,
//! annotations, verification links, sessions, intents, and the per-change
//! spec/evidence/risk metadata) is intentionally NOT round-tripped — Git has no
//! representation for it. Code and Git history travel; the semantic layer is
//! what Kin adds on top.

use serial_test::serial;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

const README: &str =
    "# git export round-trip demo\n\nA tiny repo used to prove the export contract.\n";

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

fn kin(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut cmd = runtime.kin_command();
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
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

fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let out = kin(runtime)
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

    git(repo, &["init", "-q", "--initial-branch=main"]);
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

fn write_proof(name: &str, value: &serde_json::Value) {
    let dir = std::env::temp_dir().join("kin-eject-fidelity-proof");
    if fs::create_dir_all(&dir).is_ok() {
        let _ = fs::write(
            dir.join(name),
            serde_json::to_string_pretty(value).unwrap_or_default(),
        );
        eprintln!(
            "[git-export-roundtrip] proof written to {}",
            dir.join(name).display()
        );
    }
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
    fs::write(repo.join("src/lib.rs"), LIB_V1).expect("edit lib.rs");
    git(&repo, &["add", "."]);
    git(
        &repo,
        &["commit", "-q", "-m", "edit greet and add farewell"],
    );
    let runtime = common::IsolatedDaemonRuntime::new(&repo);

    // Admit the complete exact history as graph-owned repository authority.
    run_kin(&runtime, &repo, &["init", "."]);

    // Export Kin's semantic history out to a plain Git repository.
    run_kin(
        &runtime,
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
        "exported src/lib.rs must match committed bytes",
    );
    let exported_main = git(&export, &["show", "main:src/main.rs"]).stdout;
    assert_eq!(
        exported_main,
        MAIN_RS.as_bytes(),
        "exported src/main.rs must match committed bytes",
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
        "clone must contain no Kin metadata",
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
            "scenario": "exact git history -> init -> git export -> plain git clone",
            "exported_commit_count": commits,
            "commit_messages_round_tripped": true,
            "file_bytes_round_tripped": ["src/lib.rs", "src/main.rs"],
            "clone_builds_and_tests_pass_without_kin": true,
            "semantic_graph_out_of_scope": EXPORT_OUT_OF_SCOPE,
        }),
    );
}
