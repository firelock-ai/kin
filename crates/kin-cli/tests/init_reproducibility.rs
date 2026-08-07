// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Two admissions of one Git repository must agree on admitted content.
//!
//! Kin's thesis is that the graph is the canonical substrate, so a receipt
//! field that names admitted content has to be a function of that content. If
//! two people admit the same commit of the same repository and get different
//! change ids and a different history root, nothing downstream — cross-repo
//! dedup, "is this the same tree?", a before/after equivalence check that can
//! tell a content regression apart from run-to-run drift — can be answered by
//! comparing hashes.
//!
//! The two admissions here read byte-identical Git object stores: the fixture
//! is built once and copied, so both runs see the same commit ids rather than
//! two commits that merely carry the same message. Whatever differs between the
//! receipts is therefore minted by Kin, not inherited from Git.
//!
//! Two groups of receipt fields are deliberately not asserted equal.
//!
//! `local_state` and `workspace_id` are per-workspace by design.
//! `RootBundle::has_same_replicated_truth` roots workspace, session, and
//! overlay authority under `local_state` and documents that it never
//! participates in replica truth equality. The second test below pins that
//! direction, so sharing content can never start meaning sharing local
//! authority.
//!
//! `ref_state`, `replication`, and `ref_log` are repository-*scoped* rather
//! than content-derived, and stay divergent here. `RepositoryRef`,
//! `ExternalChangeAlias`, and `GitExternalAuthority` each carry the
//! `RepositoryId` that `KinManifest::new` mints per admission, and the ref-log
//! projection additionally carries a random operation id and the wall-clock
//! commit time. Two admissions agree on those roots only by adopting one
//! repository identity, which is what `KinManifest::adopting` is for and which
//! two independent `kin init` runs deliberately do not do. Closing them is
//! FIR-2068's follow-up and needs a repository-identity decision plus a root
//! schema version, because every existing store validates that its recorded
//! root bundle recomputes from its persisted envelope.

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

/// Receipt fields that must be a function of admitted content alone.
const CONTENT_IDENTITY_FIELDS: &[&str] = &[
    "base_tree_hash",
    "workspace_tree_hash",
    "initial_change_id",
    "roots/history/hash",
    "roots/collaboration/hash",
];

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Build the one fixture both admissions read.
///
/// The rename in the second commit is load-bearing: artifact identity has to
/// survive a path change, so a derivation keyed on the current path would pass
/// a fixture without one and still be wrong.
fn seed_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    fs::write(
        path.join("lib.rs"),
        "pub fn helper() -> u32 {\n    7\n}\n\npub fn caller() -> u32 {\n    helper() + 1\n}\n",
    )
    .expect("write first revision");
    fs::write(path.join("README.md"), "first\n").expect("write readme");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "first"]);

    run_git(path, &["mv", "lib.rs", "renamed.rs"]);
    fs::write(path.join("README.md"), "second\n").expect("write second revision");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "second"]);
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create copy target");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("read fixture entry");
        let from = entry.path();
        let to = target.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy fixture file");
        }
    }
}

fn admit(repo: &Path, home: &Path) -> Value {
    fs::create_dir_all(home).expect("create scratch home");
    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(repo)
        .arg("--json")
        .env("HOME", home)
        .output()
        .expect("run kin init");
    assert!(
        output.status.success(),
        "kin init failed for {}: stdout={} stderr={}",
        repo.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("init stdout should be JSON")
}

fn field<'a>(receipt: &'a Value, pointer: &str) -> &'a Value {
    receipt
        .pointer(&format!("/{pointer}"))
        .unwrap_or_else(|| panic!("receipt has no field {pointer}: {receipt}"))
}

#[test]
fn two_admissions_of_one_repository_agree_on_admitted_content() {
    let root = tempdir().expect("temp root");
    let source = root.path().join("source");
    seed_git_repo(&source);

    let first_repo = root.path().join("first");
    let second_repo = root.path().join("second");
    copy_tree(&source, &first_repo);
    copy_tree(&source, &second_repo);

    let first = admit(&first_repo, &root.path().join("home-first"));
    let second = admit(&second_repo, &root.path().join("home-second"));

    // A fixture whose two copies disagreed on Git identity would make every
    // later comparison meaningless, so prove they agree before reading Kin's.
    assert_eq!(
        field(&first, "raw_git_head"),
        field(&second, "raw_git_head"),
        "the two copies must admit the same Git commit for this test to mean anything"
    );

    let divergent = CONTENT_IDENTITY_FIELDS
        .iter()
        .filter(|pointer| field(&first, pointer) != field(&second, pointer))
        .map(|pointer| {
            format!(
                "  {pointer}\n    first:  {}\n    second: {}",
                field(&first, pointer),
                field(&second, pointer)
            )
        })
        .collect::<Vec<_>>();

    assert!(
        divergent.is_empty(),
        "{} of {} content-identity receipt fields are not a function of admitted content:\n{}",
        divergent.len(),
        CONTENT_IDENTITY_FIELDS.len(),
        divergent.join("\n")
    );
}

#[test]
fn admissions_of_one_repository_are_distinct_workspaces() {
    let root = tempdir().expect("temp root");
    let source = root.path().join("source");
    seed_git_repo(&source);

    let first_repo = root.path().join("first");
    let second_repo = root.path().join("second");
    copy_tree(&source, &first_repo);
    copy_tree(&source, &second_repo);

    let first = admit(&first_repo, &root.path().join("home-first"));
    let second = admit(&second_repo, &root.path().join("home-second"));

    // The other half of the contract. Sharing replicated truth must not make
    // two checkouts share local workspace authority, or one machine's
    // uncommitted state would speak for another's.
    assert_ne!(
        field(&first, "workspace_id"),
        field(&second, "workspace_id"),
        "two admissions are two workspaces"
    );
    assert_ne!(
        field(&first, "roots/local_state/hash"),
        field(&second, "roots/local_state/hash"),
        "local_state roots per-workspace authority and never replicated truth"
    );
}
