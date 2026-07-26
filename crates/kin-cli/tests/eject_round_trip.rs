// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end acceptance for leaving a graph-authoritative Kin repository.
//!
//! Eject is an export boundary, not a return to pre-init file authority. These
//! tests prove that the real binary:
//! - leaves exact graph-projected code, config, lockfile, binary, executable,
//!   and symlink state in place;
//! - reconstructs imported Git objects from repository CAS without consulting
//!   drifted working files;
//! - refuses a working tree that diverges from the current graph ref;
//! - refuses to flatten a graph-owned gitlink during eject;
//! - keeps metadata recoverable outside the repository by default; and
//! - has no legacy initialization-snapshot restore surface.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use tempfile::tempdir;

mod common;

use common::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryState {
    kind: &'static str,
    bytes: Vec<u8>,
    executable: bool,
}

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

/// Run the real `kin` binary in `dir` with an isolated registry so the test
/// never touches shared repository state.
fn run_kin(dir: &Path, registry: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .current_dir(dir)
        .env("KIN_REGISTRY_PATH", registry)
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

fn seed_git_repo(repo: &Path) {
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
        repo.join("compose.yaml"),
        "services:\n  app:\n    image: example/demo:1\n",
    )
    .unwrap();
    fs::write(repo.join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::create_dir_all(repo.join("tools")).unwrap();
    fs::write(repo.join("tools/build.py"), "print('polyglot')\n").unwrap();
    fs::create_dir_all(repo.join("config")).unwrap();
    fs::write(
        repo.join("config/policy.unrecognized"),
        "arbitrary = true\n",
    )
    .unwrap();
    fs::write(repo.join("unrelated.payload"), "not source code\n").unwrap();
    fs::write(
        repo.join("Cargo.lock"),
        "# generated lockfile\nversion = 4\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join("assets")).unwrap();
    let mut binary: Vec<u8> = (0u8..=255).collect();
    binary.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0x80]);
    fs::write(repo.join("assets/blob.bin"), binary).unwrap();
    fs::write(repo.join("run-demo"), "#!/bin/sh\nexec echo demo\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        fs::set_permissions(repo.join("run-demo"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("compose.yaml", repo.join("current-compose")).unwrap();
    }

    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "seed repo"]);
    git(repo, &["branch", "-M", "main"]);
    git(
        repo,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/firelock/fixture.git",
        ],
    );
    git(
        repo,
        &[
            "config",
            "--add",
            "remote.origin.pushurl",
            "https://push.example.invalid/firelock/fixture.git",
        ],
    );
    git(repo, &["config", "branch.main.remote", "origin"]);
    git(
        repo,
        &["config", "--add", "branch.main.merge", "refs/heads/main"],
    );
    git(repo, &["config", "remote.pushDefault", "origin"]);
    git(repo, &["config", "push.default", "current"]);
}

fn git_head(repo: &Path) -> String {
    String::from_utf8_lossy(&git(repo, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string()
}

fn git_object_ids(repo: &Path) -> Vec<String> {
    let mut objects = String::from_utf8(
        git(
            repo,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        )
        .stdout,
    )
    .unwrap()
    .lines()
    .map(str::to_string)
    .collect::<Vec<_>>();
    objects.sort();
    objects
}

fn git_config_values(repo: &Path, key: &str) -> Vec<String> {
    String::from_utf8(git(repo, &["config", "--get-all", key]).stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn tracked_state(repo: &Path) -> BTreeMap<PathBuf, EntryState> {
    let listing = git(repo, &["ls-files", "-z"]).stdout;
    listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|relative| {
            let relative = PathBuf::from(String::from_utf8(relative.to_vec()).unwrap());
            let state = entry_state(&repo.join(&relative));
            (relative, state)
        })
        .collect()
}

fn entry_state(path: &Path) -> EntryState {
    let metadata = fs::symlink_metadata(path).unwrap();
    if metadata.file_type().is_symlink() {
        return EntryState {
            kind: "symlink",
            bytes: os_string_bytes(fs::read_link(path).unwrap().into_os_string()),
            executable: false,
        };
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    EntryState {
        kind: "blob",
        bytes: fs::read(path).unwrap(),
        executable,
    }
}

#[cfg(unix)]
fn os_string_bytes(value: OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt as _;
    value.into_vec()
}

#[cfg(not(unix))]
fn os_string_bytes(value: OsString) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

fn metadata_archives(repo: &Path) -> Vec<PathBuf> {
    let parent = repo.parent().expect("repo has parent");
    let mut archives: Vec<_> = fs::read_dir(parent)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".kin-ejected-")
        })
        .map(|entry| entry.path())
        .collect();
    archives.sort();
    archives
}

fn assert_refused(output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains(&expected.to_lowercase()),
        "expected {expected:?} in refusal, got: {combined}"
    );
}

#[test]
fn brownfield_eject_preserves_exact_files_and_git_with_recoverable_metadata() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_git_repo(&repo);

    let head_before = git_head(&repo);
    let objects_before = git_object_ids(&repo);
    let tracked_before = tracked_state(&repo);

    run_kin_ok(&repo, &registry, &["init", "."]);
    assert!(repo.join(".kin").is_dir());
    assert!(
        !repo.join(".kin/snapshot").exists(),
        "graph-first init must not retain a raw filesystem snapshot"
    );

    run_kin_ok(&repo, &registry, &["eject", "--yes"]);

    assert!(!repo.join(".kin").exists());
    assert_eq!(tracked_state(&repo), tracked_before);
    assert_eq!(git_head(&repo), head_before);
    assert_eq!(
        git_object_ids(&repo),
        objects_before,
        "eject must not omit or invent imported Git objects"
    );
    git(&repo, &["fsck", "--strict"]);
    assert_eq!(
        git_config_values(&repo, "remote.origin.url"),
        ["https://example.invalid/firelock/fixture.git"]
    );
    assert_eq!(
        git_config_values(&repo, "remote.origin.pushurl"),
        ["https://push.example.invalid/firelock/fixture.git"]
    );
    assert_eq!(
        git_config_values(&repo, "remote.origin.fetch"),
        ["+refs/heads/*:refs/remotes/origin/*"]
    );
    assert_eq!(git_config_values(&repo, "branch.main.remote"), ["origin"]);
    assert_eq!(
        git_config_values(&repo, "branch.main.merge"),
        ["refs/heads/main"]
    );
    assert_eq!(git_config_values(&repo, "remote.pushDefault"), ["origin"]);
    assert_eq!(git_config_values(&repo, "push.default"), ["current"]);
    assert!(
        git(&repo, &["status", "--porcelain"]).stdout.is_empty(),
        "recovery metadata must live outside the plain Git working tree"
    );

    let archives = metadata_archives(&repo);
    assert_eq!(archives.len(), 1);
    assert!(archives[0].join("kin").is_dir());
    assert!(archives[0].join("previous-git").exists());
}

#[test]
fn eject_refuses_a_projection_that_differs_from_current_graph_ref() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_git_repo(&repo);
    let original = fs::read(repo.join("compose.yaml")).unwrap();
    run_kin_ok(&repo, &registry, &["init", "."]);

    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  unexpected:\n    image: local-only\n",
    )
    .unwrap();
    let output = run_kin(&repo, &registry, &["eject", "--yes"]);
    assert_refused(&output, "exact projection");
    assert!(repo.join(".kin").exists());
    assert_eq!(
        fs::read(repo.join("compose.yaml")).unwrap(),
        b"services:\n  unexpected:\n    image: local-only\n"
    );
    assert!(metadata_archives(&repo).is_empty());

    fs::write(repo.join("compose.yaml"), original).unwrap();
    run_kin_ok(&repo, &registry, &["eject", "--yes", "--purge-metadata"]);
}

#[test]
fn git_export_reads_repository_authority_when_working_files_drift() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let exported = root.path().join("export.git");
    let checkout = root.path().join("checkout");
    let registry = root.path().join("registry.toml");
    seed_git_repo(&repo);
    let expected = tracked_state(&repo);
    let head = git_head(&repo);
    run_kin_ok(&repo, &registry, &["init", "."]);

    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  drift:\n    image: working-tree-only\n",
    )
    .unwrap();
    fs::remove_file(repo.join("assets/blob.bin")).unwrap();

    run_kin_ok(
        &repo,
        &registry,
        &["git", "export", "--output", exported.to_str().unwrap()],
    );
    assert!(exported.join("HEAD").is_file());
    let exported_arg = exported.to_str().unwrap();
    git(
        root.path(),
        &["--git-dir", exported_arg, "fsck", "--strict"],
    );
    git(
        root.path(),
        &["clone", "-q", exported_arg, checkout.to_str().unwrap()],
    );

    assert_eq!(git_head(&checkout), head);
    assert_eq!(
        tracked_state(&checkout),
        expected,
        "export must come from repository-v6 source CAS, not drifted working files"
    );
}

#[test]
fn git_export_refuses_to_publish_inside_the_kin_working_repository() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_git_repo(&repo);
    run_kin_ok(&repo, &registry, &["init", "."]);
    fs::create_dir(repo.join("nested")).unwrap();

    let output = run_kin(
        &repo,
        &registry,
        &["git", "export", "--output", "nested/export.git"],
    );
    assert_refused(&output, "inside the Kin working repository");
    assert!(!repo.join("nested/export.git").exists());
}

#[test]
fn native_unborn_repository_ejects_to_an_unborn_ordinary_git_repository() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    fs::create_dir(&repo).unwrap();

    run_kin_ok(&repo, &registry, &["init", "."]);
    run_kin_ok(&repo, &registry, &["eject", "--yes", "--purge-metadata"]);

    assert!(!repo.join(".kin").exists());
    assert!(repo.join(".git").is_dir());
    assert_eq!(
        String::from_utf8(git(&repo, &["symbolic-ref", "HEAD"]).stdout)
            .unwrap()
            .trim(),
        "refs/heads/main"
    );
    let head = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(
        !head.status.success(),
        "unborn eject must not invent a commit"
    );
    git(&repo, &["fsck", "--strict"]);
    assert!(git(&repo, &["status", "--porcelain"]).stdout.is_empty());
    assert!(
        !repo.join(".git/index").exists(),
        "unborn eject must preserve the canonical absent-index state"
    );
    let object_counts = String::from_utf8(git(&repo, &["count-objects", "-v"]).stdout).unwrap();
    assert!(
        object_counts.lines().any(|line| line == "count: 0")
            && object_counts.lines().any(|line| line == "in-pack: 0"),
        "unborn eject must not invent unreachable Git objects:\n{object_counts}"
    );
    assert!(metadata_archives(&repo).is_empty());
}

#[test]
fn exact_git_repo_ejects_without_language_support() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    fs::create_dir_all(&repo).unwrap();
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  db:\n    image: postgres:17\n",
    )
    .unwrap();
    fs::write(repo.join("vendor.lock"), b"opaque lock syntax\n").unwrap();
    fs::write(repo.join("firmware.bin"), [0, 0xff, 0x42, 0x80]).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.email", "kin@example.invalid"]);
    git(&repo, &["config", "user.name", "Kin Test"]);
    git(&repo, &["add", "--all"]);
    git(&repo, &["commit", "-q", "-m", "exact non-code tree"]);
    let before = ["compose.yaml", "vendor.lock", "firmware.bin"]
        .into_iter()
        .map(|path| (path, entry_state(&repo.join(path))))
        .collect::<BTreeMap<_, _>>();

    run_kin_ok(&repo, &registry, &["init", "."]);
    run_kin_ok(&repo, &registry, &["eject", "--yes", "--purge-metadata"]);

    assert!(!repo.join(".kin").exists());
    assert!(repo.join(".git").exists());
    assert!(metadata_archives(&repo).is_empty());
    for (path, expected) in before {
        assert_eq!(entry_state(&repo.join(path)), expected);
    }
}

#[test]
fn eject_refuses_gitlinks_before_replacing_git_or_detaching_kin() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let dependency = repo.join("vendor/dependency");
    let exported = root.path().join("export.git");
    let registry = root.path().join("registry.toml");

    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.email", "kin@example.invalid"]);
    git(&repo, &["config", "user.name", "Kin Test"]);
    fs::write(repo.join("README.md"), "gitlink fixture\n").unwrap();
    git(&repo, &["add", "README.md"]);
    git(&repo, &["commit", "-q", "-m", "gitlink base"]);
    let dependency_target = git_head(&repo);
    fs::create_dir_all(&dependency).unwrap();
    let cache_info = format!("160000,{dependency_target},vendor/dependency");
    git(
        &repo,
        &["update-index", "--add", "--cacheinfo", &cache_info],
    );
    git(&repo, &["commit", "-q", "-m", "track dependency gitlink"]);
    let head_before = git_head(&repo);

    run_kin_ok(&repo, &registry, &["init", "."]);
    run_kin_ok(
        &repo,
        &registry,
        &[
            "git",
            "export",
            "--output",
            exported.to_str().expect("UTF-8 temp path"),
        ],
    );
    let exported_tree = git(
        root.path(),
        &[
            "--git-dir",
            exported.to_str().expect("UTF-8 temp path"),
            "ls-tree",
            "HEAD",
            "vendor/dependency",
        ],
    );
    assert_eq!(
        String::from_utf8(exported_tree.stdout).unwrap(),
        format!("160000 commit {dependency_target}\tvendor/dependency\n"),
        "bare Git export must preserve the exact gitlink pointer"
    );

    let output = run_kin(&repo, &registry, &["eject", "--yes"]);
    assert_refused(&output, "gitlink");
    assert!(repo.join(".kin").is_dir());
    assert!(repo.join(".git").is_dir());
    assert_eq!(git_head(&repo), head_before);
    assert!(metadata_archives(&repo).is_empty());
}

#[test]
fn legacy_snapshot_restore_flag_is_not_a_product_surface() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let registry = root.path().join("registry.toml");
    seed_git_repo(&repo);
    run_kin_ok(&repo, &registry, &["init", "."]);

    let output = run_kin(&repo, &registry, &["eject", "--revert-files", "--yes"]);
    assert_refused(&output, "unexpected argument");
    assert!(repo.join(".kin").exists());

    run_kin_ok(&repo, &registry, &["eject", "--yes", "--purge-metadata"]);
}
