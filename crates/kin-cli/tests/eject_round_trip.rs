// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end acceptance for leaving a graph-authoritative Kin repository.
//!
//! Eject is an export boundary, not a return to pre-init file authority. These
//! tests prove that the real binary:
//! - leaves exact graph-projected code, config, lockfile, binary, executable,
//!   and symlink state in place;
//! - preserves an interoperability `.git/` store byte-for-byte;
//! - refuses a working tree that diverges from the current graph ref;
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
}

fn git_head(repo: &Path) -> String {
    String::from_utf8_lossy(&git(repo, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string()
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

fn directory_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<_> = fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.file_type().is_dir() {
                collect(root, &path, output);
            } else if metadata.file_type().is_symlink() {
                output.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    os_string_bytes(fs::read_link(path).unwrap().into_os_string()),
                );
            } else {
                output.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }

    let mut output = BTreeMap::new();
    collect(root, root, &mut output);
    output
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
    let tracked_before = tracked_state(&repo);
    let git_before = directory_bytes(&repo.join(".git"));

    run_kin_ok(&repo, &registry, &["init", "."]);
    assert!(repo.join(".kin").is_dir());
    assert!(
        !repo.join(".kin/snapshot").exists(),
        "graph-first init must not retain a raw filesystem snapshot"
    );

    run_kin_ok(&repo, &registry, &["eject", "--yes"]);

    assert!(!repo.join(".kin").exists());
    assert_eq!(tracked_state(&repo), tracked_before);
    assert_eq!(
        directory_bytes(&repo.join(".git")),
        git_before,
        "eject must not mutate the Git interoperability store"
    );
    assert_eq!(git_head(&repo), head_before);
    assert!(
        git(&repo, &["status", "--porcelain"]).stdout.is_empty(),
        "recovery metadata must live outside the plain Git working tree"
    );

    let archives = metadata_archives(&repo);
    assert_eq!(archives.len(), 1);
    fs::rename(&archives[0], repo.join(".kin")).unwrap();
    run_kin_ok(&repo, &registry, &["status", "--json"]);
    run_kin_ok(&repo, &registry, &["eject", "--yes", "--purge-metadata"]);
    assert!(metadata_archives(&repo).is_empty());
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
