// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin init` says about disk before it starts, driven through the real
//! binary.
//!
//! Nothing used to check free space before a conversion whose store can be
//! two orders of magnitude larger than the Git object store it came from, so a
//! full disk was discovered partway through, after minutes of work. These drive
//! the binary rather than the library because the refusal has to survive the
//! trip out through `KinError`, `anyhow`'s context chain and the process exit.
//!
//! Free space is pinned with `KIN_INIT_DISK_FREE_BYTES` rather than by filling
//! a disk, the same seam the memory refusal's tests use for its ceiling.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

const FREE_ENV: &str = "KIN_INIT_DISK_FREE_BYTES";

/// Room for any fixture here, so the memory check never decides these runs.
const ROOMY_MEMORY: &str = "549755813888";

/// Room for any fixture here, so a quiet conversion is the product choosing
/// quiet rather than the test failing to look.
const ROOMY_DISK: &str = "549755813888";

/// Less than the three file versions this fixture holds, twice over.
const TINY_DISK: &str = "1";

/// More than the fixture's floor, twice its 126 bytes of file versions, and
/// far less than any store measured on a current release would take next to
/// its loose-object Git store, which is the band that is warned about.
const BETWEEN_FLOOR_AND_FORECAST: &str = "4096";

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

/// Three commits, each adding one 42-byte file.
fn seed_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    for revision in 0..3 {
        fs::write(
            path.join(format!("module{revision}.py")),
            format!("def handler{revision}(payload):\n    return payload\n"),
        )
        .expect("write a revision");
        run_git(path, &["add", "--all"]);
        run_git(path, &["commit", "-m", &format!("revision {revision}")]);
    }
}

struct Run {
    code: Option<i32>,
    text: String,
}

impl Run {
    fn contains(&self, needle: &str) -> bool {
        self.text.contains(needle)
    }
}

fn kin_init(repo: &Path, home: &Path, free: &str) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(repo)
        .arg("--no-enrich")
        .env("HOME", home)
        .env("KIN_HOME", home.join("kin-home"))
        .env("KIN_INIT_MEMORY_CEILING_BYTES", ROOMY_MEMORY)
        .env(FREE_ENV, free)
        .output()
        .expect("run kin init");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Run {
        code: output.status.code(),
        text,
    }
}

fn stranded_staging(parent: &Path) -> Vec<String> {
    fs::read_dir(parent)
        .expect("read workspace")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".kin-git-capture-") || name.starts_with(".kin.init-"))
        .collect()
}

/// A conversion the disk cannot hold is turned away in words, having written
/// nothing.
#[test]
fn a_conversion_the_disk_cannot_hold_refuses_before_it_writes_anything() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), TINY_DISK);

    assert_ne!(
        run.code,
        Some(0),
        "a conversion with one byte free exited 0: {}",
        run.text
    );
    for phrase in [
        "needs more free disk",
        "held twice while the conversion runs",
        "their Git object store",
        "run `kin init` again",
        FREE_ENV,
        "nothing was written",
    ] {
        assert!(
            run.contains(phrase),
            "the refusal omits {phrase:?}; it printed: {}",
            run.text
        );
    }
    assert!(
        !repo.join(".kin").exists(),
        "a refused conversion left a store behind"
    );
    let stranded = stranded_staging(workspace.path());
    assert!(
        stranded.is_empty(),
        "a refused conversion stranded staging: {stranded:?}"
    );
}

/// Room for the floor and not for the forecast is said once, and the
/// conversion carries on.
#[test]
fn a_tight_disk_is_named_and_the_conversion_still_runs() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), BETWEEN_FLOOR_AND_FORECAST);

    assert!(
        run.contains("this conversion may not fit on disk"),
        "a disk under the forecast was not named: {}",
        run.text
    );
    assert!(
        !run.contains("needs more free disk"),
        "a disk with room for the floor was refused: {}",
        run.text
    );
    assert!(
        repo.join(".kin").exists(),
        "a warned conversion must still convert: {}",
        run.text
    );
}

/// A conversion with room converts and says nothing about disk.
#[test]
fn a_conversion_with_room_converts_and_says_nothing_about_disk() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), ROOMY_DISK);

    assert!(
        repo.join(".kin").exists(),
        "no store was written: {}",
        run.text
    );
    for phrase in ["needs more free disk", "may not fit on disk"] {
        assert!(
            !run.contains(phrase),
            "a conversion with room narrated its disk with {phrase:?}: {}",
            run.text
        );
    }
}

/// A free-space override Kin cannot read is refused, never treated as absent.
#[test]
fn an_unreadable_free_space_override_is_refused_rather_than_ignored() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), "lots");

    assert_ne!(
        run.code,
        Some(0),
        "an unreadable free-space override was ignored and the conversion ran: {}",
        run.text
    );
    assert!(
        run.contains(FREE_ENV) && run.contains("not a positive whole number"),
        "the refusal does not name the variable and what is wrong with it: {}",
        run.text
    );
    assert!(
        !repo.join(".kin").exists(),
        "a refused conversion left a store behind"
    );
}
