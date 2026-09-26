// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exercise Cargo's real fingerprint reuse, not a mocked build-script decision.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn run(command: &mut Command, log: &Path) -> Output {
    let shown = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{shown}: {error}"));
    fs::write(
        log,
        format!(
            "{shown}\nstatus: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{shown} failed; see {}",
        log.display()
    );
    output
}

fn git(root: &Path, args: &[&str], log: &Path) -> String {
    let output = run(
        Command::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args),
        log,
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn copy_tree(from: &Path, to: &Path, log: &Path) {
    let flag = if cfg!(target_os = "macos") {
        "-cRp"
    } else {
        "-Rp"
    };
    run(Command::new("cp").arg(flag).arg(from).arg(to), log);
}

fn cargo(root: &Path, target: &Path, args: &[&str], log: &Path) -> Output {
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(root)
        // Freshness assertions below inspect Cargo's text. CI can force ANSI
        // colors even for captured output, inserting escapes inside that text.
        .arg("--color=never")
        .args(args)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_NET_OFFLINE", "true")
        .env_remove("KIN_BUILD_GIT_SHA_OVERRIDE")
        .env_remove("KIN_BUILD_DIRTY_OVERRIDE")
        .env_remove("KIN_BUILD_BRANCH_OVERRIDE");
    run(&mut command, log)
}

#[test]
fn relocated_warm_target_refreshes_identity_and_then_stays_fresh() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let retained = std::env::var_os("KIN_BUILDINFO_RELOCATION_EVIDENCE");
    let evidence = retained.clone().map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "kin-buildinfo-relocation-{}-{nonce}",
            std::process::id()
        ))
    });
    assert!(!evidence.exists(), "fresh evidence directory required");
    fs::create_dir_all(&evidence).unwrap();
    eprintln!("buildinfo relocation evidence: {}", evidence.display());
    let a = evidence.join("source-a");
    let b = evidence.join("source-b");
    let ta = evidence.join("target-a");
    let tb = evidence.join("target-b");
    let wa = a.join("open/kin");
    let wb = b.join("open/kin");
    // Keep the package below a tracked top-level subtree, as in the real
    // workspace. A top-level package gets a relative Cargo watch that can
    // invalidate on relocation and accidentally hide the original defect.
    fs::create_dir_all(wa.join("crates")).unwrap();
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    copy_tree(
        crate_root,
        &wa.join("crates/kin-buildinfo"),
        &evidence.join("copy-source.txt"),
    );
    fs::create_dir_all(wa.join("consumer/src")).unwrap();
    fs::write(wa.join("Cargo.toml"), "[workspace]\nmembers=[\"crates/kin-buildinfo\",\"consumer\"]\nresolver=\"2\"\n[workspace.package]\nversion=\"0.8.0\"\nedition=\"2021\"\nlicense=\"Apache-2.0\"\nrepository=\"https://example.invalid/local-fixture\"\n[workspace.dependencies]\nsha2=\"0.11\"\n").unwrap();
    fs::write(wa.join("consumer/Cargo.toml"), "[package]\nname=\"identity-consumer\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nkin-buildinfo={path=\"../crates/kin-buildinfo\"}\n").unwrap();
    fs::write(wa.join("consumer/src/main.rs"), "fn main(){let b=kin_buildinfo::get();println!(\"{}|{}|{}\", b.sha,b.dirty,b.source_known);}\n").unwrap();
    fs::write(a.join("identity-marker.txt"), "a\n").unwrap();
    cargo(
        &wa,
        &ta,
        &["generate-lockfile", "--offline"],
        &evidence.join("lock.txt"),
    );
    git(&a, &["init", "-b", "fixture-a"], &evidence.join("init.txt"));
    git(
        &a,
        &["config", "user.name", "Build Identity Test"],
        &evidence.join("name.txt"),
    );
    git(
        &a,
        &["config", "user.email", "build-identity@example.invalid"],
        &evidence.join("email.txt"),
    );
    git(
        &a,
        &["config", "commit.gpgsign", "false"],
        &evidence.join("signing.txt"),
    );
    git(&a, &["add", "."], &evidence.join("add-a.txt"));
    git(
        &a,
        &["commit", "-s", "-m", "test: create identity fixture"],
        &evidence.join("commit-a.txt"),
    );
    let sha_a = git(&a, &["rev-parse", "HEAD"], &evidence.join("head-a.txt"));
    git(
        &a,
        &["worktree", "add", "-b", "fixture-b", b.to_str().unwrap()],
        &evidence.join("worktree.txt"),
    );
    fs::write(b.join("identity-marker.txt"), "b\n").unwrap();
    git(
        &b,
        &["add", "identity-marker.txt"],
        &evidence.join("add-b.txt"),
    );
    git(
        &b,
        &[
            "commit",
            "-s",
            "-m",
            "test: advance independent identity fixture",
        ],
        &evidence.join("commit-b.txt"),
    );
    let sha_b = git(&b, &["rev-parse", "HEAD"], &evidence.join("head-b.txt"));
    assert_ne!(sha_a, sha_b);
    // Both source worktrees and their Git metadata predate the warm build. A
    // timestamp accidentally newer than the cache must not rescue relocation.
    cargo(
        &wa,
        &ta,
        &[
            "build",
            "--locked",
            "--offline",
            "-vv",
            "-p",
            "identity-consumer",
        ],
        &evidence.join("build-a.txt"),
    );
    let first = run(
        &mut Command::new(ta.join("debug/identity-consumer")),
        &evidence.join("identity-a.txt"),
    );
    assert_eq!(
        String::from_utf8(first.stdout).unwrap().trim(),
        format!("{sha_a}|false|true")
    );
    copy_tree(&ta, &tb, &evidence.join("clone-target.txt"));
    cargo(
        &wb,
        &tb,
        &[
            "build",
            "--locked",
            "--offline",
            "-vv",
            "-p",
            "identity-consumer",
        ],
        &evidence.join("build-b.txt"),
    );
    let moved = run(
        &mut Command::new(tb.join("debug/identity-consumer")),
        &evidence.join("identity-b.txt"),
    );
    assert_eq!(
        String::from_utf8(moved.stdout).unwrap().trim(),
        format!("{sha_b}|false|true"),
        "relocated cache retained another checkout's identity; see {}",
        evidence.display()
    );
    let repeated = cargo(
        &wb,
        &tb,
        &[
            "build",
            "--locked",
            "--offline",
            "-vv",
            "-p",
            "identity-consumer",
        ],
        &evidence.join("build-b-repeat.txt"),
    );
    let log = String::from_utf8(repeated.stderr).unwrap();
    assert!(
        log.contains("Fresh kin-buildinfo") && !log.contains("Compiling kin-buildinfo"),
        "unchanged checkout rebuilt buildinfo; see {}",
        evidence.display()
    );
    assert!(
        log.contains("Fresh identity-consumer") && !log.contains("Compiling identity-consumer"),
        "unchanged checkout relinked its consumer; see {}",
        evidence.display()
    );
    if retained.is_none() {
        fs::remove_dir_all(&evidence).unwrap();
    }
}
