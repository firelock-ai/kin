// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin init` under the open-file limit a stock macOS install ships with.
//!
//! macOS sets the open-file soft limit to 256 on every machine. A single
//! admission needs more than that, so `kin init` on a clean Mac failed at step
//! 9 of 17 with `Too many open files (os error 24)` on the first real
//! repository anyone tried, and only a six-file fixture got through. The only
//! Macs this project had ever admitted on were tuned ones.
//!
//! The demand behind it is fixed rather than repository-shaped. The storage
//! layer pins one directory capability per digest prefix a write batch touches,
//! each pins two directory descriptors, and there are 256 possible prefixes, so
//! a warmed batch costs 512 descriptors whatever the repository's size. A sweep
//! against kin 0.6.3 on a 237-file repository measured exactly that: failure at
//! soft limits 256, 384 and 512, success from 576 up, peaking at 543 open
//! files.
//!
//! Two arms, and the second is the first one's control.
//!
//! The success arm holds the class: a soft limit of 256 with room above it,
//! which is the stock Mac, must admit. It passes because
//! `kin_core::file_limit` raises the soft limit at startup.
//!
//! The refusal arm pins the soft limit AND the hard limit at 256, so the raise
//! cannot succeed, and requires that the failure name the limit and the remedy
//! instead of reporting descriptor exhaustion. It is also what proves the
//! fixture is potent: if this arm ever admits, the fixture no longer reaches
//! the limit and the success arm above has gone vacuous. It says so rather than
//! passing quietly.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::IsolatedDaemonRuntime;

/// Distinct file bodies in the fixture, which is what decides whether it
/// reaches the limit.
///
/// What exhausts descriptors is digest-prefix coverage, not file count: each of
/// the 256 possible prefixes costs two descriptors once a batch touches it. 600
/// distinct bodies land in roughly 230 of them, about 460 descriptors, which
/// clears 256 with margin and stays well under the 543 a full admission peaks
/// at. Measured against released kin 0.6.3 at `ulimit -Sn 256`: this fixture
/// fails at step 9 in one second, the same failure a real repository gives.
const DISTINCT_BODIES: usize = 600;

/// The soft limit macOS ships, and the one both arms run under.
const STOCK_MACOS_SOFT_LIMIT: &str = "256";

/// Raise nothing, lower the soft limit, then become `kin`.
///
/// `$0` is the binary and `$1` the repository, passed as `sh` positional
/// arguments so no path needs quoting. Chained with `&&` on purpose: `ulimit`
/// writes its refusal to stderr and returns non-zero without stopping a `;`
/// chain, so a separator here would run the admission at the machine's own
/// limit and pass for the wrong reason.
const LIMITED_SOFT: &str = "ulimit -Sn 256 && exec \"$0\" init --no-enrich \"$1\"";

/// The same, with the hard limit pinned so the raise cannot succeed.
///
/// Order matters. `ulimit -Hn` below the current soft limit is refused by the
/// kernel, so the soft limit has to come down first.
const LIMITED_SOFT_AND_HARD: &str =
    "ulimit -Sn 256 && ulimit -Hn 256 && exec \"$0\" init --no-enrich \"$1\"";

fn run_git(path: &Path, args: &[&str]) {
    let output = common::Command::new("git")
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

/// A repository whose objects span most of the 256 digest prefixes.
fn seed_prefix_spanning_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    for index in 0..DISTINCT_BODIES {
        fs::write(
            path.join(format!("src_{index}.rs")),
            format!("pub fn item_{index}() -> u64 {{ {} }}\n", index * 7919 + 13),
        )
        .expect("write a distinct source body");
    }
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "distinct bodies"]);
    fs::write(path.join("CHANGES.md"), "second revision\n").expect("write a second revision");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "second"]);
}

/// Run `kin init` on `repo` under `script`, which sets the limits and execs.
fn init_under_limits(
    runtime: &IsolatedDaemonRuntime,
    script: &str,
    repo: &Path,
) -> std::process::Output {
    runtime
        .process_command_for_test("sh")
        .arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_kin"))
        .arg(repo)
        .output()
        .expect("run kin init under a lowered open-file limit")
}

/// The shell must actually apply the limit, or both arms below run unbounded
/// and prove nothing. Cheap, and it fails on the setup rather than the subject.
#[test]
fn the_fixture_shell_really_lowers_the_limit() {
    let output = common::Command::new("sh")
        .arg("-c")
        .arg("ulimit -Sn 256 && ulimit -Sn")
        .output()
        .expect("lower the soft limit in a shell");
    assert!(output.status.success(), "the shell refused to lower it");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        STOCK_MACOS_SOFT_LIMIT,
        "the soft limit did not take effect, so both arms below are unbounded"
    );
}

#[test]
fn a_stock_soft_limit_admits_a_real_repository() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("stock-soft-limit");
    seed_prefix_spanning_repo(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = init_under_limits(&runtime, LIMITED_SOFT, &repo);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a soft limit of {STOCK_MACOS_SOFT_LIMIT} with headroom above it is what every Mac ships, \
so admission must raise its own limit and succeed: stdout={} stderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !stderr.contains("Too many open files"),
        "the admission succeeded but still reported descriptor exhaustion: {stderr}"
    );
}

#[test]
fn a_pinned_hard_limit_names_the_limit_and_the_remedy() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("pinned-hard-limit");
    seed_prefix_spanning_repo(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = init_under_limits(&runtime, LIMITED_SOFT_AND_HARD, &repo);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "admission succeeded with both limits pinned at {STOCK_MACOS_SOFT_LIMIT}, so this fixture \
no longer reaches the descriptor ceiling and the success arm beside it now proves nothing. \
Enlarge DISTINCT_BODIES until this refuses again, or retire both arms deliberately: stderr={stderr}"
    );
    // The guidance is the whole value of this fix, so it is asserted as the
    // exact lines the product prints rather than as loose substrings. A
    // substring is too weak twice over here: the store path in the failure
    // already carries `sha256`, so a bare "256" passes on the wrong text, and a
    // bare "ulimit -n" passes on a remedy that forgot to say what to raise it
    // to, which is the one number the reader does not have.
    //
    // The remedy is composed from `TARGET_OPEN_FILES`, the same constant the
    // message is built from, so changing the target cannot leave this arm
    // asserting a number that no longer appears anywhere.
    let value_line = format!(
        "open files: soft limit {STOCK_MACOS_SOFT_LIMIT}, hard limit {STOCK_MACOS_SOFT_LIMIT}."
    );
    let shell_remedy = format!("ulimit -n {}", kin_core::file_limit::TARGET_OPEN_FILES);
    for expected in [
        "kin: ran out of open file descriptors.",
        value_line.as_str(),
        "Kin raises the soft limit at startup and cannot go past the hard limit.",
        shell_remedy.as_str(),
    ] {
        assert!(
            stderr.contains(expected),
            "the refusal must carry `{expected}` verbatim: {stderr}"
        );
    }

    // The machine-wide remedy is macOS-only in the product, and this is the
    // platform the class was found on.
    #[cfg(target_os = "macos")]
    {
        let machine_remedy = format!(
            "sudo launchctl limit maxfiles {} unlimited",
            kin_core::file_limit::TARGET_OPEN_FILES
        );
        assert!(
            stderr.contains(&machine_remedy),
            "the refusal must carry `{machine_remedy}` verbatim: {stderr}"
        );
    }
}
