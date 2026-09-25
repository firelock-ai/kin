// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin init` says before it starts, driven through the real binary.
//!
//! The measured failure is silence. On `prometheus/prometheus`, 18,514 commits
//! over 1,676 tracked files inside an 8 GiB container, the shipped 0.6.0 was
//! killed by the kernel at phase 4 of 17 and printed nothing at all: `SIGKILL`
//! runs no destructor, so the operator got four phase lines and a shell that
//! said `Killed`. Measured twice, exit 137 each time.
//!
//! These drive the binary rather than the library on purpose. The refusal has to
//! survive the trip out through `KinError`, `anyhow`'s context chain and the
//! process exit, and a library test would pass on a build where the sentence
//! never reaches a terminal.
//!
//! The ceiling is pinned with `KIN_INIT_MEMORY_CEILING_BYTES` rather than by
//! filling a machine, which is the same seam `memory_pressure_refusal.py` uses
//! for the same reason: a test that has to exhaust memory to prove Kin refuses
//! is a test that takes the machine down to run.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

/// A ceiling no conversion of anything fits under, so what is graded is the
/// comparison rather than the fixture's size. One byte rather than zero,
/// because zero is refused as unreadable and that case has its own test.
const TINY_CEILING: &str = "1";

/// Room for any fixture here, so a silent conversion is the product choosing
/// silence rather than the test failing to look.
const ROOMY_CEILING: &str = "549755813888";

const CEILING_ENV: &str = "KIN_INIT_MEMORY_CEILING_BYTES";

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

/// A tiny repository with real history, which any real ceiling admits.
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

fn kin_init(repo: &Path, home: &Path, ceiling: &str) -> Run {
    kin_init_with(repo, home, ceiling, &[])
}

fn kin_init_with(repo: &Path, home: &Path, ceiling: &str, extra_env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .arg("init")
        .arg(repo)
        .env("HOME", home)
        .env("KIN_HOME", home.join("kin-home"))
        .env(CEILING_ENV, ceiling);
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let output = command.output().expect("run kin init");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Run {
        code: output.status.code(),
        text,
    }
}

/// A conversion the machine cannot afford is turned away, in words, having
/// written nothing.
///
/// Three properties, because any one of them alone passes on a build that
/// merely crashed differently: it does not succeed, it says why, and it leaves
/// no store and no staging behind. The last matters because the pre-fix death
/// stranded 3.4 GB of capture staging that nothing pointed at.
#[test]
fn a_conversion_over_the_ceiling_refuses_before_it_writes_anything() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), TINY_CEILING);

    assert_ne!(
        run.code,
        Some(0),
        "a conversion under a one-byte ceiling exited 0: {}",
        run.text
    );
    assert!(
        run.contains("needs more memory"),
        "the refusal printed no memory sentence, which is the silence this guards: {}",
        run.text
    );
    assert!(
        !repo.join(".kin").exists(),
        "a refused conversion left a store behind"
    );
    let stranded: Vec<_> = fs::read_dir(workspace.path())
        .expect("read workspace")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".kin-git-capture-") || name.starts_with(".kin.init-"))
        .collect();
    assert!(
        stranded.is_empty(),
        "a refused conversion stranded staging: {stranded:?}"
    );
}

/// The refusal carries every number and every way forward.
///
/// A refusal that says only "no" reproduces the dead end the cold walk found:
/// the obvious workaround, `git clone --depth 1`, is refused by admission with
/// "shallow Git repositories cannot be imported losslessly", so a reader told to
/// convert something with less history and nothing else is being sent at the one
/// thing that cannot work.
#[test]
fn the_refusal_names_the_counts_the_remedies_and_the_shallow_dead_end() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), TINY_CEILING);

    for phrase in [
        "needs more memory",
        "commits over",
        "tracked files",
        "give it more than",
        "convert a repository with less history",
        "git clone --depth",
        CEILING_ENV,
    ] {
        assert!(
            run.contains(phrase),
            "the refusal omits {phrase:?}; it printed: {}",
            run.text
        );
    }
}

/// A conversion with room converts and says nothing about memory.
///
/// The control, and the half that fails quietly. A forecast wired to refuse
/// everything satisfies every assertion in the first test while making Kin
/// unusable, and one that narrates itself on an ordinary repository trains a
/// reader to skip the line that matters.
#[test]
fn a_conversion_with_room_converts_and_says_nothing_about_memory() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), ROOMY_CEILING);

    assert_eq!(
        run.code,
        Some(0),
        "a conversion with room exited {:?}: {}",
        run.code,
        run.text
    );
    assert!(repo.join(".kin").exists(), "no store was written");
    for phrase in ["needs more memory", "is expected to hold about"] {
        assert!(
            !run.contains(phrase),
            "a conversion with room narrated its memory with {phrase:?}: {}",
            run.text
        );
    }
}

/// A ceiling override Kin cannot read is refused, never treated as absent.
///
/// Falling back to the measured ceiling is the tempting behaviour and the wrong
/// one. An operator who set the variable believes it took effect, so a typo
/// would silently restore the conversion they set it to avoid, and it would be
/// discovered as a kernel kill with no message.
#[test]
fn an_unreadable_ceiling_override_is_refused_rather_than_ignored() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), "eight gigabytes");

    assert_ne!(
        run.code,
        Some(0),
        "an unreadable ceiling was ignored and the conversion ran: {}",
        run.text
    );
    assert!(
        run.contains(CEILING_ENV) && run.contains("not a positive whole number"),
        "the refusal does not name the variable and what is wrong with it: {}",
        run.text
    );
    assert!(
        !repo.join(".kin").exists(),
        "a refused conversion left a store behind"
    );
}

/// An empty override is refused for the same reason a malformed one is.
///
/// Its own case because an empty string is what an operator gets from
/// `KIN_INIT_MEMORY_CEILING_BYTES=` and from a shell variable that expanded to
/// nothing, which is the likeliest way to set it wrong by accident.
#[test]
fn an_empty_ceiling_override_is_refused() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo(&repo);

    let run = kin_init(&repo, home.path(), "");

    assert_ne!(
        run.code,
        Some(0),
        "an empty ceiling was ignored and the conversion ran: {}",
        run.text
    );
    assert!(
        run.contains(CEILING_ENV),
        "the refusal does not name the variable: {}",
        run.text
    );
}

/// The ceiling the ref-universe tests pin, 16 MiB. The fixture's HEAD history
/// forecasts about 2 MB and its off-HEAD history projects about 33 MB, so this
/// sits between them and away from both.
const REF_UNIVERSE_CEILING: &str = "16777216";

/// Pins the memory-pressure level, so nothing on this host is charged against
/// the ceiling above.
///
/// Once a conversion has planned what it captured, it is judged against the
/// ceiling less what the machine already uses. Pinning the level gives that
/// check no reading of the host, so it charges nothing, and the room it judges
/// against is the pinned ceiling on every host rather than whatever this one
/// happens to have free. `nominal` is the level that refuses no other work.
const PRESSURE_ENV: &str = "KIN_MEMORY_PRESSURE";

/// Bytes of the one file only the side branch and its tag reach.
const OFF_HEAD_BYTES: usize = 1 << 20;

/// Three commits on `main`, plus a side branch and an annotated tag that carry
/// a commit HEAD never reaches.
///
/// The side commit holds one file of `OFF_HEAD_BYTES`, and checking `main` out
/// again leaves the working tree clean, which is what admission requires. The
/// history HEAD reaches stays as small as `seed_git_repo`'s, so the forecast
/// taken before capture, which walks HEAD alone, has nothing to say about the
/// side commit.
fn seed_git_repo_with_history_off_head(path: &Path) {
    seed_git_repo(path);
    run_git(path, &["checkout", "-b", "side"]);
    let line = "a line of history that only a side branch and its tag reach\n";
    let body = line.repeat(OFF_HEAD_BYTES.div_ceil(line.len()));
    fs::write(path.join("side-history.txt"), body).expect("write the off-HEAD file");
    run_git(path, &["add", "side-history.txt"]);
    run_git(path, &["commit", "-m", "history HEAD does not reach"]);
    run_git(
        path,
        &["tag", "-a", "v1", "-m", "a release HEAD does not reach"],
    );
    run_git(path, &["checkout", "main"]);
    assert!(
        !path.join("side-history.txt").exists(),
        "the fixture has to leave main's working tree clean"
    );
}

fn stranded_staging(workspace: &Path) -> Vec<String> {
    fs::read_dir(workspace)
        .expect("read workspace")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".kin-git-capture-") || name.starts_with(".kin.init-"))
        .collect()
}

/// History that only other refs reach is judged before it is derived, and a
/// conversion without the memory for it is refused rather than started.
///
/// A conversion captures every ref under `refs/`, not only the history HEAD
/// reaches, while the forecast taken before capture walks HEAD alone. On a
/// clone carrying 1,227 refs that forecast came to 34.5 GiB and passed, the
/// plan then projected 96.4 GiB against 68.5 GiB free, and the conversion
/// carried on into the phase that spends it with nothing but a warning. This
/// is that shape at the size of a test: HEAD's history fits the pinned ceiling
/// with room to spare, and a side branch and an annotated tag carry the rest.
///
/// Four things are graded. The run is refused. The forecast before capture let
/// it through, since that refusal's own wording is absent. The refusal counts
/// the four commits and three refs the capture took, which is the proof that
/// the side branch and the tag were captured. And nothing is left behind,
/// neither a store nor the capture the run took before it stopped.
#[test]
fn history_only_other_refs_reach_is_refused_before_it_is_derived() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo_with_history_off_head(&repo);

    let run = kin_init_with(
        &repo,
        home.path(),
        REF_UNIVERSE_CEILING,
        &[(PRESSURE_ENV, "nominal")],
    );

    assert_ne!(
        run.code,
        Some(0),
        "a conversion whose captured refs project past the room it has exited 0: {}",
        run.text
    );
    assert!(
        run.contains("needs more memory"),
        "the refusal printed no memory sentence: {}",
        run.text
    );
    assert!(
        !run.contains("this refusal happens before any capture"),
        "the forecast before capture refused, so this run never reached the refs it exists \
         to judge: {}",
        run.text
    );
    for phrase in [
        "4 commits",
        "from 3 refs",
        "every branch, tag and other ref",
        "--single-branch --no-tags",
        CEILING_ENV,
        "nothing was published",
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
        "a refused conversion stranded its capture: {stranded:?}"
    );
}

/// The same repository, under the same pins, converts once those refs are gone.
///
/// The control for the test above, and the proof that the refs alone moved
/// its verdict: the commit they carried is still in the object store, and with
/// no ref naming it the capture does not take it. A check wired to refuse
/// everything under a small ceiling would pass the test above and fail here.
#[test]
fn the_same_repository_without_those_refs_converts_under_the_same_pins() {
    let home = tempdir().expect("home");
    let workspace = tempdir().expect("workspace");
    let repo = workspace.path().join("repo");
    seed_git_repo_with_history_off_head(&repo);
    run_git(&repo, &["branch", "-D", "side"]);
    run_git(&repo, &["tag", "-d", "v1"]);

    let run = kin_init_with(
        &repo,
        home.path(),
        REF_UNIVERSE_CEILING,
        &[(PRESSURE_ENV, "nominal")],
    );

    assert_eq!(
        run.code,
        Some(0),
        "a conversion with room exited {:?}: {}",
        run.code,
        run.text
    );
    assert!(repo.join(".kin").exists(), "no store was written");
    for phrase in [
        "needs more memory",
        "is expected to hold about",
        "is projected to hold about",
    ] {
        assert!(
            !run.contains(phrase),
            "a conversion with room narrated its memory with {phrase:?}: {}",
            run.text
        );
    }
    let stranded = stranded_staging(workspace.path());
    assert!(
        stranded.is_empty(),
        "a finished conversion stranded staging: {stranded:?}"
    );
}
