// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Peak-heap ceiling for admitting real Git history.
//!
//! Init peaked at 46.2 GiB admitting a 2190-commit repository, holding several
//! whole-history structures at once. Peak memory is what decides whether init
//! runs at all on a small machine, and it is invisible to every other test in
//! this workspace: a structure held live for a phase longer than it needs to be
//! changes no output and fails no assertion, and is only felt on a machine that
//! then has to swap.
//!
//! The guard measures live heap directly rather than resident set. RSS is a
//! high-water mark of pages the allocator has touched, so it keeps counting
//! memory that was freed but not returned to the OS, which makes it reproducible
//! only within one allocator and one platform. Live heap moves when, and only
//! when, the code allocates differently.
//!
//! This binary installs a counting global allocator, so it holds exactly one
//! test on purpose. The counter is process-wide, and a second test running
//! beside it would charge its allocations to this one. The allocator and the
//! per-phase probe both live in `support`, so other admission memory tests can
//! install the same instrument.

mod support;

use std::path::Path;
use std::process::Command;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// Commits in the fixture history.
///
/// Init's cost scales with history depth, so the fixture buys depth. The
/// modules below are sized so the admitted history, rather than init's fixed
/// overhead, dominates the measurement; with a two-file-per-commit tree the
/// fixed cost swamps everything and the number stops tracking the code.
const COMMITS: usize = 32;

/// Modules rewritten on every commit.
const MODULES: usize = 10;

/// Types defined in each module.
const ITEMS_PER_MODULE: usize = 8;

/// Ceiling on peak live heap for admitting `COMMITS` commits.
///
/// Measured at 317 MiB on this fixture. The headroom is set to catch a change
/// that holds another whole-history structure live, which is the failure this
/// path has actually produced: init already keeps the import plan, the admitted
/// plan, and the bootstrap transaction alive at once, and each one it adds is a
/// step change rather than a trim.
///
/// Be precise about what this ceiling does and does not catch as written.
/// Removing the whole-history copy that motivated it moved this fixture by
/// 22 MiB, about 6 percent, matching the 6.9 percent it moved a 2190-commit
/// repository. This ceiling is loose enough that a change that size passes, so
/// it is a floor under gross regressions rather than proof no copy came back,
/// and a change to the commit path still needs its own measurement.
///
/// The headroom is deliberately larger than the measurement needs, and that is
/// the part worth revisiting. Two clean runs on one host landed within 5 KB of
/// each other, 0.002 percent, against a 22 MiB signal, so locally the ceiling
/// could sit far tighter and still catch the copy. It is set wide because that
/// determinism has only been observed on macOS, and this suite also runs on
/// Linux and Windows, where a different allocator and parser behavior may shift
/// the baseline. Tighten it once the number has been seen on all three, rather
/// than on the strength of one platform: a ceiling that flakes in the merge
/// queue costs more than the regression it would have caught.
const PEAK_HEAP_CEILING: usize = 448 * 1024 * 1024;

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Kin Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@firelock.ai")
        .env("GIT_COMMITTER_NAME", "Kin Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@firelock.ai")
        .output()
        .unwrap_or_else(|error| panic!("git {args:?} failed to start: {error}"));
    assert!(
        status.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn build_history(repo: &Path) {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["config", "user.name", "Kin Fixture"]);
    git(repo, &["config", "user.email", "fixture@firelock.ai"]);
    std::fs::write(repo.join("Cargo.toml"), b"[package]\nname = \"fixture\"\n").unwrap();

    for commit in 0..COMMITS {
        // Every commit rewrites the whole module set, so the admitted history
        // carries a full tree delta and a fresh set of semantic entities per
        // commit rather than a single-file edit. That is what makes history,
        // not fixed init overhead, the dominant term in the measurement.
        for module in 0..MODULES {
            let mut body = String::new();
            for item in 0..ITEMS_PER_MODULE {
                body.push_str(&format!(
                    "pub struct Item{module}_{item}_{commit} {{ pub field: u32 }}\n\
                     impl Item{module}_{item}_{commit} {{\n\
                     pub fn build() -> Self {{ Self {{ field: {commit} }} }}\n\
                     pub fn read(&self) -> u32 {{ self.field }}\n\
                     }}\n"
                ));
            }
            std::fs::write(repo.join(format!("src/mod_{module}.rs")), body.as_bytes()).unwrap();
        }
        git(repo, &["add", "-A"]);
        git(repo, &["commit", "-m", &format!("commit {commit}")]);
    }
}

#[test]
fn admitting_git_history_stays_under_the_init_heap_ceiling() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = workspace.path().join("source");
    std::fs::create_dir(&repo).unwrap();
    build_history(&repo);

    // Installed before the measured call so every admission phase is sampled.
    // Without it a breach reports a number and no way to act on it.
    support::install_phase_layer();

    let repo = repo.canonicalize().unwrap();
    support::reset_peak();
    let baseline = support::live();

    kin_core::init_from_git(&repo).expect("admit the fixture repository");

    let peak = support::peak().saturating_sub(baseline);
    println!(
        "peak live heap admitting {COMMITS} commits: {peak} bytes ({:.1} MiB), ceiling {} MiB",
        peak as f64 / 1024.0 / 1024.0,
        PEAK_HEAP_CEILING / 1024 / 1024
    );
    assert!(
        peak < PEAK_HEAP_CEILING,
        "admitting {COMMITS} commits peaked at {peak} bytes of live heap, over the \
         {PEAK_HEAP_CEILING} byte ceiling. Init already holds the import plan, the admitted \
         plan, and the bootstrap transaction at the same time, so a structure kept live for \
         a phase longer than it needs to be is charged where the working set is already \
         largest. On a repository with real history that is the difference between init \
         running on a small machine and swapping it.\n\n{}\n\
         Read the grew column to find which phase moved, and the retained column to tell a \
         structure held too long from allocation churn inside one phase. They need opposite \
         fixes.",
        support::phase_attribution_table()
    );
}
