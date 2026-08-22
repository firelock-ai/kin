// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Peak-heap ceiling for admitting DEEP Git history.
//!
//! `init_peak_heap_ceiling` guards a 32-commit fixture, which is deep enough to
//! catch a new whole-history structure but not deep enough to price one. The
//! structures that decide whether a real repository converts at all scale with
//! commits multiplied by tree size, so at 32 commits they are a rounding error
//! against init's fixed cost and a change that doubles them barely moves the
//! number.
//!
//! This fixture buys the depth that makes them the dominant term. A full-history
//! psf/requests conversion measured 11.72 GiB of resident set inside a 12 GiB
//! container, hitting the cgroup limit 871 times, because a conversion proved
//! its import plan by rebuilding the whole plan and comparing the two, six times
//! over, holding as many as four whole histories at once. That class is
//! invisible to every functional test in this workspace: a re-derivation that
//! materializes a second copy of history produces exactly the same verdict as
//! one that streams it, and fails no assertion until the machine runs out of
//! memory.
//!
//! What this guards is therefore not a number but a shape: that proving a
//! history costs a bounded amount of memory rather than another copy of the
//! history. Revert the streaming comparison and this ceiling breaks; the
//! functional suite does not.
//!
//! Live heap, not resident set, for the reason spelled out in
//! `init_peak_heap_ceiling`: RSS keeps counting memory that was freed but not
//! returned, so it is reproducible only within one allocator on one platform,
//! while live heap moves when and only when the code allocates differently.
//!
//! This binary installs a counting global allocator, so it holds exactly one
//! test on purpose.

mod support;

use std::path::Path;
use std::process::Command;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// Commits in the fixture history.
///
/// Eight times the shallow fixture's depth, which is what moves the
/// whole-history structures from a rounding error to the dominant term.
const COMMITS: usize = 256;

/// Modules rewritten on every commit.
const MODULES: usize = 8;

/// Types defined in each module.
const ITEMS_PER_MODULE: usize = 4;

/// Ceiling on peak live heap for admitting `COMMITS` commits.
///
/// Measured on this fixture at 1176 MiB before the streaming comparison landed
/// and 515 MiB after, so the ceiling sits at 700 MiB: comfortably above the
/// post-fix number and far below the pre-fix one. Both numbers are printed on
/// every run, so drift is visible long before it is a failure.
///
/// The gap this ceiling exists to catch is a step change, not a trim. A
/// re-derivation that materializes a second whole history costs roughly what
/// the first one did, and at this depth that is hundreds of megabytes. If a
/// future change lands between 515 and 700 MiB, read the phase table rather
/// than raising the ceiling: the whole point is that the proof no longer scales
/// with history.
const PEAK_HEAP_CEILING: usize = 700 * 1024 * 1024;

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
        // Every commit rewrites the whole module set, so each one carries a full
        // tree delta and a fresh set of semantic entities. A single-file edit
        // per commit would make the trees nearly free to hold, which is the
        // opposite of the shape this guard is about.
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

/// Ignored in the ordinary sweep, and run by the acceptance workflow instead.
///
/// Admitting this fixture takes minutes rather than seconds, because depth is
/// the whole point and every commit is parsed. Leaving it in the default suite
/// would tax every pull request that touches nothing near admission. Run it
/// directly with:
///
/// ```text
/// cargo test --release -p kin-core --test init_deep_history_heap_ceiling \
///     -- --ignored --nocapture
/// ```
#[test]
#[ignore = "deep-history admission takes minutes; the acceptance workflow runs it"]
fn proving_deep_history_does_not_cost_another_copy_of_it() {
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
         {PEAK_HEAP_CEILING} byte ceiling. At this depth the whole-history structures are \
         the dominant term, so a breach here means a phase is holding another copy of \
         history rather than streaming it. That is the class that put a full-history \
         conversion at the ceiling of a 12 GiB container.\n\n{}\n\
         Read the grew column to find which phase moved, and the retained column to tell a \
         structure held too long from allocation churn inside one phase. They need opposite \
         fixes.",
        support::phase_attribution_table()
    );
}
