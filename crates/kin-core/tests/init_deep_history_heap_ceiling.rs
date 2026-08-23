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
//! This fixture buys the depth that prices them. A full-history psf/requests
//! conversion measured 11.72 GiB of resident set inside a 12 GiB container,
//! hitting the cgroup limit 871 times, because a conversion proved its import
//! plan by rebuilding the whole plan and comparing the two, six times over,
//! holding as many as four whole histories at once. That class is invisible to
//! every functional test in this workspace: a re-derivation that materializes a
//! second copy of history produces exactly the same verdict as one that streams
//! it, and fails no assertion until the machine runs out of memory.
//!
//! Read `PROOF_PEAK_GROWTH_CEILING` as the guard and `PEAK_HEAP_CEILING` as a
//! backstop, and do not reverse them. The total is set by the bootstrap
//! transaction, built and then committed after every proof has run, so it does
//! NOT move when a proof stops copying history: the base commit and the fix
//! both measure 995.3 MiB here. Measuring that, rather than assuming it, is
//! what stopped this file from shipping a ceiling that could not fail.
//!
//! What the guard asserts is therefore one phase, not one number: proof 1
//! revalidates the whole import plan and keeps nothing, so whatever it adds to
//! the peak is a second copy of history built to check the first. It added
//! 88,146,432 bytes before the re-derivation was made to stream and 0 after.
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

/// The phase whose entire job is proving, and therefore the one that must not
/// pay for a copy of history to do it.
///
/// `source_proof_staged` is proof 1 of 3. It revalidates the plan structurally
/// and then observes the Git source twice; it keeps nothing at all. Whatever it
/// adds to the peak is memory the machine has to survive so that a check can
/// reach a verdict it was always going to reach.
const PROOF_PHASE: &str = "kin.init.source_proof_staged";

/// Ceiling on what proof 1 may add to the running peak.
///
/// Measured on this fixture, release, one host, both numbers quoted in the pull
/// request that introduced this guard: 88,146,432 bytes (84.1 MiB) on the base
/// commit and 0 bytes after the re-derivation was made to stream. The ceiling
/// sits at 16 MiB, which is far below the pre-fix figure and far above the
/// post-fix one, and there is nothing in between that a legitimate change
/// should produce: either a re-derivation materializes a second history or it
/// does not.
///
/// This is the assertion that carries the class. The total below is a coarser
/// backstop.
const PROOF_PEAK_GROWTH_CEILING: usize = 16 * 1024 * 1024;

/// The phase that binds every imported change's historical semantics.
///
/// It derives one set of entity and relation deltas per commit and writes them
/// into the plan. Those two are the same values, so the phase legitimately ends
/// up holding one copy; what it must not do is hold two, which is what it did
/// while the derived set was collected into owned vectors, copied into the
/// plan, and then dropped unread.
const BIND_PHASE: &str = "kin.init.bind_historical_semantics";

/// How far past what it retains the binding phase may push the running peak,
/// in percent.
///
/// Calibrated inside the run rather than against a constant, deliberately.
/// Both figures scale with commits multiplied by per-commit semantic churn, and
/// a byte ceiling written for this fixture would say nothing about a repository
/// and would have to be retuned whenever the fixture moved. The ratio is the
/// invariant: a phase that produces one copy of a structure and keeps it should
/// not lift the peak by two of them.
///
/// Measured on this fixture, release, one host: 218 percent with the derived
/// deltas alive beside the copy, and 118 percent without. The gate sits at 175,
/// which is below the first and above the second, and there is nothing
/// legitimate in between: either the derived deltas exist twice at once or they
/// do not. The 218 figure is from a build of that mutant rather than from an
/// earlier report, because the earlier report's base carried a different
/// dependency pin.
const BIND_PEAK_GROWTH_PERCENT_OF_RETAINED: usize = 175;

/// The phase that gives up the import plan's change bodies.
///
/// Proof 1 is the last reader of a change's body. Everything after it reads the
/// plan's proved facts, so the phase below converts the plan into a closure
/// carrying those facts and drops the bodies. It exists as a named phase
/// precisely so this guard can watch the live heap fall across it.
const RELEASE_PHASE: &str = "kin.init.release_plan_bodies";

/// How much of what the binding phase retained must actually be given back,
/// in percent.
///
/// Calibrated inside the run rather than against a constant, for the reason
/// `BIND_PEAK_GROWTH_PERCENT_OF_RETAINED` gives: both figures scale with
/// commits multiplied by per-commit churn, so a byte floor written for this
/// fixture would say nothing about a repository. The binding phase produces one
/// copy of every commit's entity, relation and tree deltas and retains it; once
/// proof 1 has read them for the last time, that copy is what this phase hands
/// back.
///
/// The floor sits at 50 percent, well under what a working release gives back
/// and far above the zero a build that keeps the bodies produces. There is
/// nothing legitimate in between: either the plan is consumed into a closure
/// without the bodies or it is not.
const RELEASE_DROP_PERCENT_OF_BIND_RETAINED: usize = 50;

/// Backstop on total peak live heap for admitting `COMMITS` commits.
///
/// Deliberately loose, and deliberately NOT the headline. The total is set by
/// the bootstrap transaction, which is built and then committed after every
/// proof has run, so removing a proof's cost moves the phase table without
/// moving this number: base and the first fix commit both measured 995.3 MiB,
/// 904 bytes apart. Anyone tuning this constant should read the phase table
/// first, and should read `PROOF_PEAK_GROWTH_CEILING` as the real guard.
///
/// What this one catches is a gross regression: a new whole-history structure
/// large enough to move even a bootstrap-dominated total.
///
/// Tightened from 1400 MiB once two whole-history holders came out of a
/// conversion. Measured on this fixture, release, one host: 660.9 MiB before
/// the import plan's change bodies were released after proof 1 and 577.5 MiB
/// after. 900 MiB stays a loose backstop rather than a discriminator, which is
/// deliberate: the release floor below is what carries this class, and a total
/// tuned tight enough to grade it would fail on a different allocator instead
/// of on a defect.
const PEAK_HEAP_CEILING: usize = 900 * 1024 * 1024;

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
    let growth = support::peak_growth_by_phase();
    let proof_growth = growth
        .iter()
        .find(|(phase, _, _)| *phase == PROOF_PHASE)
        .map(|(_, grew, _)| *grew);
    let bind = growth
        .iter()
        .find(|(phase, _, _)| *phase == BIND_PHASE)
        .map(|(_, grew, retained)| (*grew, *retained));
    // The release phase gives memory BACK, and `peak_growth_by_phase` reports
    // what a phase retained with a saturating subtraction, so a phase that
    // frees reads zero there and says nothing. Read the entry and exit samples
    // directly instead, and measure the drop.
    let release_drop = support::samples()
        .iter()
        .position(|sample| sample.phase == RELEASE_PHASE && sample.entering)
        .and_then(|entered| {
            let samples = support::samples();
            let entry = samples[entered];
            samples[entered + 1..]
                .iter()
                .find(|sample| sample.phase == RELEASE_PHASE && !sample.entering)
                .map(|exit| entry.live.saturating_sub(exit.live))
        });

    println!(
        "peak live heap admitting {COMMITS} commits: {peak} bytes ({:.1} MiB), backstop {} MiB",
        peak as f64 / 1024.0 / 1024.0,
        PEAK_HEAP_CEILING / 1024 / 1024
    );
    // Printed on every run, not only on a breach. A guard that shows its
    // working only when it fails leaves the number that is about to become a
    // failure invisible until it is one, and this table is the only view of
    // what a conversion holds and where.
    println!("{}", support::phase_attribution_table());
    println!(
        "{PROOF_PHASE} added {} bytes to the peak, ceiling {} MiB",
        proof_growth
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "NO SAMPLE".to_string()),
        PROOF_PEAK_GROWTH_CEILING / 1024 / 1024
    );
    println!(
        "{BIND_PHASE} grew the peak by {} bytes while retaining {} bytes, ceiling {} percent",
        bind.map(|(grew, _)| grew.to_string())
            .unwrap_or_else(|| "NO SAMPLE".to_string()),
        bind.map(|(_, retained)| retained.to_string())
            .unwrap_or_else(|| "NO SAMPLE".to_string()),
        BIND_PEAK_GROWTH_PERCENT_OF_RETAINED
    );
    println!(
        "{RELEASE_PHASE} gave back {} bytes of the {} bytes {BIND_PHASE} retained, floor {} percent",
        release_drop
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "NO SAMPLE".to_string()),
        bind.map(|(_, retained)| retained.to_string())
            .unwrap_or_else(|| "NO SAMPLE".to_string()),
        RELEASE_DROP_PERCENT_OF_BIND_RETAINED
    );

    // An absent sample is not a pass. If the phase never opened, the guard
    // measured nothing and has to say so rather than report the zero that a
    // missing entry would otherwise look like.
    let proof_growth = proof_growth.unwrap_or_else(|| {
        panic!(
            "no {PROOF_PHASE} sample was recorded, so this run proved nothing about \
             what proving costs. Either the phase span was renamed or the probe was not \
             installed before the measured call.\n\n{}",
            support::phase_attribution_table()
        )
    });
    assert!(
        proof_growth < PROOF_PEAK_GROWTH_CEILING,
        "proof 1 added {proof_growth} bytes to the peak, over the \
         {PROOF_PEAK_GROWTH_CEILING} byte ceiling. That phase revalidates the import plan \
         and keeps nothing, so anything it adds is a second copy of history built to check \
         the first. This is the defect that put a full-history conversion at the ceiling of \
         a 12 GiB container.\n\n{}",
        support::phase_attribution_table()
    );
    // Two states this refuses to grade, for the same reason the proof sample
    // does: a phase that never opened measured nothing, and a phase that
    // retained nothing gives the ratio no denominator, so the comparison would
    // pass on any growth at all.
    let (bind_growth, bind_retained) = bind.unwrap_or_else(|| {
        panic!(
            "no {BIND_PHASE} sample was recorded, so this run proved nothing about what \
             binding historical semantics holds. Either the phase span was renamed or the \
             probe was not installed before the measured call.\n\n{}",
            support::phase_attribution_table()
        )
    });
    assert!(
        bind_retained > 0,
        "{BIND_PHASE} retained nothing, so there is no copy to compare its peak growth \
         against and this check graded nothing. The phase writes one set of entity and \
         relation deltas per commit into the plan, so a fixture where it keeps zero bytes \
         is not exercising it.\n\n{}",
        support::phase_attribution_table()
    );
    let bind_percent = bind_growth.saturating_mul(100) / bind_retained;
    assert!(
        bind_percent < BIND_PEAK_GROWTH_PERCENT_OF_RETAINED,
        "{BIND_PHASE} grew the peak by {bind_growth} bytes while retaining {bind_retained}, \
         {bind_percent} percent, at or over the {BIND_PEAK_GROWTH_PERCENT_OF_RETAINED} percent \
         ceiling. That phase derives one set of deltas per commit and keeps exactly one copy \
         of them, so growth of about two copies means the derived set and the plan's set are \
         alive at the same time. On a real conversion that is gigabytes.\n\n{}",
        support::phase_attribution_table()
    );
    // Same two refusals as above, for the same reasons: an absent phase measured
    // nothing, and a zero denominator would let any drop at all pass.
    let release_drop = release_drop.unwrap_or_else(|| {
        panic!(
            "no {RELEASE_PHASE} sample was recorded, so this run proved nothing about \
             whether the import plan's change bodies are given back after proof 1. Either \
             the phase span was renamed or the conversion no longer releases them.\n\n{}",
            support::phase_attribution_table()
        )
    });
    let release_percent = release_drop.saturating_mul(100) / bind_retained;
    assert!(
        release_percent >= RELEASE_DROP_PERCENT_OF_BIND_RETAINED,
        "{RELEASE_PHASE} gave back {release_drop} bytes, {release_percent} percent of the \
         {bind_retained} bytes {BIND_PHASE} retained, under the \
         {RELEASE_DROP_PERCENT_OF_BIND_RETAINED} percent floor. Proof 1 is the last reader \
         of a change's body, so past that point the plan's entity, relation and tree deltas \
         for every commit in history answer no question and must be released. Holding them \
         to the end of a conversion is over a gigabyte live across the peak on a mid-size \
         repository.\n\n{}",
        support::phase_attribution_table()
    );
    assert!(
        peak < PEAK_HEAP_CEILING,
        "admitting {COMMITS} commits peaked at {peak} bytes of live heap, over the \
         {PEAK_HEAP_CEILING} byte backstop. This total is normally set by the bootstrap \
         transaction rather than by any proof, so a breach here is a gross regression: a \
         new whole-history structure large enough to move a bootstrap-dominated \
         number.\n\n{}\n\
         Read the grew column to find which phase moved, and the retained column to tell a \
         structure held too long from allocation churn inside one phase. They need opposite \
         fixes.",
        support::phase_attribution_table()
    );
}
