// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Live-heap profile of admitting a real repository through the library API.
//!
//! Uses the deep-history guard's `support::Counting` allocator and
//! `PhaseHeapLayer` to measure outstanding allocations, peak growth and retained
//! heap. The subject is a disposable repository named by [`REPO_ENV`]. Survey
//! counts let the caller compare measured demand with history bytes and commits.
//!
//! Run under `/usr/bin/time -l` on macOS to capture whole-process maximum RSS
//! alongside these live-heap columns. RSS includes allocator-retained pages and
//! other resident memory; the admission live-heap column subtracts its baseline.
//!
//! Allocator scope matters for budget calibration: `support::Counting` delegates
//! to `std::alloc::System`, while the shipped CLI and daemon use mimalloc. The
//! RSS measurement describes this instrument and needs an allocator-matched
//! measurement before it can justify a production budget coefficient. The
//! in-process authority reopen also does not measure a fresh daemon's memory.
//!
//! Admission writes `.kin` into the repository it admits and refuses a
//! repository that already has one, so give this a throwaway copy per run.
//!
//! This binary installs a counting global allocator and holds exactly one test.

mod support;

use std::path::PathBuf;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// The repository to admit.
const REPO_ENV: &str = "KIN_HEAP_PROFILE_REPO";

/// Ignored in every sweep, because without [`REPO_ENV`] there is no subject.
///
/// ```text
/// KIN_HEAP_PROFILE_REPO=/path/to/a/throwaway/clone \
///   cargo test --release -p kin-core --test init_real_repository_heap_profile \
///     -- --ignored --nocapture
/// ```
#[test]
#[ignore = "profiles a named real repository; the calibration driver runs it"]
fn profiling_what_admitting_a_real_repository_holds() {
    let raw = std::env::var_os(REPO_ENV)
        .unwrap_or_else(|| panic!("set {REPO_ENV} to the repository to profile"));
    let repo = PathBuf::from(&raw)
        .canonicalize()
        .unwrap_or_else(|error| panic!("{REPO_ENV}={raw:?} does not resolve: {error}"));

    // Surveyed before the counters are reset, so the survey's own allocation is
    // not charged to the conversion. This is the same function the budget calls,
    // so the numbers the coefficients are divided by are the numbers a refusal
    // would have been computed from rather than a second count of the same repo.
    let survey = kin_core::init_budget::survey_history(&repo)
        .unwrap_or_else(|reason| panic!("survey {}: {reason}", repo.display()));

    support::install_phase_layer();
    support::reset_peak();
    let baseline = support::live();
    let started = std::time::Instant::now();

    let initialized = kin_core::init_from_git(&repo)
        .unwrap_or_else(|error| panic!("admit the repository: {error}"));

    let admission_peak = support::peak().saturating_sub(baseline);
    let admission_elapsed = started.elapsed();
    let phase_table = support::phase_attribution_table();

    // Measure in-process authority reopening separately from admission to expose
    // lazy materialization and retained heap. This is not fresh-daemon RSS and
    // cannot by itself calibrate DAEMON_BYTES_PER_COMMIT.
    let before_open = support::live();
    support::reset_peak();
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout)
        .expect("bind the initialized repository");
    let manager = binding
        .open_manager()
        .expect("open the repository authority");
    let authority = manager.read_authority();
    let changes = &authority.snapshot().changes;
    let change_count = changes.len();
    let decoded_on_open = changes.is_decoded();
    let open_peak = support::peak().saturating_sub(before_open);
    let open_retained = support::live().saturating_sub(before_open);

    let per_history_byte = |bytes: usize| bytes as f64 / survey.history_bytes.max(1) as f64;
    let per_commit = |bytes: usize| bytes as f64 / survey.commits.max(1) as f64;

    // One `PROFILE` line per figure, each naming what it is, so the driver reads
    // this output rather than re-deriving anything of its own. A number computed
    // twice is a number that can disagree with itself.
    println!("PROFILE repo {}", repo.display());
    println!("PROFILE commits {}", survey.commits);
    println!("PROFILE tracked_artifacts {}", survey.tracked_artifacts);
    println!("PROFILE history_bytes {}", survey.history_bytes);
    println!("PROFILE admission_peak_live_heap_bytes {admission_peak}");
    println!(
        "PROFILE admission_peak_live_heap_per_history_byte {:.4}",
        per_history_byte(admission_peak)
    );
    println!(
        "PROFILE admission_peak_live_heap_per_commit {:.1}",
        per_commit(admission_peak)
    );
    println!(
        "PROFILE admission_seconds {:.1}",
        admission_elapsed.as_secs_f64()
    );
    println!("PROFILE open_peak_live_heap_bytes {open_peak}");
    println!("PROFILE open_retained_live_heap_bytes {open_retained}");
    println!(
        "PROFILE open_peak_live_heap_per_commit {:.1}",
        per_commit(open_peak)
    );
    println!("PROFILE changes {change_count}");
    println!("PROFILE decoded_on_open {decoded_on_open}");
    println!("{phase_table}");

    // The profile is not a gate and asserts no ceiling: a ceiling here would be a
    // number invented before the measurement it exists to take. What it does
    // assert is that the run measured the repository it was pointed at, because a
    // profile that admitted nothing would still print a tidy table of zeroes and
    // a driver would record it.
    assert_eq!(
        change_count as u64, survey.commits,
        "admitted {change_count} changes for {} surveyed commits, so this profile is not about \
         the history it counted",
        survey.commits
    );
    assert!(
        admission_peak > 0,
        "admission peaked at no bytes above its baseline, so the counters measured nothing"
    );
}
