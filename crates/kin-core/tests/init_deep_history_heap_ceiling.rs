// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Peak-heap ceiling for admitting deep Git history.
//!
//! This fixture rewrites every module across 256 commits so retaining decoded
//! history has a measurable cost. Admission must spool and stream change bodies;
//! opening the resulting authority must preserve the complete history without
//! decoding it. Explicit materialization after admission supplies a positive
//! control for phase residency and bootstrap peak growth.
//!
//! Admission's peak and phase measurements are captured before the control.
//! The proof-growth ceiling guards transient proof allocations, while the total
//! heap ceiling is a coarse backstop. Live heap counts outstanding allocations,
//! unlike resident set, which also counts freed pages retained by the allocator.
//!
//! This binary installs a counting global allocator and holds exactly one test.

mod support;

use std::path::Path;
use std::process::Command;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// Commits in the fixture history.
const COMMITS: usize = 256;

/// Modules rewritten on every commit.
const MODULES: usize = 8;

/// Types defined in each module.
const ITEMS_PER_MODULE: usize = 4;

/// Structural and source revalidation must not materialize another history.
const PROOF_PHASE: &str = "kin.init.source_proof_staged";

/// Backstop on transient peak growth during the first source proof.
const PROOF_PEAK_GROWTH_CEILING: usize = 16 * 1024 * 1024;

/// Historical semantics must be spooled without retaining decoded history.
const BIND_PHASE: &str = "kin.init.bind_historical_semantics";

/// Consuming the disk-backed plan need not produce a measurable heap drop.
const RELEASE_PHASE: &str = "kin.init.release_plan_bodies";

/// Bootstrap construction must avoid materializing the full admitted history.
const BUILD_PHASE: &str = "kin.init.build_bootstrap_transaction";

/// Admission must retain bounded state while preserving every imported change.
const ADMIT_PHASE: &str = "kin.init.admit_semantic_import";

/// The enrichment summary must read history without retaining decoded bodies.
const SUMMARY_PHASE: &str = "kin.init.commit.enrichment_summary";

/// Coarse backstop on total peak live heap, independent of the positive control.
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

    let initialized = kin_core::init_from_git(&repo).expect("admit the fixture repository");

    // Freeze admission measurements before opening or materializing the control.
    let peak = support::peak().saturating_sub(baseline);
    let growth = support::peak_growth_by_phase();
    let phase_table = support::phase_attribution_table();
    let phase = |name| {
        growth
            .iter()
            .find(|(phase, _, _)| *phase == name)
            .map(|(_, grew, retained)| (*grew, *retained))
            .unwrap_or_else(|| {
                panic!(
                    "no {name} sample was recorded; phase coverage is required.\n\n{phase_table}"
                )
            })
    };
    let (proof_growth, _) = phase(PROOF_PHASE);
    let (_, bind_retained) = phase(BIND_PHASE);
    let (build_growth, _) = phase(BUILD_PHASE);
    let (_, admit_retained) = phase(ADMIT_PHASE);
    let (_, summary_retained) = phase(SUMMARY_PHASE);
    let _ = phase(RELEASE_PHASE);

    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout)
        .expect("bind the initialized repository");
    let manager = binding
        .open_manager()
        .expect("open the repository authority");
    let authority = manager.read_authority();
    let changes = &authority.snapshot().changes;
    assert_eq!(
        changes.len(),
        COMMITS,
        "admission must preserve full history"
    );
    assert!(
        !changes.is_decoded(),
        "opening the authority must not materialize history"
    );
    let before_materialization = support::live();
    let decoded = changes
        .decoded()
        .expect("materialize history for the control");
    let materialized_history_bytes = support::live().saturating_sub(before_materialization);
    std::hint::black_box(decoded);
    assert!(
        materialized_history_bytes > 0,
        "explicit history materialization retained no bytes, so the control measured nothing"
    );

    println!(
        "peak live heap admitting {COMMITS} commits: {peak} bytes ({:.1} MiB), backstop {} MiB",
        peak as f64 / 1024.0 / 1024.0,
        PEAK_HEAP_CEILING / 1024 / 1024
    );
    println!("{phase_table}");
    println!("explicit history materialization retained {materialized_history_bytes} bytes");
    println!(
        "{PROOF_PHASE} peak growth: {proof_growth} bytes; \
         {BUILD_PHASE} peak growth: {build_growth} bytes"
    );
    println!(
        "retained bytes: {BIND_PHASE}={bind_retained}, \
         {ADMIT_PHASE}={admit_retained}, {SUMMARY_PHASE}={summary_retained}"
    );

    assert!(
        proof_growth < PROOF_PEAK_GROWTH_CEILING,
        "{PROOF_PHASE} added {proof_growth} bytes to the peak, at or over the \
         {PROOF_PEAK_GROWTH_CEILING} byte ceiling.\n\n{phase_table}"
    );
    for (name, retained) in [
        (BIND_PHASE, bind_retained),
        (ADMIT_PHASE, admit_retained),
        (SUMMARY_PHASE, summary_retained),
    ] {
        assert!(
            retained < materialized_history_bytes / 4,
            "{name} retained {retained} bytes, at or over one quarter of the \
             {materialized_history_bytes} bytes retained by explicit history materialization. \
             The phase must stream history with bounded residency.\n\n{phase_table}"
        );
    }
    assert!(
        build_growth < materialized_history_bytes / 2,
        "{BUILD_PHASE} added {build_growth} bytes to the peak, at or over one half of the \
         {materialized_history_bytes} bytes retained by explicit history materialization. \
         Bootstrap construction must avoid whole-history materialization.\n\n{phase_table}"
    );
    assert!(
        peak < PEAK_HEAP_CEILING,
        "admitting {COMMITS} commits peaked at {peak} bytes of live heap, at or over the \
         {PEAK_HEAP_CEILING} byte backstop.\n\n{phase_table}"
    );
}
