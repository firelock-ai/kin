// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Real-corpus phase attribution for init. Local measurement scaffolding for the
//! step 5 fold, never a CI gate: it is `#[ignore]`d, it needs a corpus handed to
//! it, and it admits real history that takes minutes even in release.

mod support;

use std::process::Command;
use std::time::Instant;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

#[test]
#[ignore]
fn real_corpus_phase_attribution() {
    let mirror = std::env::var("KIN_STEP5_CORPUS")
        .expect("set KIN_STEP5_CORPUS to a git repository or mirror path");
    let workspace = tempfile::tempdir().unwrap();
    let repo = workspace.path().join("source");
    assert!(
        Command::new("git")
            .args(["clone", &mirror])
            .arg(&repo)
            .status()
            .unwrap()
            .success(),
        "clone the corpus from {mirror}"
    );

    let out = Command::new("git")
        .current_dir(&repo)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .unwrap();
    let commits: usize = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    assert!(
        commits > 6000,
        "corpus has {commits} commits, expected real history"
    );

    support::install_phase_layer();
    let repo = repo.canonicalize().unwrap();
    support::reset_peak();
    let baseline = support::live();
    let start = Instant::now();

    kin_core::init_from_git(&repo).expect("admit the corpus");

    let elapsed = start.elapsed();
    let peak = support::peak().saturating_sub(baseline);
    println!("REAL-CORPUS PROBE");
    println!("  commits: {commits}");
    println!("  init wall: {:.1}s", elapsed.as_secs_f64());
    println!(
        "  peak live heap: {peak} bytes ({:.1} MiB)",
        peak as f64 / 1_048_576.0
    );
    println!("{}", support::phase_attribution_table());
}
