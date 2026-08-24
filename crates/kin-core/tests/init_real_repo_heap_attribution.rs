// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Allocator-exact phase attribution for admitting a REAL Git repository.
//!
//! The synthetic fixtures price a shape. This one prices a repository a user
//! actually converts, because the proportions between the whole-history
//! structures follow per-commit semantic churn and no synthetic fixture
//! reproduces that: psf/requests and expressjs/express have similar commit
//! counts and land on opposite sides of a 12 GiB cap.
//!
//! Not a gate. It asserts nothing about a ceiling and takes a repository path
//! from the environment, so it reports rather than grades.
//!
//! ```text
//! KIN_HEAP_REPO=/path/to/clone cargo test --release -p kin-core \
//!     --test init_real_repo_heap_attribution -- --ignored --nocapture
//! ```

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

/// Copy the source repository so the admission writes its `.kin` beside a
/// scratch copy rather than into the caller's clone.
fn stage_copy(source: &Path, into: &Path) -> PathBuf {
    let staged = into.join("source");
    let status = Command::new("cp")
        .args(["-a".as_ref(), source.as_os_str(), staged.as_os_str()])
        .status()
        .expect("cp failed to start");
    assert!(status.success(), "cp -a {source:?} {staged:?} failed");
    staged.canonicalize().expect("canonicalize staged copy")
}

#[test]
#[ignore = "reads a real repository named by KIN_HEAP_REPO and takes minutes"]
fn admitting_a_real_repository_reports_where_the_peak_is() {
    let Some(source) = std::env::var_os("KIN_HEAP_REPO") else {
        panic!("KIN_HEAP_REPO must name a non-shallow Git clone to admit");
    };
    let source = PathBuf::from(source);
    assert!(
        source.join(".git").exists(),
        "{source:?} is not a Git checkout"
    );

    let workspace = tempfile::tempdir().expect("scratch workspace");
    let repo = stage_copy(&source, workspace.path());

    support::install_phase_layer();
    support::reset_peak();
    let baseline = support::live();
    let started = std::time::Instant::now();

    let outcome = kin_core::init_from_git(&repo);

    let wall = started.elapsed();
    let peak = support::peak().saturating_sub(baseline);

    println!(
        "repository {source:?}\npeak live heap: {peak} bytes ({:.2} GiB) in {:.0} s, outcome {}",
        peak as f64 / 1024.0 / 1024.0 / 1024.0,
        wall.as_secs_f64(),
        if outcome.is_ok() { "ok" } else { "ERROR" },
    );
    println!("{}", support::phase_attribution_table());
    outcome.expect("admit the repository");
}
