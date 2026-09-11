// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every surface that shows a review's reviewers derives them.
//!
//! A review's stored assignment set is an add log. A removal is recorded as a
//! `review.unassign` audit event and never shrinks that set, because shrinking
//! it cannot express removing a review's last reviewer and leaves a later
//! re-assignment unable to reach the live graph. So a surface that reads the
//! stored set shows reviewers who were removed, and
//! `kin_review::assignments::current_assignments` is the one place that
//! subtracts them.
//!
//! This is what fails when a new read surface skips it. It counts the raw reads
//! per file rather than forbidding them outright, because the writers that keep
//! the add log read it on purpose, and a new one has to be admitted here
//! deliberately rather than by being overlooked.

const REVIEW_RECORDS: &str = include_str!("../src/records.rs");
const REVIEW_WRITE: &str = include_str!("../src/write.rs");
const CLI_REVIEW: &str = include_str!("../../kin-cli/src/commands/review.rs");
const MCP_REVIEW: &str = include_str!("../../kin-mcp/src/handlers/review.rs");
const DAEMON_REVIEW: &str = include_str!("../../kin-daemon/src/repo_review.rs");

const RAW_READ: &str = "get_review_assignments(";
const DERIVED_READ: &str = "assignments::current_assignments(";

/// What a file does, without what its tests do.
///
/// A test reads the stored set on purpose, to prove the add log still holds
/// what a removal hid, and counting those would make this guard measure the
/// tests rather than the surfaces.
fn production(source: &str) -> &str {
    source.split("\n#[cfg(test)]").next().unwrap_or(source)
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    production(haystack).matches(needle).count()
}

/// The scan can see a raw read at all, and the writers that keep the add log
/// are where they are.
///
/// Without this, every count below could be zero because the needle is wrong
/// rather than because nothing reads the stored set.
#[test]
fn the_writers_that_keep_the_add_log_read_the_stored_set() {
    for (name, source, least) in [
        (
            "kin-review write.rs, which levels a written set",
            REVIEW_WRITE,
            2,
        ),
        (
            "kin-cli review.rs, which appends an assignment",
            CLI_REVIEW,
            1,
        ),
        (
            "kin-mcp review.rs, which appends and records a removal",
            MCP_REVIEW,
            2,
        ),
    ] {
        let found = occurrences(source, RAW_READ);
        assert!(
            found >= least,
            "{name} reads the stored set {found} time(s); this scan expected at least {least}, so \
             either a writer stopped keeping the add log or the needle no longer matches"
        );
    }
    assert_eq!(
        occurrences(CLI_REVIEW, "get_review_assignments_no_crate_has("),
        0,
        "the must-miss control matched, so a count above proves nothing"
    );
}

/// No surface that shows a review reads the stored set.
#[test]
fn no_review_read_surface_reads_the_stored_assignment_set() {
    for (name, source) in [
        (
            "kin-review records.rs, where every surface reads a review",
            REVIEW_RECORDS,
        ),
        ("kin-daemon repo_review.rs", DAEMON_REVIEW),
    ] {
        let found = occurrences(source, RAW_READ);
        assert_eq!(
            found, 0,
            "{name} reads the stored assignment set {found} time(s), so it shows reviewers a \
             removal already took off; read them through \
             kin_review::assignments::current_assignments instead"
        );
    }
    assert_eq!(
        occurrences(REVIEW_RECORDS, DERIVED_READ),
        1,
        "records.rs must derive a review's reviewers exactly once, which is what every surface \
         that shows a review reads"
    );
}

/// The reviewers a review has come from one function, so two surfaces cannot
/// disagree about who they are.
#[test]
fn one_function_answers_who_the_reviewers_are() {
    let derivations = occurrences(REVIEW_RECORDS, DERIVED_READ)
        + occurrences(CLI_REVIEW, DERIVED_READ)
        + occurrences(MCP_REVIEW, DERIVED_READ)
        + occurrences(DAEMON_REVIEW, DERIVED_READ);
    assert!(
        derivations >= 2,
        "only {derivations} call site(s) derive the reviewers; the read path and the removal \
         planner both have to, or a removal is decided against the wrong set"
    );
}
