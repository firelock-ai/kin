// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The refusal marker may only be applied before a command writes.
//!
//! `CommandRefusal::before_write` tells a caller nothing was published, and a
//! caller may act on that. Its correctness is a property of WHERE it is applied:
//! above the `finalize_local_repository_commit` call it is true by control flow,
//! and below that call it is a lie the transport would faithfully relay.
//!
//! That is a source-level property, so this is a source-level check, which is
//! the right layer for it and not a proxy for something else. The mutation it
//! exists to catch is moving a marker below the write, which no behavioural
//! test in this repository can reach: a post-write refusal needs a finalize
//! failure, and nothing in a fixture can make one happen on demand.
//!
//! This file is never one of the files it scans, so it cannot match itself.

use std::path::PathBuf;

// The needles are the INVOCATIONS, with their opening parenthesis, and comment
// lines are skipped before matching. Both names appear in prose in the files
// this scans, including in the comment that explains the rule, so a needle that
// matched a mention would have found the explanation and graded that. It did,
// on the first run: the write "call" it found was a sentence about the write.
const MARKER: &str = "CommandRefusal::before_write(";
const WRITE: &str = ".finalize_local_repository_commit(";

fn crate_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The lines of one function, as (line number, text), one-indexed.
fn function_lines(source: &str, signature: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains(signature))
        .unwrap_or_else(|| panic!("no function matching {signature}"));
    let end = (start..lines.len())
        .find(|index| lines[*index] == "}")
        .unwrap_or_else(|| panic!("{signature} never closes at column zero"));
    (start..=end)
        .filter(|index| !lines[*index].trim_start().starts_with("//"))
        .map(|index| (index + 1, lines[index].to_string()))
        .collect()
}

fn assert_marker_precedes_the_write(relative: &str, signature: &str) {
    let source = crate_file(relative);
    let body = function_lines(&source, signature);

    let write_line = body
        .iter()
        .find(|(_, text)| text.contains(WRITE))
        .map(|(number, _)| *number);
    // The scan proves nothing without this. A function whose write call was
    // renamed would have no line to compare against, and every marker would
    // pass by vacuum.
    let write_line = write_line.unwrap_or_else(|| {
        panic!("{relative}: {signature} has no {WRITE} call, so this check graded nothing")
    });

    let markers: Vec<usize> = body
        .iter()
        .filter(|(_, text)| text.contains(MARKER))
        .map(|(number, _)| *number)
        .collect();
    assert!(
        !markers.is_empty(),
        "{relative}: {signature} applies no marker, so this check graded nothing"
    );

    for marker in &markers {
        assert!(
            *marker < write_line,
            "{relative}: {signature} marks a refusal at line {marker} as pre-write, but the \
             authority write is at line {write_line}. A refusal raised at or below that line \
             cannot promise nothing was published."
        );
    }
}

#[test]
fn the_merge_command_marks_only_refusals_raised_before_its_write() {
    assert_marker_precedes_the_write("src/repository_merge.rs", "pub(crate) fn execute(");
}

#[test]
fn the_resolve_command_marks_only_refusals_raised_before_its_write() {
    assert_marker_precedes_the_write(
        "src/repository_merge_state.rs",
        "pub(crate) fn execute_resolve(",
    );
}

/// The control. A needle that cannot exist must find nothing, or the two checks
/// above are matching on something other than what they name.
#[test]
fn a_marker_that_does_not_exist_is_found_nowhere() {
    for relative in ["src/repository_merge.rs", "src/repository_merge_state.rs"] {
        let source = crate_file(relative);
        assert!(
            !source.contains("CommandRefusal::after_a_write_that_cannot_exist("),
            "{relative} matched a fabricated marker, so the scan matches too loosely"
        );
        // And the real needle must be present, so a scan that found nothing at
        // all cannot read as a clean pass.
        assert!(
            source.contains(MARKER),
            "{relative} carries no {MARKER}, so the checks above have no subject"
        );
    }
}
