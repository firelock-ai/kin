// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The verdict's codes are one closed list, and two things hold it closed.
//!
//! `docs/mcp-tools.md` carries the list's table row for row, so the page a
//! reader looks a code up in cannot drift from the list the verdict reads. And
//! every clause label a producer in kin-mcp or kin-core writes is on the list,
//! so a new reason cannot reach a response as a code nobody can look up. The
//! verdict sends an unlisted label as `unlisted_clause` rather than mint it; this
//! scan is what keeps that fallback from ever being needed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kin_mcp::verdict::{CLAUSE_CODES, UNLISTED_CLAUSE_CODE};

/// Labels the scan finds that are not verdict clauses, each with where it lives
/// and what it is instead. Every entry must still be found by the scan, so a
/// stale allowance fails rather than quietly widening what passes.
const NOT_CLAUSES: &[(&str, &str)] = &[
    (
        "kin",
        "kin-core layout.rs: the prefix of a CLI refusal message",
    ),
    (
        "parse_hole",
        "kin-core reference_coverage.rs: a census label no MCP verdict carries",
    ),
    ("phase", "startup_binding.rs: a startup progress label"),
    (
        "spine_unavailable",
        "handlers/review.rs: the cross_repo_impact_status payload field",
    ),
    (
        "staged_byte_limit_exceeded",
        "session.rs: a transaction refusal code",
    ),
    (
        "staged_operation_limit_exceeded",
        "session.rs: a transaction refusal code",
    ),
    (
        "trace_computation",
        "handlers/entities.rs: a tool error message prefix",
    ),
    (
        "trace_data_flow",
        "handlers/entities.rs: a tool error message prefix",
    ),
    (
        "transaction_limit_exceeded",
        "session.rs: a session refusal code",
    ),
    ("warning", "kin-core init_attempt.rs: a CLI warning line"),
];

/// A label written with a placeholder, and every code it can expand to.
const PATTERNS: &[(&str, &[&str])] =
    &[("substrate_{}", &["substrate_partial", "substrate_unknown"])];

/// Listed codes no literal names, each with the source that produces it.
const SOURCED_ELSEWHERE: &[(&str, &str)] = &[
    (
        "cross_repo_unavailable",
        "negative.rs cross_repo_unavailable_qualifier, the label for a spine answer naming no code",
    ),
    (
        "spine_root_stale",
        "handlers/entities.rs SPINE_ROOT_STALE, a spine's code carried as the label",
    ),
    ("unlisted_clause", "verdict.rs, the fallback itself"),
];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The production half of a source file: everything before its test module,
/// with line comments dropped, so a doc example or a test fixture cannot put a
/// label on the list or take one off it.
fn production_source(text: &str) -> String {
    let body = match text.find("\n#[cfg(test)]") {
        Some(cut) => &text[..cut],
        None => text,
    };
    body.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every label a string literal opens with (`"label: ...`), and every value of
/// a `*_LIMITING_FACTOR` constant.
fn labels_in(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = source.as_bytes();
    for (index, _) in source.match_indices('"') {
        let rest = &source[index + 1..];
        let label: String = rest
            .chars()
            .take_while(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '{' | '}')
            })
            .collect();
        let opens_clause = !label.is_empty()
            && label.as_bytes()[0].is_ascii_lowercase()
            && rest[label.len()..].starts_with(": ")
            && (index == 0 || bytes[index - 1] != b'\\');
        if opens_clause {
            found.insert(label);
        }
    }
    for (index, _) in source.match_indices("_LIMITING_FACTOR: &str = \"") {
        let value_start = index + "_LIMITING_FACTOR: &str = \"".len();
        if let Some(end) = source[value_start..].find('"') {
            found.insert(source[value_start..value_start + end].to_string());
        }
    }
    found
}

fn scanned_labels() -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(&crate_dir().join("src"), &mut files);
    rust_files(&crate_dir().join("../kin-core/src"), &mut files);
    assert!(
        files.len() > 20,
        "the scan read {} files, so it read almost nothing",
        files.len()
    );
    let mut labels = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        labels.extend(labels_in(&production_source(&text)));
    }
    labels
}

#[test]
fn every_clause_label_a_producer_writes_is_listed() {
    let scanned = scanned_labels();
    // The control: a label the verdict is known to write, and enough of them
    // that a scanner which matched nothing cannot pass.
    assert!(
        scanned.contains("edge_coverage_unknown"),
        "the scan missed a known producer: {scanned:?}"
    );
    assert!(
        scanned.len() >= 50,
        "the scan found only {} labels: {scanned:?}",
        scanned.len()
    );

    let listed: BTreeSet<&str> = CLAUSE_CODES.iter().map(|entry| entry.code).collect();
    let not_clauses: BTreeSet<&str> = NOT_CLAUSES.iter().map(|(label, _)| *label).collect();
    let mut unlisted = Vec::new();
    let mut produced: BTreeSet<String> = BTreeSet::new();
    for label in &scanned {
        if not_clauses.contains(label.as_str()) {
            continue;
        }
        if label.contains('{') {
            match PATTERNS.iter().find(|(pattern, _)| pattern == label) {
                Some((_, codes)) => produced.extend(codes.iter().map(|code| code.to_string())),
                None => unlisted.push(format!(
                    "{label} (a placeholder label with no PATTERNS entry)"
                )),
            }
            continue;
        }
        if listed.contains(label.as_str()) {
            produced.insert(label.clone());
        } else {
            unlisted.push(label.clone());
        }
    }
    assert!(
        unlisted.is_empty(),
        "a producer writes clause labels the closed list does not carry, so the verdict would send \
         them as {UNLISTED_CLAUSE_CODE}: {unlisted:?}. List each in verdict.rs CLAUSE_CODES and in \
         docs/mcp-tools.md, or name it in NOT_CLAUSES with what it is instead."
    );

    let stale_allowances: Vec<&str> = NOT_CLAUSES
        .iter()
        .map(|(label, _)| *label)
        .filter(|label| !scanned.contains(*label))
        .collect();
    assert!(
        stale_allowances.is_empty(),
        "NOT_CLAUSES names labels no source writes: {stale_allowances:?}"
    );

    let elsewhere: BTreeSet<&str> = SOURCED_ELSEWHERE.iter().map(|(code, _)| *code).collect();
    let never_produced: Vec<&str> = listed
        .iter()
        .copied()
        .filter(|code| !produced.contains(*code) && !elsewhere.contains(code))
        .collect();
    assert!(
        never_produced.is_empty(),
        "CLAUSE_CODES lists codes no producer writes, so the docs promise codes a reader will never \
         see: {never_produced:?}"
    );
}

#[test]
fn the_docs_code_table_is_the_closed_list() {
    let path = crate_dir().join("../../docs/mcp-tools.md");
    let docs = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let begin = docs
        .find("<!-- clause-codes:begin -->")
        .expect("the docs carry the table's begin marker");
    let end = docs
        .find("<!-- clause-codes:end -->")
        .expect("the docs carry the table's end marker");
    let rows: Vec<&str> = docs[begin..end]
        .lines()
        .filter(|line| line.starts_with("| `"))
        .collect();
    let expected: Vec<String> = CLAUSE_CODES
        .iter()
        .map(|entry| format!("| `{}` | {} |", entry.code, entry.meaning))
        .collect();
    assert_eq!(
        rows,
        expected.iter().map(String::as_str).collect::<Vec<_>>(),
        "docs/mcp-tools.md and CLAUSE_CODES disagree; the rows the docs should carry are:\n{}",
        expected.join("\n")
    );
}

#[test]
fn the_list_is_sorted_unique_and_holds_no_separator() {
    let codes: Vec<&str> = CLAUSE_CODES.iter().map(|entry| entry.code).collect();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        codes, sorted,
        "CLAUSE_CODES must be in code order with no duplicate"
    );
    for entry in CLAUSE_CODES {
        assert!(
            entry
                .code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "a code is snake_case and so can never hold the separator: {}",
            entry.code
        );
        assert!(
            !entry.meaning.contains('|'),
            "a meaning with a pipe breaks the docs table: {}",
            entry.code
        );
    }
}
