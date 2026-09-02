// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every workflow that installs Rust must name a toolchain something resolves.
//!
//! `.github/actions/rust-toolchain` takes an optional `toolchain` input and
//! otherwise reads the channel out of `rust-toolchain.toml`. When neither is
//! present it refuses rather than guessing, because a wrong toolchain installed
//! quietly turns into a compile error attributed to the code under test. That
//! refusal is correct and this guard does not weaken it. What it guards is the
//! caller: kin-search keeps no `rust-toolchain.toml`, so a workflow that omits
//! the input is asking for a refusal.
//!
//! `cache-seed.yml` did exactly that. Its step exited 1 in 34 ms on both
//! runners, and every Cache Seed run on main failed that way from 2026-08-19 to
//! 2026-09-02 (shas eb2e77c1f, 1a1b8eac1, aa101a9a3). Nothing caught it for two
//! weeks, and nothing was going to: CI has no push trigger on main here, so the
//! seed is the only workflow that runs there, and its whole output is a warm
//! cache. A cold cache is slower, never red, so the failure had no reader.
//!
//! This test is that reader. It runs inside the `cargo test` gate `ci.yml`
//! already has, so it needs no new CI wiring, and it fails on the tree rather
//! than a fortnight later on a push nobody watches.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const LOCAL_ACTION: &str = "uses: ./.github/actions/rust-toolchain";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The channel in `rust-toolchain.toml`, when the repository keeps one.
///
/// Read rather than assumed: kin-search has no such file today, but the sibling
/// primitives do, and a later decision to add one here is exactly the change
/// that should let a workflow drop its explicit input.
fn pinned_channel(root: &Path) -> Option<String> {
    let text = fs::read_to_string(root.join("rust-toolchain.toml")).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("channel") {
            let rest = rest.trim_start();
            if let Some(value) = rest.strip_prefix('=') {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The lines of the step that owns `uses_index`.
///
/// A step is a YAML sequence item, so its first line is the nearest preceding
/// line whose content starts with `- `, and it ends at the next line that
/// dedents to or past that item's own indentation. Slicing on the item rather
/// than scanning a fixed window is what keeps a `toolchain:` belonging to some
/// LATER step from being read as this one's.
fn step_lines(lines: &[&str], uses_index: usize) -> Vec<String> {
    let mut start = uses_index;
    while start > 0 && !lines[start].trim_start().starts_with("- ") {
        start -= 1;
    }
    let base = indent_of(lines[start]);

    let mut end = start + 1;
    while end < lines.len() {
        let line = lines[end];
        if !line.trim().is_empty() && indent_of(line) <= base {
            break;
        }
        end += 1;
    }
    lines[start..end].iter().map(|l| l.to_string()).collect()
}

fn declares_toolchain(step: &[String]) -> bool {
    step.iter().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#') && trimmed.starts_with("toolchain:")
    })
}

#[test]
fn every_rust_toolchain_step_resolves_a_channel() {
    let root = repo_root();
    let workflows = root.join(".github/workflows");
    let pinned = pinned_channel(&root);

    let mut inspected = 0usize;
    let mut offenders = BTreeSet::new();

    let mut entries: Vec<PathBuf> = fs::read_dir(&workflows)
        .expect("the repository must keep a .github/workflows directory")
        .map(|entry| {
            entry
                .expect("workflow directory entry must be readable")
                .path()
        })
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml") | Some("yaml")
            )
        })
        .collect();
    entries.sort();

    for path in &entries {
        let text = fs::read_to_string(path).expect("workflow file must be readable");
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || !trimmed.contains(LOCAL_ACTION) {
                continue;
            }
            inspected += 1;
            if pinned.is_none() && !declares_toolchain(&step_lines(&lines, index)) {
                offenders.insert(format!(
                    "{}:{}",
                    path.file_name()
                        .expect("workflow path has a file name")
                        .to_string_lossy(),
                    index + 1
                ));
            }
        }
    }

    // A guard that inspected nothing would pass on a tree where every caller had
    // been renamed out from under it, which is the same green it prints when
    // every caller is correct. Refuse to be that check.
    assert!(
        inspected > 0,
        "no workflow step uses {LOCAL_ACTION}, so this guard graded nothing. \
         If the local action was renamed or replaced, update LOCAL_ACTION here."
    );

    assert!(
        offenders.is_empty(),
        "these workflow steps install Rust without naming a toolchain, and this \
         repository keeps no rust-toolchain.toml for the action to fall back to, \
         so each refuses at run time with \"no toolchain resolved\": {offenders:?}"
    );
}
