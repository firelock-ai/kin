// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wall time to read every record out of a [`SemanticChangeSpool`] sized and
//! named after this repository's own commit history.
//!
//! Measures indexed reads of synthetic records carrying real commit IDs and
//! subjects. Tree and semantic deltas are empty, so this isolates spool read
//! overhead rather than measuring a full repository conversion.
//!
//! ```text
//! KIN_SPOOL_BENCH_REPO=/path/to/kin cargo test --release -p kin-git \
//!     --test history_spool_wall_time -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use chrono::DateTime;
use kin_git::SemanticChangeSpool;
use kin_model::{
    AuthorId, ChangeOrigin, GitObjectId, Hash256, SemanticChange, SemanticChangeId, Timestamp,
};
use sha2::{Digest, Sha256};

/// A synthetic record carrying a real commit ID and subject, with empty deltas.
fn change_for_commit(oid_hex: &str, subject: &str) -> SemanticChange {
    let oid_vec = hex::decode(oid_hex).expect("git log %H must be valid hex");
    let oid_bytes: [u8; 20] = oid_vec
        .try_into()
        .expect("this repository's commit oids must be 20-byte sha1");
    let id_hash: [u8; 32] = Sha256::digest(oid_hex.as_bytes()).into();
    SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes(id_hash)),
        origin: ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1(oid_bytes),
        },
        parents: Vec::new(),
        timestamp: Timestamp::from(DateTime::from_timestamp(0, 0).unwrap()),
        author: AuthorId::new("history-spool-wall-time"),
        message: subject.to_string(),
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: Vec::new(),
        admission_policy_delta: None,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    }
}

/// `(oid, subject)` for every commit reachable from HEAD, oldest first.
fn real_commits(repo: &std::path::Path) -> Vec<(String, String)> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--format=%H %s", "--reverse", "HEAD"])
        .output()
        .expect("git log must start");
    assert!(
        output.status.success(),
        "git log failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git log output must be UTF-8")
        .lines()
        .map(|line| {
            let (oid, subject) = line
                .split_once(' ')
                .expect("git log emitted an ID and subject");
            (oid.to_string(), subject.to_string())
        })
        .collect()
}

#[test]
#[ignore = "reads a real repository named by KIN_SPOOL_BENCH_REPO and takes real wall time to be worth measuring"]
fn read_at_wall_time_across_kins_own_history() {
    let Some(repo) = std::env::var_os("KIN_SPOOL_BENCH_REPO") else {
        panic!("KIN_SPOOL_BENCH_REPO must name a non-shallow Git clone to read commits from");
    };
    let repo = PathBuf::from(repo);
    let commits = real_commits(&repo);
    assert!(
        !commits.is_empty(),
        "{repo:?} produced no commits from `git log`"
    );
    let count = commits.len();

    let changes: Vec<SemanticChange> = commits
        .iter()
        .map(|(oid, subject)| change_for_commit(oid, subject))
        .collect();

    let directory = tempfile::tempdir().expect("scratch spool directory");
    let spool = SemanticChangeSpool::from_changes(directory.path(), changes)
        .expect("build a spool from every real commit");

    let started = Instant::now();
    let mut read_count = 0usize;
    for record in spool.iter() {
        record.expect("read every spooled record");
        read_count += 1;
    }
    let elapsed = started.elapsed();

    assert_eq!(read_count, count);
    println!(
        "read_at: {count} records from {repo:?} in {:.3}s ({:.1} us/record)",
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1_000_000.0 / count as f64,
    );
}
