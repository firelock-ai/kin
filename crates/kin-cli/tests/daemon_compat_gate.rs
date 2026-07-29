// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The reuse decision behind `common::fresh_daemon_bin`.
//!
//! A daemon that is version-compatible but built from a different tree is the
//! failure this gate exists for: it serves the repository correctly and then
//! rejects every vector sidecar the test binary seeded, because the two stamp
//! different embedder identities. The suite then reports zero indexed
//! embeddings as a product defect. These cases pin the comparison so that
//! skew is caught and named instead.

use serde_json::json;

mod common;

use common::{daemon_compat_mismatch, expected_build_stamp};

const VERSION: u64 = 9;
const SHA: &str = "1111111111111111111111111111111111111111";
const OTHER_SHA: &str = "2222222222222222222222222222222222222222";

fn payload(sha: &str, dirty: bool, version: u64) -> serde_json::Value {
    json!({
        "schema": "kin.daemon.compat.v1",
        "graph_snapshot_version": version,
        "build": { "sha": sha, "dirty": dirty },
    })
}

#[test]
fn matching_version_and_build_identity_is_reusable() {
    assert_eq!(
        daemon_compat_mismatch(&payload(SHA, false, VERSION), VERSION, SHA),
        None
    );
}

#[test]
fn snapshot_version_skew_is_still_caught() {
    let reason = daemon_compat_mismatch(&payload(SHA, false, VERSION + 1), VERSION, SHA)
        .expect("a daemon on another snapshot version must not be reused");
    assert!(
        reason.contains(&(VERSION + 1).to_string()) && reason.contains(&VERSION.to_string()),
        "reason must name both versions, got {reason}"
    );
}

#[test]
fn build_identity_skew_names_both_stamps() {
    let reason = daemon_compat_mismatch(&payload(OTHER_SHA, false, VERSION), VERSION, SHA)
        .expect("a daemon built from another commit must not be reused");
    assert!(
        reason.contains(OTHER_SHA) && reason.contains(SHA),
        "reason must name the daemon stamp and the test binary stamp, got {reason}"
    );
}

#[test]
fn dirty_flag_skew_is_a_mismatch() {
    let reason = daemon_compat_mismatch(&payload(SHA, true, VERSION), VERSION, SHA)
        .expect("a dirty daemon must not be reused by a clean test binary");
    assert!(
        reason.contains(&format!("{SHA}-dirty")),
        "reason must name the dirty stamp, got {reason}"
    );
}

/// With no commit id there is no identity to skew, and `sha_with_dirty` drops
/// the dirty flag. Comparing the raw pair instead of the joined stamp would
/// reject a daemon whose embedder identity actually matches, and no rebuild
/// would ever clear it.
#[test]
fn unknown_commit_ignores_the_dirty_flag() {
    assert_eq!(
        daemon_compat_mismatch(&payload("unknown", true, VERSION), VERSION, "unknown"),
        None
    );
}

#[test]
fn a_compat_payload_without_build_identity_is_not_reusable() {
    let payload = json!({ "graph_snapshot_version": VERSION });
    let reason = daemon_compat_mismatch(&payload, VERSION, SHA)
        .expect("a daemon that reports no build identity must not be reused");
    assert!(
        reason.contains("build.sha"),
        "reason must name the missing field, got {reason}"
    );
}

/// Pins the harness's `build.sha` + `build.dirty` join against
/// `kin_buildinfo::sha_with_dirty`, which is what the daemon actually stamps
/// sidecars with. If that rule changes and this join does not, every daemon
/// would look skewed and no rebuild would clear it.
#[test]
fn the_joined_stamp_agrees_with_kin_buildinfo() {
    let info = kin_buildinfo::get();
    assert_eq!(
        daemon_compat_mismatch(
            &payload(info.sha, info.dirty, VERSION),
            VERSION,
            &expected_build_stamp()
        ),
        None,
        "this binary's own build identity must read as reusable"
    );
}
