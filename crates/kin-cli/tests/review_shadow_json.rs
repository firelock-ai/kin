// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof of the shadow-mode merge gate: a PR-shaped change (two
//! Git commits) goes in, one report comes out with a non-empty graph-proven
//! blast radius, a report-only verdict, and audit evidence. Also proves the
//! fail-loud contract: a change the graph cannot see must surface as an
//! explicit evidence gap, never as a silent pass.

use kin_cli::commands::ref_lookup::{
    git_ref_requires_hydration, resolve_ref_importing_git_if_needed_with_report,
};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

mod common;

fn kin_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kin"));
    cmd.env("KIN_DAEMON_BIN", common::fresh_daemon_bin());
    cmd
}

fn run_git(repo: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(repo);
    // Fixture commits carry explicit, strictly increasing timestamps so tests
    // that assert commit order or ancestry semantics never depend on how fast
    // the machine can commit within git's one-second timestamp granularity.
    if args.first() == Some(&"commit") {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
        let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
        cmd.env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date);
    }
    let output = cmd.output().expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_head(repo: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse HEAD");
    assert!(output.status.success(), "git rev-parse HEAD failed");
    String::from_utf8(output.stdout)
        .expect("utf8 git head")
        .trim()
        .to_string()
}

/// Fixture: base commit defines `compute_total` with a cross-file consumer
/// `render_invoice`; head commit changes `compute_total`'s signature; a
/// third commit touches only an unparsed artifact (YAML).
fn setup_fixture_repo(repo: &Path) -> (String, String, String) {
    std::fs::create_dir_all(repo.join("src")).expect("create src");
    std::fs::write(
        repo.join("src/billing.rs"),
        "pub fn compute_total(amount: u64) -> u64 {\n    amount + fee()\n}\n\nfn fee() -> u64 {\n    3\n}\n",
    )
    .expect("write billing.rs");
    std::fs::write(
        repo.join("src/invoice.rs"),
        "use crate::billing::compute_total;\n\npub fn render_invoice(amount: u64) -> String {\n    format!(\"total: {}\", compute_total(amount))\n}\n",
    )
    .expect("write invoice.rs");
    std::fs::write(
        repo.join("src/lib.rs"),
        "pub mod billing;\npub mod invoice;\n",
    )
    .expect("write lib.rs");

    run_git(repo, &["init"]);
    run_git(repo, &["config", "user.email", "shadow-test@example.com"]);
    run_git(repo, &["config", "user.name", "Shadow Test"]);
    run_git(repo, &["add", "-A"]);
    run_git(repo, &["commit", "-m", "base: billing and invoice"]);
    let base = git_head(repo);

    std::fs::write(
        repo.join("src/billing.rs"),
        "pub fn compute_total(amount: u64, currency: &str) -> u64 {\n    let _ = currency;\n    amount + fee()\n}\n\nfn fee() -> u64 {\n    3\n}\n",
    )
    .expect("rewrite billing.rs");
    run_git(repo, &["add", "-A"]);
    run_git(
        repo,
        &["commit", "-m", "head: change compute_total signature"],
    );
    let head = git_head(repo);

    std::fs::write(repo.join("policy.yaml"), "gate:\n  mode: shadow\n").expect("write yaml");
    run_git(repo, &["add", "-A"]);
    run_git(repo, &["commit", "-m", "artifact: add policy config"]);
    let artifact_head = git_head(repo);

    (base, head, artifact_head)
}

fn kin_init(repo: &Path) {
    let init = kin_command()
        .arg("init")
        .current_dir(repo)
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn run_shadow_json(repo: &Path, base: &str, head: &str) -> Value {
    let output = kin_command()
        .args(["review", "shadow", &format!("{base}..{head}"), "--json"])
        .arg("--title")
        .arg("Shadow gate smoke")
        .current_dir(repo)
        .output()
        .expect("run kin review shadow");
    assert!(
        output.status.success(),
        "kin review shadow failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("shadow report must be valid JSON on stdout")
}

#[test]
fn shadow_report_end_to_end_change_in_report_out() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    let (base, head, _artifact_head) = setup_fixture_repo(repo);
    kin_init(repo);

    let report = run_shadow_json(repo, &base, &head);

    // Contract identity: report-only shadow payload, v1.
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "shadow");
    assert_eq!(report["policy"]["enforcement"], "report_only");

    // Input echo resolves both refs to semantic changes.
    assert_eq!(report["input"]["base_ref"], Value::String(base.clone()));
    assert_eq!(report["input"]["head_ref"], Value::String(head.clone()));
    assert!(!report["input"]["resolved_base"]
        .as_str()
        .unwrap()
        .is_empty());
    assert!(!report["input"]["resolved_head"]
        .as_str()
        .unwrap()
        .is_empty());

    // The changed entity is captured with its signature change.
    let changed = report["changed_entities"].as_array().unwrap();
    assert!(
        changed
            .iter()
            .any(|entity| entity["name"] == "compute_total"
                && entity["change"] == "modified"
                && entity["signature_changed"] == true),
        "compute_total signature change must be captured: {changed:?}"
    );

    // Non-empty, graph-proven blast radius including the cross-file consumer.
    let radius = &report["blast_radius"];
    assert!(radius["total_affected"].as_u64().unwrap() >= 1);
    let dependents = radius["dependents"].as_array().unwrap();
    assert!(
        dependents
            .iter()
            .any(|dependent| dependent["name"] == "render_invoice"),
        "cross-file consumer render_invoice must appear in the blast radius: {dependents:?}"
    );

    // The gate reports what it WOULD do; a contract-surface change with
    // downstream entities must not pass silently.
    let verdict = report["policy"]["verdict"].as_str().unwrap();
    assert!(
        verdict == "would_block" || verdict == "needs_attention",
        "signature change with dependents must not pass: {verdict}"
    );
    assert!(!report["policy"]["findings"].as_array().unwrap().is_empty());

    // Repair context exists for the findings.
    assert!(!report["repair_context"].as_array().unwrap().is_empty());

    // Audit evidence: who/what/when + graph state identity.
    let audit = &report["audit"];
    for key in [
        "generated_at",
        "actor",
        "actor_kind",
        "tool",
        "tool_version",
        "base_change",
        "head_change",
    ] {
        assert!(
            !audit[key]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_default()
                .is_empty()
                || audit[key].is_number(),
            "audit.{key} must be present and non-empty: {audit:?}"
        );
    }
    assert_eq!(audit["tool"], "kin-review");
    assert!(audit["changes_in_range"].as_u64().unwrap() >= 1);

    // Cross-repo scope is labeled explicitly, never silently implied.
    assert_eq!(radius["cross_repo"]["status"], "not_evaluated");
    let gaps = report["evidence_gaps"].as_array().unwrap();
    assert!(gaps
        .iter()
        .any(|gap| gap["kind"] == "cross_repo_not_evaluated"));
}

#[test]
fn shadow_report_labels_config_only_change_without_demoting() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    let (_base, head, artifact_head) = setup_fixture_repo(repo);
    kin_init(repo);

    let report = run_shadow_json(repo, &head, &artifact_head);

    // The YAML-only change is invisible to the semantic graph: the report
    // must say so explicitly as an evidence gap.
    let gaps = report["evidence_gaps"].as_array().unwrap();
    assert!(
        gaps.iter()
            .any(|gap| gap["kind"] == "artifact_only_change" && gap["subject"] == "policy.yaml"),
        "artifact-only change must surface as an explicit evidence gap: {gaps:?}"
    );

    // A config-class artifact carries no semantic entities by design, so the
    // reported gap does not demote the verdict: a config-only change is an
    // honest pass with the gap attached, not an attention signal.
    let verdict = report["policy"]["verdict"].as_str().unwrap();
    assert_eq!(
        verdict, "pass",
        "config-class artifact gap must be reported without demoting the verdict"
    );
}

#[test]
fn shadow_report_fails_loud_on_unknown_ref() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    let (_base, head, _artifact_head) = setup_fixture_repo(repo);
    kin_init(repo);

    let output = kin_command()
        .args([
            "review",
            "shadow",
            &format!("{}..{}", "0".repeat(40), head),
            "--json",
        ])
        .current_dir(repo)
        .output()
        .expect("run kin review shadow with bogus base");
    assert!(
        !output.status.success(),
        "unknown base ref must fail loud, got stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// `HEAD^` — the idiomatic "review my last commit" — must resolve on a
/// freshly-inited repo with no further Git ancestry import: `kin init`
/// shallow-imports the current Git HEAD as a single change parented on
/// genesis, so `HEAD^` walks straight to genesis in the graph.
#[test]
fn shadow_report_head_caret_resolves_from_a_fresh_init() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    setup_fixture_repo(repo);
    kin_init(repo);

    let report = run_shadow_json(repo, "HEAD^", "HEAD");

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "shadow");
    assert!(!report["input"]["resolved_base"]
        .as_str()
        .unwrap()
        .is_empty());
    assert!(!report["input"]["resolved_head"]
        .as_str()
        .unwrap()
        .is_empty());
}

/// Caret and tilde relative-ref syntax must resolve to the same change on
/// the shadow CLI path.
#[test]
fn shadow_report_head_caret_and_head_tilde_one_agree() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    setup_fixture_repo(repo);
    kin_init(repo);

    let caret_report = run_shadow_json(repo, "HEAD^", "HEAD");
    let tilde_report = run_shadow_json(repo, "HEAD~1", "HEAD");

    assert_eq!(
        caret_report["input"]["resolved_base"], tilde_report["input"]["resolved_base"],
        "HEAD^ and HEAD~1 must resolve to the same change"
    );
}

/// A ref the resolver genuinely cannot make sense of must still fail the
/// command, but with a friendly, specific message rather than an opaque
/// HTTP 500 — the daemon now reports it as a client error.
#[test]
fn shadow_report_unsupported_ref_syntax_fails_friendly_not_opaque() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    let (_base, head, _artifact_head) = setup_fixture_repo(repo);
    kin_init(repo);

    let output = kin_command()
        .args([
            "review",
            "shadow",
            &format!("HEAD@{{upstream}}..{head}"),
            "--json",
        ])
        .current_dir(repo)
        .output()
        .expect("run kin review shadow with unsupported ref syntax");

    assert!(
        !output.status.success(),
        "unresolvable ref must still fail the command, got stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot resolve ref"),
        "error must name the ref-resolution problem plainly: {stderr}"
    );
    assert!(
        !stderr.contains("HTTP 500"),
        "an unresolvable ref must not surface as an opaque server error: {stderr}"
    );
}

/// A review pair is almost always ancestor..descendant, and `review shadow`
/// resolves the head ref before the base ref so that ancestry hydrates in a
/// single pass. This proves the invariant that makes head-first cheap: once the
/// head is imported, its ancestor base is already in the graph and needs no
/// second hydration, so the base resolve takes the fast path with no re-walk of
/// the shared history. Base-first and head-first yield the same graph state and
/// the same `hydrated_git_history` union — the only difference is that head-first
/// avoids re-importing the ancestry the base and head share.
#[test]
fn shadow_head_import_hydrates_ancestor_base_in_single_pass() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    // `base` -> `head` is a linear ancestor pair (head's parent is base).
    let (base, head, _artifact_head) = setup_fixture_repo(repo);
    kin_init(repo);

    // A fresh in-memory graph: the git commits exist on disk, but neither ref is
    // imported as a semantic change yet, so both would require hydration.
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let graph = kin_db::InMemoryGraph::new();
    assert!(
        git_ref_requires_hydration(&graph, &head),
        "head must require hydration before any import"
    );
    assert!(
        git_ref_requires_hydration(&graph, &base),
        "base must require hydration before any import"
    );

    // Resolve ONLY the head. Its import walks genesis..head, which contains base.
    let resolved_head =
        resolve_ref_importing_git_if_needed_with_report(&graph, &layout, Some(head.as_str()))
            .expect("resolve head imports its git ancestry");
    assert!(
        resolved_head.hydrated_git_history,
        "resolving the head on a fresh graph must hydrate git history"
    );

    // Single-pass invariant: base is now already present, so it needs no further
    // hydration — the head's import subsumed the ancestor.
    assert!(
        !git_ref_requires_hydration(&graph, &base),
        "after importing the head, its ancestor base must need no second pass"
    );

    // Resolving the base now takes the fast path: it resolves to a distinct
    // change without re-walking (hydrated_git_history == false).
    let resolved_base =
        resolve_ref_importing_git_if_needed_with_report(&graph, &layout, Some(base.as_str()))
            .expect("resolve base after head takes the fast path");
    assert!(
        !resolved_base.hydrated_git_history,
        "base must resolve without a second hydration pass"
    );
    assert_ne!(
        resolved_base.head, resolved_head.head,
        "base and head must resolve to distinct semantic changes"
    );
}
