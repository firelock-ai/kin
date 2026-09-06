// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Executable first publication of a reserved hosted repository.
//!
//! Every case here builds a real source through the exact adopting-init
//! boundary, publishes through the real primitive into a real filesystem
//! destination, and then drops every handle and reads the result back off the
//! durable files. Nothing is stubbed, and no case asserts on a value the
//! adapter merely echoed.
//!
//! The durable boundaries are reached deliberately rather than by timing a
//! signal. A run whose intent cannot be made durable stops before the
//! compare-and-swap with the bodies already written, which is exactly the state
//! a process killed there would leave, and the case that follows proves a later
//! attempt still completes from it. A signal-timed kill would reach the same
//! states less reliably and prove no more.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_cli::commands::hosted_publication::{
    install_no_replace, run_publish, run_verify, EvidenceRecord, IntentRecord, Outcome,
    PublishArgs, RefTargetRecord, VerifyArgs, EXIT_ABSENT, EXIT_CONFLICT,
};
use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_model::{Hash256, RepositoryId};
use kin_remote::first_publication::read_pinned_published_authority;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const RESERVED_ID: &str = "9f1c2e04-3b7a-4d21-9c55-0ab61d7e8f30";
const OLD_BODY: &[u8] = b"initial historical body, retained after replacement\n";
const NEW_BODY: &[u8] = b"current imported body, checked after first publication\n";
const SOURCE_INPUT_HASH: &str = "a71b0f5c2d9e4813a6c07f52b8d31e94a05c76fb28d13e0947ab65cf2081d3e7";
const REQUEST_HASH: &str = "5f2c81a30bd47e6915c8f0234ab7de91c605f3821de74a90bc3f2178e045a6d1";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn git(root: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "user.name=Publication fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Two commits, an annotated tag, and a body that only the first commit holds.
fn materialize_git_source(root: &Path) -> String {
    fs::create_dir_all(root).expect("create git source");
    git(root, &["init", "--initial-branch=main"]);
    fs::write(root.join("source.txt"), OLD_BODY).expect("write old body");
    git(root, &["add", "source.txt"]);
    git(root, &["commit", "-m", "Initial source"]);
    fs::write(root.join("source.txt"), NEW_BODY).expect("write new body");
    git(root, &["add", "source.txt"]);
    git(root, &["commit", "-m", "Update source"]);
    git(root, &["tag", "-a", "baseline", "-m", "Imported reference"]);
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .expect("read HEAD");
    String::from_utf8(output.stdout)
        .expect("HEAD is utf-8")
        .trim()
        .to_string()
}

fn operation() -> serde_json::Value {
    json!({
        "org_id": "org-7f3c",
        // A UUID, because a hosted receipt decodes this field with the same
        // decoder it uses for a repository id.
        "operation_id": "2a91c3f0-51bd-4e77-9a06-8c4127de35b1",
        "operation_revision": 7,
        "request_hash": REQUEST_HASH,
        "holder_id": "worker-3",
        "fencing_token": 4,
    })
}

fn native_manifest(destination: &Path, branch: &str) -> serde_json::Value {
    json!({
        "schema": "kin.hosted-first-publication-manifest.v1",
        "operation": operation(),
        "repository_id": RESERVED_ID,
        "source": { "kind": "native-empty", "default_branch": branch },
        "source_input_hash": SOURCE_INPUT_HASH,
        "destination": { "kind": "filesystem", "root": destination },
        "expected_authority": serde_json::Value::Null,
    })
}

fn git_manifest(
    destination: &Path,
    commit_oid: &str,
    bindings: serde_json::Value,
    scope: &str,
) -> serde_json::Value {
    json!({
        "schema": "kin.hosted-first-publication-manifest.v1",
        "operation": operation(),
        "repository_id": RESERVED_ID,
        "source": {
            "kind": "exact-git",
            "provider": "github",
            "object_format": "sha1",
            "source_commit_oid": commit_oid,
            "default_branch": "main",
            "expected_refs": { "scope": scope, "bindings": bindings },
        },
        "source_input_hash": SOURCE_INPUT_HASH,
        "destination": { "kind": "filesystem", "root": destination },
        "expected_authority": serde_json::Value::Null,
    })
}

fn write_manifest(path: &Path, value: &serde_json::Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("encode manifest"),
    )
    .expect("write manifest");
}

struct Case {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Case {
    fn new() -> Self {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().to_path_buf();
        Self { _temp: temp, root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn publish_args(&self, mode: &str) -> PublishArgs {
        PublishArgs {
            manifest: self.path("manifest.json"),
            source: self.path("source"),
            intent_out: self.path("intent.json"),
            evidence_out: self.path("evidence.json"),
            expect_repository_id: RESERVED_ID.to_string(),
            expect_mode: mode.to_string(),
        }
    }

    fn verify_args(&self, mode: &str, evidence: &str) -> VerifyArgs {
        VerifyArgs {
            manifest: self.path("manifest.json"),
            intent: Some(self.path("intent.json")),
            evidence_out: self.path(evidence),
            expect_repository_id: RESERVED_ID.to_string(),
            expect_mode: mode.to_string(),
        }
    }

    fn evidence(&self, name: &str) -> EvidenceRecord {
        let bytes = fs::read(self.path(name)).expect("read evidence");
        serde_json::from_slice(&bytes).expect("decode evidence")
    }

    fn intent(&self) -> IntentRecord {
        let bytes = fs::read(self.path("intent.json")).expect("read intent");
        serde_json::from_slice(&bytes).expect("decode intent")
    }

    /// Every authority handle is gone by the time this runs, so what it reads is
    /// the durable files and nothing else.
    fn reopen_destination(&self) -> Arc<RepositoryAuthorityManager<dyn StorageBackend>> {
        let backend: Arc<dyn StorageBackend> =
            Arc::new(LocalFileBackend::new(self.path("destination")));
        Arc::new(
            RepositoryAuthorityManager::open(
                RepositoryId::new(RESERVED_ID).expect("reserved id"),
                backend,
            )
            .expect("reopen the published authority from durable files"),
        )
    }
}

fn hash(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

// ---------------------------------------------------------------------------
// Compositions
// ---------------------------------------------------------------------------

#[test]
fn native_empty_on_a_non_default_branch_publishes_and_reopens_from_durable_files() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );

    let code = run_publish(case.publish_args("native-empty")).expect("publish a native empty");
    assert_eq!(code, 0, "a completed publication exits zero");

    let evidence = case.evidence("evidence.json");
    assert_eq!(evidence.outcome, Outcome::Published);
    let measured = evidence
        .measured
        .as_ref()
        .expect("published evidence measures");
    assert_eq!(
        measured.default_branch, "trunk",
        "the published default branch is measured off the authority, not echoed from the request"
    );
    assert_eq!(
        measured.head_change_id, None,
        "an unborn default ref names no head change"
    );
    assert_eq!(
        measured.source_closure.body_count, 0,
        "a native empty authority references no source bodies"
    );
    assert_eq!(measured.source_closure.total_bytes, 0);
    assert!(
        !measured.git_external_authority_present,
        "a native publication carries no imported Git authority"
    );
    assert_eq!(
        measured.storage_generation, "1",
        "a first publication lands at the backend's first generation"
    );
    assert_eq!(
        measured.artifact_sha256, measured.snapshot_sha256,
        "the fresh readback agrees with what the publication installed"
    );
    assert_eq!(
        evidence.echoed.source_input_hash, SOURCE_INPUT_HASH,
        "the orchestrator's own source digest is carried, never recomputed"
    );

    // Every handle above is dropped here; what follows reads durable files.
    let reopened = case.reopen_destination();
    let lease = reopened.read_authority();
    assert_eq!(
        lease.metadata().repository_id.as_str(),
        RESERVED_ID,
        "the reserved identity survives the publication"
    );
    let default_ref = lease
        .metadata()
        .ref_state
        .default_ref
        .as_ref()
        .expect("published authority carries a default ref");
    assert_eq!(
        default_ref.as_utf8(),
        Some("refs/heads/trunk"),
        "the requested non-default branch is the one that landed"
    );
    assert_eq!(
        measured.authority_root_binding.len(),
        64,
        "the root binding is a canonical 256-bit digest"
    );
}

#[test]
fn exact_git_with_two_commits_a_tag_and_a_historical_body_publishes_completely() {
    let case = Case::new();
    let commit_oid = materialize_git_source(&case.path("source"));
    write_manifest(
        &case.path("manifest.json"),
        &git_manifest(
            &case.path("destination"),
            &commit_oid,
            json!([]),
            "named-subset",
        ),
    );

    let code = run_publish(case.publish_args("exact-git")).expect("publish an exact Git import");
    assert_eq!(code, 0);

    let evidence = case.evidence("evidence.json");
    assert_eq!(evidence.outcome, Outcome::Published);
    let measured = evidence
        .measured
        .as_ref()
        .expect("published evidence measures");
    assert!(
        measured.git_external_authority_present,
        "an exact Git publication carries its imported Git authority"
    );
    assert_eq!(measured.default_branch, "main");
    let head = measured
        .head_change_id
        .as_ref()
        .expect("an imported HEAD resolves to a semantic change");
    assert_eq!(
        head.len(),
        64,
        "the head is a semantic change id, never a Git object id cast into one"
    );
    assert_ne!(
        head, &commit_oid,
        "the head change id is the alias target, not the Git commit it was imported from"
    );
    assert!(
        measured.source_closure.body_count >= 2,
        "the closure counts the replaced body as well as the current one, got {}",
        measured.source_closure.body_count
    );
    let tag = measured
        .ref_bindings
        .iter()
        .find(|binding| binding.name == "refs/tags/baseline")
        .expect("the annotated tag is one of the published ref bindings");
    assert!(
        matches!(tag.target, RefTargetRecord::ExternalObject { .. }),
        "an imported tag binds a raw Git object, {:?}",
        tag.target
    );

    let reopened = case.reopen_destination();
    for body in [OLD_BODY, NEW_BODY] {
        assert_eq!(
            reopened
                .load_source_blob(hash(body))
                .expect("read a published body")
                .as_deref(),
            Some(body),
            "every referenced body is readable from the durable destination"
        );
    }
}

#[test]
fn exact_ref_bindings_are_checked_against_the_imported_authority() {
    let case = Case::new();
    let commit_oid = materialize_git_source(&case.path("source"));
    // A binding that names the right ref and the wrong target. Names alone would
    // accept this; a binding must not.
    write_manifest(
        &case.path("manifest.json"),
        &git_manifest(
            &case.path("destination"),
            &commit_oid,
            json!([{
                "name": "refs/heads/main",
                "target": {
                    "kind": "external-object",
                    "object_kind": "commit",
                    "object_format": "sha1",
                    "oid": "0".repeat(40),
                },
            }]),
            "named-subset",
        ),
    );

    let error = run_publish(case.publish_args("exact-git"))
        .expect_err("a ref binding that does not match the import must refuse");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("refs/heads/main"),
        "the refusal names the ref that disagreed: {rendered}"
    );
    assert!(
        !case.path("destination").join("repos").exists() || destination_is_unpublished(&case),
        "a refused import publishes nothing"
    );
}

fn destination_is_unpublished(case: &Case) -> bool {
    let backend = LocalFileBackend::new(case.path("destination"));
    backend
        .load_snapshot_cursor(RESERVED_ID)
        .expect("inspect the destination")
        .is_none()
}

// ---------------------------------------------------------------------------
// Identity and second invocations
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_that_reserves_another_identity_is_refused_before_any_work() {
    let case = Case::new();
    let mut manifest = native_manifest(&case.path("destination"), "trunk");
    manifest["repository_id"] = json!("11111111-2222-4333-8444-555555555555");
    write_manifest(&case.path("manifest.json"), &manifest);

    let error = run_publish(case.publish_args("native-empty"))
        .expect_err("a manifest naming another identity must be refused");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(RESERVED_ID),
        "the refusal names the identity this invocation expected: {rendered}"
    );
    assert!(
        !case.path("intent.json").exists(),
        "an identity refusal writes no intent"
    );
    assert!(
        !case.path("source").exists(),
        "an identity refusal initializes no source"
    );
}

#[test]
fn a_mode_that_disagrees_with_the_manifest_is_refused() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );

    let error = run_publish(case.publish_args("exact-git"))
        .expect_err("a mode flag that disagrees with the manifest must be refused");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("native-empty") && rendered.contains("exact-git"),
        "the refusal names both modes: {rendered}"
    );
}

#[test]
fn an_identical_second_invocation_recovers_rather_than_republishing() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("first publication"),
        0
    );
    let first = case.evidence("evidence.json");
    let first_measured = first.measured.expect("first run measures");

    // The intent from the first run is still on disk, which is exactly the state
    // a restarted worker finds.
    let code = run_publish(case.publish_args("native-empty")).expect("second invocation");
    assert_eq!(code, 0, "a recovery is a success the caller proceeds from");
    let second = case.evidence("evidence.json");
    assert_eq!(
        second.outcome,
        Outcome::Recovered,
        "the second invocation recovers the publication it already made"
    );
    let second_measured = second.measured.expect("a recovery measures");
    assert_eq!(
        second_measured.storage_generation, first_measured.storage_generation,
        "recovery does not advance the storage generation, so nothing was overwritten"
    );
    assert_eq!(
        second_measured.artifact_sha256, first_measured.artifact_sha256,
        "recovery reads back the same authority bytes"
    );
    assert_eq!(
        second_measured.artifact_id, first_measured.artifact_id,
        "one reserved identity keeps one permanent artifact identity"
    );
}

#[test]
fn a_publication_this_run_cannot_account_for_is_a_conflict_rather_than_a_second_publication() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("first publication"),
        0
    );
    let before = case.evidence("evidence.json").measured.expect("measured");
    // A worker that lost its durable intent, which is the case the reserved
    // identity must survive rather than be republished under.
    fs::remove_file(case.path("intent.json")).expect("drop the durable intent");

    let mut args = case.publish_args("native-empty");
    args.evidence_out = case.path("stranger.json");
    let code = run_publish(args).expect("a stranger publication reports rather than throws");
    assert_eq!(
        code, EXIT_CONFLICT,
        "a publication this run cannot account for is a conflict"
    );
    let record = case.evidence("stranger.json");
    assert_eq!(record.outcome, Outcome::Conflict);
    assert!(
        record
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("no intent")),
        "the conflict says why it could not account for what it found: {:?}",
        record.detail
    );
    let after = case.reopen_destination();
    assert_eq!(
        after.read_authority().roots().generation,
        before.roots.generation,
        "a conflict changes nothing on the destination"
    );
}

// ---------------------------------------------------------------------------
// Durable boundaries
// ---------------------------------------------------------------------------

#[test]
fn a_run_that_cannot_make_its_intent_durable_stops_before_the_compare_and_swap() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    // A directory where the intent file belongs. The bodies are already written
    // by the time the intent is, so this reaches the exact durable state a
    // process killed between the body writes and the compare-and-swap leaves.
    fs::create_dir_all(case.path("intent.json")).expect("occupy the intent path");

    let error = run_publish(case.publish_args("native-empty"))
        .expect_err("a publication whose intent cannot be made durable must not commit");
    assert!(
        format!("{error:#}").contains("intent"),
        "the refusal names the intent it could not write: {error:#}"
    );
    assert!(
        destination_is_unpublished(&case),
        "no publication is installed when the intent never became durable"
    );

    // The same destination, now with bodies already written, still completes.
    fs::remove_dir(case.path("intent.json")).expect("free the intent path");
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("a later attempt completes"),
        0
    );
    assert_eq!(case.evidence("evidence.json").outcome, Outcome::Published);
}

#[test]
fn evidence_lost_after_the_compare_and_swap_is_recovered_from_the_durable_intent() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    let published = case.evidence("evidence.json").measured.expect("measured");
    // The exact durable state of a process killed after the compare-and-swap and
    // before it could report: the publication is there and the evidence is not.
    fs::remove_file(case.path("evidence.json")).expect("drop the evidence");

    let code = run_verify(case.verify_args("native-empty", "recovered.json"))
        .expect("verification reads a destination against a durable intent");
    assert_eq!(code, 0);
    let recovered = case.evidence("recovered.json");
    assert_eq!(recovered.outcome, Outcome::Recovered);
    let measured = recovered.measured.expect("a recovery measures");
    assert_eq!(measured.artifact_sha256, published.artifact_sha256);
    assert_eq!(measured.storage_generation, published.storage_generation);
    assert_eq!(
        measured.roots, published.roots,
        "the recovered roots are the published ones"
    );
}

#[test]
fn verification_reads_the_destination_and_never_the_source() {
    // A publication that is not this operation's, standing where this
    // operation's is expected. Both authorities decode cleanly and differ only
    // in their default branch, so nothing but reading the destination can tell
    // them apart, and a verifier that answered from the intent it was handed
    // would call the second one a recovery of the first.
    //
    // The stranger is moved onto this operation's own destination rather than
    // verified in place, because an intent is bound to the destination it names
    // and a manifest pointed somewhere else is refused before any reading.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish trunk"),
        0
    );
    let trunk = case
        .evidence("evidence.json")
        .measured
        .expect("the first publication measures");

    let stranger = Case::new();
    write_manifest(
        &stranger.path("manifest.json"),
        &native_manifest(&stranger.path("destination"), "release"),
    );
    assert_eq!(
        run_publish(stranger.publish_args("native-empty")).expect("publish release"),
        0
    );
    let release = stranger
        .evidence("evidence.json")
        .measured
        .expect("the second publication measures");
    assert_ne!(
        trunk.artifact_sha256, release.artifact_sha256,
        "the fixture must publish two different authorities, or this case proves nothing"
    );

    replace_directory(&case.path("destination"), &stranger.path("destination"));

    let code = run_verify(case.verify_args("native-empty", "stranger-evidence.json"))
        .expect("verification reports rather than throws");
    assert_eq!(
        code, EXIT_CONFLICT,
        "a destination holding another authority is a conflict, never a recovery"
    );
    let record = case.evidence("stranger-evidence.json");
    assert_eq!(record.outcome, Outcome::Conflict);
    let fields: Vec<&str> = record
        .differences
        .iter()
        .map(|difference| difference.field.as_str())
        .collect();
    assert!(
        fields.contains(&"snapshot_sha256"),
        "the conflict names the digest that disagreed: {fields:?}"
    );
    assert!(
        fields.contains(&"default_branch"),
        "the conflict names the branch that disagreed: {fields:?}"
    );
    let measured = record
        .measured
        .expect("a conflict still measures what it found");
    assert_eq!(
        measured.default_branch, "release",
        "the report carries what the destination actually holds, not what was intended"
    );
    assert_eq!(
        measured.artifact_sha256, release.artifact_sha256,
        "the digest is measured off the destination that was read"
    );
}

/// Put `source`'s contents where `target`'s were, leaving nothing of the old.
fn replace_directory(target: &Path, source: &Path) {
    fs::remove_dir_all(target).expect("clear the destination");
    copy_tree(source, target);
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create the copy root");
    for entry in fs::read_dir(source).expect("read the source tree") {
        let entry = entry.expect("read a source entry");
        let to = target.join(entry.file_name());
        if entry.file_type().expect("classify a source entry").is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).expect("copy a source file");
        }
    }
}

#[test]
fn a_destination_whose_bytes_no_longer_decode_is_never_a_recovery() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    corrupt_published_snapshot(&case);

    match run_verify(case.verify_args("native-empty", "corrupt.json")) {
        Ok(code) => {
            assert_ne!(code, 0, "a corrupt destination is not a success");
            let record = case.evidence("corrupt.json");
            assert_ne!(record.outcome, Outcome::Recovered);
            assert_ne!(record.outcome, Outcome::Published);
        }
        Err(error) => assert!(
            !format!("{error:#}").is_empty(),
            "a corrupt destination fails with a reason"
        ),
    }
}

/// Replace the published snapshot bytes in place, leaving everything else.
fn corrupt_published_snapshot(case: &Case) {
    let mut replaced = false;
    let mut stack = vec![case.path("destination")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            if bytes.len() > 64 && path.to_string_lossy().contains("snapshot") {
                let mut corrupted = bytes.clone();
                let last = corrupted.len() - 1;
                corrupted[last] ^= 0xff;
                fs::write(&path, corrupted).expect("corrupt the published snapshot");
                replaced = true;
            }
        }
    }
    assert!(
        replaced,
        "the fixture must actually change a published snapshot, or this case proves nothing"
    );
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[test]
fn the_intent_is_durable_before_the_publication_and_names_the_same_authority() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    let intent = case.intent();
    let measured = case.evidence("evidence.json").measured.expect("measured");
    assert_eq!(
        intent.intended_snapshot_sha256, measured.artifact_sha256,
        "what was intended before the compare-and-swap is what a fresh handle read back"
    );
    assert_eq!(intent.intended_roots, measured.roots);
    assert_eq!(intent.intended_source_closure, measured.source_closure);
    assert_eq!(intent.intended_default_branch, measured.default_branch);
    assert_eq!(intent.intended_head_change_id, measured.head_change_id);
    assert_eq!(intent.intended_ref_bindings, measured.ref_bindings);
}

#[test]
fn an_intent_recording_another_publication_is_never_replaced() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    let mut intent: serde_json::Value =
        serde_json::from_slice(&fs::read(case.path("intent.json")).expect("read intent"))
            .expect("decode intent");
    intent["intended_snapshot_sha256"] = json!("b".repeat(64));
    fs::write(
        case.path("intent.json"),
        serde_json::to_vec_pretty(&intent).expect("encode"),
    )
    .expect("install a foreign intent");

    let mut args = case.publish_args("native-empty");
    args.evidence_out = case.path("foreign.json");
    let code = run_publish(args).expect("a foreign intent is reported rather than thrown");
    assert_eq!(
        code, EXIT_CONFLICT,
        "a durable intent that names another publication is a conflict"
    );
    let record = case.evidence("foreign.json");
    assert_eq!(record.outcome, Outcome::Conflict);
    assert!(
        record
            .differences
            .iter()
            .any(|difference| difference.field == "snapshot_sha256"),
        "the conflict names the field that disagreed: {:?}",
        record.differences
    );
}

#[test]
fn a_gcs_destination_is_refused_by_name() {
    let case = Case::new();
    let mut manifest = native_manifest(&case.path("destination"), "trunk");
    manifest["destination"] = json!({ "kind": "gcs", "bucket": "kin-graph", "prefix": "hosted" });
    write_manifest(&case.path("manifest.json"), &manifest);

    let error = run_publish(case.publish_args("native-empty"))
        .expect_err("an object-store destination is not implemented by this build");
    assert!(
        format!("{error:#}").contains("destination_backend_unavailable"),
        "the refusal names the missing capability: {error:#}"
    );
}

#[test]
fn the_evidence_separates_what_was_measured_from_what_was_carried() {
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    let rendered: serde_json::Value =
        serde_json::from_slice(&fs::read(case.path("evidence.json")).expect("read evidence"))
            .expect("decode evidence");
    let measured = rendered["measured"]
        .as_object()
        .expect("measured is an object");
    let echoed = rendered["echoed"].as_object().expect("echoed is an object");
    assert!(
        !measured.contains_key("source_input_hash"),
        "an input the adapter never checked must not appear as a measurement"
    );
    assert_eq!(
        echoed["source_input_hash"],
        json!(SOURCE_INPUT_HASH),
        "the carried digest is exactly what the manifest supplied"
    );
    // No single value fills more than one measured slot except the two snapshot
    // digests, which are two independent measurements that must agree.
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in measured {
        if let Some(text) = value.as_str() {
            if text.len() == 64 {
                seen.entry(text.to_string()).or_default().push(key.clone());
            }
        }
    }
    for (value, keys) in seen {
        assert!(
            keys.len() == 1 || keys == ["artifact_sha256", "snapshot_sha256"],
            "digest {value} fills {keys:?}, which is more than one meaning"
        );
    }
}

#[test]
fn a_resumption_under_a_renewed_lease_recovers_rather_than_conflicting() {
    // The store bounds a worker lease to fifteen minutes and a renewal advances
    // the operation's revision, holder and fence. A resumption therefore holds a
    // renewed record of the same intent while the file its earlier attempt wrote
    // still carries the old one, and both are handed to this run. Treating any
    // of the three as part of the publication's identity would make those two
    // accounts of one attempt look like two publications and refuse.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("first publication"),
        0
    );
    let first = case
        .evidence("evidence.json")
        .measured
        .expect("the first run measures");

    // What the store would hand back after a renewal: the same intent, carried
    // at the current revision, holder and fence.
    let mut renewed_intent: serde_json::Value =
        serde_json::from_slice(&fs::read(case.path("intent.json")).expect("read intent"))
            .expect("decode intent");
    renewed_intent["operation"]["operation_revision"] = json!(11);
    renewed_intent["operation"]["holder_id"] = json!("worker-9");
    renewed_intent["operation"]["fencing_token"] = json!(6);
    let mut renewed = native_manifest(&case.path("destination"), "trunk");
    renewed["operation"]["operation_revision"] = json!(11);
    renewed["operation"]["holder_id"] = json!("worker-9");
    renewed["operation"]["fencing_token"] = json!(6);
    renewed["expected_authority"] = renewed_intent;
    write_manifest(&case.path("renewed.json"), &renewed);
    // The file on disk is still the pre-renewal one, which is the whole point.
    let on_disk = case.intent();
    assert_eq!(
        on_disk.operation.operation_revision, 7,
        "the fixture must leave the earlier revision on disk, or this case proves nothing"
    );

    let mut args = case.publish_args("native-empty");
    args.manifest = case.path("renewed.json");
    args.evidence_out = case.path("renewed-evidence.json");
    let code = run_publish(args).expect("a resumption under a renewed lease");
    assert_eq!(
        code, 0,
        "a renewed lease resuming its own publication is a recovery, not a conflict"
    );
    let record = case.evidence("renewed-evidence.json");
    assert_eq!(record.outcome, Outcome::Recovered);
    assert_eq!(
        record.operation.operation_revision, 11,
        "the evidence carries the revision this run was given, not the one the intent holds"
    );
    let measured = record.measured.expect("a recovery measures");
    assert_eq!(
        measured.storage_generation, first.storage_generation,
        "a resumption advances no generation"
    );
    assert_eq!(measured.artifact_sha256, first.artifact_sha256);
}

#[test]
fn a_resumption_that_names_another_operation_is_still_refused() {
    // The other half of the same rule. Revision, holder and fence may move; the
    // org, the operation and the request digest may not. An intent file outlives
    // the run that wrote it, so without this an operation could be handed a
    // stranger's intent, find the destination matching it, and report a recovery
    // for work it never did.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("first publication"),
        0
    );

    let mut foreign = native_manifest(&case.path("destination"), "trunk");
    foreign["operation"]["operation_id"] = json!("77e10b4c-9a32-4d58-b0e1-6f2c845d19aa");
    write_manifest(&case.path("foreign-op.json"), &foreign);

    let mut args = case.publish_args("native-empty");
    args.manifest = case.path("foreign-op.json");
    args.evidence_out = case.path("foreign-op-evidence.json");
    let error =
        run_publish(args).expect_err("an intent belonging to another operation must be refused");
    assert!(
        format!("{error:#}").contains("belongs to another operation"),
        "the refusal says whose intent it is: {error:#}"
    );
    assert!(
        !case.path("foreign-op-evidence.json").exists(),
        "a refusal writes no evidence record"
    );
}

#[test]
fn an_intent_recording_another_destination_is_refused() {
    // The same class as the operation check. The reading an intent is compared
    // against comes from the manifest's destination, so an intent that records a
    // different one would have its intended values checked against somewhere it
    // never wrote. Two destinations holding byte-identical authorities make that
    // concrete: without the check this reads as a clean recovery.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish here"),
        0
    );
    let here = case.intent();

    let elsewhere = Case::new();
    write_manifest(
        &elsewhere.path("manifest.json"),
        &native_manifest(&elsewhere.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(elsewhere.publish_args("native-empty")).expect("publish elsewhere"),
        0
    );
    // Deliberately not asserted equal. Each initialization mints its own
    // workspace identity, so two stores under one repository id do not publish
    // identical bytes, which is exactly why an intent has to be bound to the
    // destination it names rather than recognized by its contents. What makes
    // this case about the destination check and not about a content mismatch is
    // the refusal text asserted at the end: a content mismatch is reported as a
    // conflict record, never as a refusal.
    let there = elsewhere.intent();
    assert_ne!(
        here.intended_snapshot_sha256, there.intended_snapshot_sha256,
        "two stores mint separate workspace identities, so their publications differ"
    );

    // This operation, this authority, and the other operation's destination.
    let mut crossed = native_manifest(&elsewhere.path("destination"), "trunk");
    crossed["expected_authority"] = serde_json::to_value(&here).expect("carry the intent");
    write_manifest(&case.path("crossed-destination.json"), &crossed);

    let error = run_verify(VerifyArgs {
        manifest: case.path("crossed-destination.json"),
        intent: None,
        evidence_out: case.path("crossed-destination-evidence.json"),
        expect_repository_id: RESERVED_ID.to_string(),
        expect_mode: "native-empty".to_string(),
    })
    .expect_err("an intent recording another destination must be refused");
    assert!(
        format!("{error:#}").contains("different destination"),
        "the refusal says the intent names another destination: {error:#}"
    );
}

#[test]
fn a_destination_holding_nothing_is_absent_and_retryable() {
    // The one outcome a caller may safely retry, and the one that must never be
    // confused with a conflict. Nothing was installed, the reserved identity is
    // untouched, and a later attempt is the correct next move, so it gets its
    // own exit status rather than sharing one with a failure.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish"),
        0
    );
    let intent = case.intent();

    // The same durable intent, pointed at a destination nothing ever published
    // to.
    let empty = Case::new();
    let mut elsewhere = native_manifest(&empty.path("destination"), "trunk");
    elsewhere["expected_authority"] = serde_json::to_value(&IntentRecord {
        destination: serde_json::from_value(json!({
            "kind": "filesystem",
            "root": empty.path("destination"),
        }))
        .expect("destination spec"),
        ..intent
    })
    .expect("carry the intent");
    write_manifest(&case.path("empty.json"), &elsewhere);

    let code = run_verify(VerifyArgs {
        manifest: case.path("empty.json"),
        intent: None,
        evidence_out: case.path("empty-evidence.json"),
        expect_repository_id: RESERVED_ID.to_string(),
        expect_mode: "native-empty".to_string(),
    })
    .expect("verification reports rather than throws");
    assert_eq!(
        code, EXIT_ABSENT,
        "a destination holding nothing is absent, which is retryable, not a conflict"
    );
    let record = case.evidence("empty-evidence.json");
    assert_eq!(record.outcome, Outcome::Absent);
    assert!(
        record.measured.is_none(),
        "an absent destination measures no authority"
    );
    assert!(
        record.differences.is_empty(),
        "an absent destination disagrees with nothing"
    );
}

#[test]
fn only_one_concurrent_writer_installs_the_intent_and_the_rest_leave_it_alone() {
    // The install is what refuses, not a check before it. A check followed by a
    // rename would let every one of these writers see an empty path and then
    // replace whatever landed there while it was encoding, so the last one home
    // would destroy the record its predecessors are the only evidence for. This
    // drives that window directly rather than through a publication, because the
    // window belongs to the install and nothing above it can widen or close it.
    let case = Case::new();
    let path = case.path("contended-intent.json");
    let writers = 8;
    let barrier = Arc::new(std::sync::Barrier::new(writers));
    let installed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let handles: Vec<_> = (0..writers)
        .map(|writer| {
            let path = path.clone();
            let barrier = barrier.clone();
            let installed = installed.clone();
            std::thread::spawn(move || {
                let payload = format!("{{\"writer\":{writer}}}\n");
                barrier.wait();
                let won = install_no_replace(&path, payload.as_bytes(), "intent")
                    .expect("an install either wins or declines, and never fails here");
                if won {
                    installed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                (won, payload)
            })
        })
        .collect();

    let results: Vec<(bool, String)> = handles
        .into_iter()
        .map(|handle| handle.join().expect("a writer thread finished"))
        .collect();
    assert_eq!(
        installed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one writer may install a contended path"
    );
    let winner = results
        .iter()
        .find(|(won, _)| *won)
        .map(|(_, payload)| payload.clone())
        .expect("one writer reported the install");
    let landed = fs::read_to_string(&path).expect("read the installed intent");
    assert_eq!(
        landed, winner,
        "the bytes on disk are the winner's, untouched by every writer that declined"
    );
    // And a late writer, arriving after the contention is over, still declines.
    assert!(
        !install_no_replace(&path, b"{\"writer\":\"late\"}\n", "intent")
            .expect("a late install declines"),
        "an install never replaces what is already there"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("re-read the installed intent"),
        winner,
        "a declined install changes nothing"
    );
}

#[cfg(unix)]
#[test]
fn an_intent_path_that_is_a_symlink_is_never_written_through() {
    // A symlink is a directory entry like any other, so the install declines
    // rather than following it. Whoever can create one at this path must not be
    // able to choose what this process overwrites.
    let case = Case::new();
    let decoy = case.path("decoy.json");
    fs::write(&decoy, b"{\"decoy\":true}\n").expect("write the decoy");
    let link = case.path("linked-intent.json");
    std::os::unix::fs::symlink(&decoy, &link).expect("create the symlink");

    assert!(
        !install_no_replace(&link, b"{\"written\":\"through\"}\n", "intent")
            .expect("an install over a symlink declines"),
        "an install must not follow a symlink at its destination"
    );
    assert_eq!(
        fs::read_to_string(&decoy).expect("read the decoy"),
        "{\"decoy\":true}\n",
        "nothing was written through the link"
    );
}

#[test]
fn a_source_that_already_holds_history_cannot_be_published_as_native_empty() {
    // Absent Git metadata says a store was not imported, not that it is empty,
    // and a source directory that already holds a store is reused rather than
    // rebuilt. Without a baseline check a repository with committed content
    // would publish under a reservation that promised an empty one, and the
    // operation would carry that label for good.
    //
    // The fixture is an admitted Git repository because that is the way to build
    // real committed graph-owned content in this process. `kin commit` needs a
    // daemon and the installed `kin-daemon` here is stale (graph snapshot
    // version 8 against the CLI's 16), so driving it would test the environment
    // rather than the check. What matters is that the check under test never
    // looks at Git metadata: it reads entities, semantic changes and refs, and
    // it runs before the mode comparison, so this source exercises exactly the
    // condition it exists for.
    //
    // The store is admitted here rather than left to the publish, because the
    // publish initializes by the mode the manifest asked for: a native-empty
    // request inits natively and would produce an empty store no matter what
    // else sat in the directory. Reuse is the path under test, so the store has
    // to exist, with history, before the run begins.
    let case = Case::new();
    materialize_git_source(&case.path("source"));
    let admitted = kin_core::init_from_git_adopting(
        &case.path("source"),
        &RepositoryId::new(RESERVED_ID).expect("reserved id"),
    )
    .expect("admit the Git repository under the reserved identity");
    assert_eq!(
        admitted.repository_id.as_str(),
        RESERVED_ID,
        "the fixture must adopt the reserved identity, or the publish refuses for another reason"
    );
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "main"),
    );

    let error = run_publish(case.publish_args("native-empty"))
        .expect_err("a source with committed content is not a native-empty publication");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("requires an unborn source"),
        "the refusal says the source is not unborn: {rendered}"
    );
    assert!(
        rendered.contains("entities") || rendered.contains("semantic changes"),
        "the refusal is about graph-owned content and not only about the head: {rendered}"
    );
    assert!(
        !case.path("intent.json").exists(),
        "the refusal lands before any intent is made durable"
    );
    assert!(
        destination_is_unpublished(&case),
        "the refusal lands before the compare-and-swap"
    );
}

#[test]
fn an_unborn_native_source_is_still_accepted() {
    // The positive control for the case above. A native-empty publication is
    // valid with zero entities, zero changes and no refs, and the baseline check
    // must not have made the ordinary path unreachable.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("an unborn native source publishes"),
        0
    );
    let measured = case
        .evidence("evidence.json")
        .measured
        .expect("the publication measures");
    assert_eq!(measured.source_closure.body_count, 0);
    assert_eq!(measured.head_change_id, None);
    assert!(measured.ref_bindings.is_empty());
}

#[test]
fn a_pinned_reading_never_mixes_in_a_later_authority() {
    // Three separate reads are three separate authorities. The backend releases
    // its lock on each one, and an opened manager recovers over acknowledged
    // journal frames while a snapshot load returns only the base, so a writer
    // that advances the destination between them yields a reading whose digest
    // belongs to one authority and whose roots and refs belong to another.
    //
    // This drives that directly: bytes are pinned from one authority, the
    // destination is then advanced to a different one, and the reading must
    // still describe the pinned bytes alone. The control beneath proves the
    // destination really did advance, so a reading that agreed with it would be
    // reading storage rather than what it was given.
    let case = Case::new();
    write_manifest(
        &case.path("manifest.json"),
        &native_manifest(&case.path("destination"), "trunk"),
    );
    assert_eq!(
        run_publish(case.publish_args("native-empty")).expect("publish trunk"),
        0
    );
    let identity = RepositoryId::new(RESERVED_ID).expect("reserved id");
    let pinned_backend: Arc<dyn StorageBackend> =
        Arc::new(LocalFileBackend::new(case.path("destination")));
    let (pinned_bytes, _) = pinned_backend
        .load_snapshot(RESERVED_ID)
        .expect("read the published snapshot")
        .expect("a publication is present");

    let later = Case::new();
    write_manifest(
        &later.path("manifest.json"),
        &native_manifest(&later.path("destination"), "release"),
    );
    assert_eq!(
        run_publish(later.publish_args("native-empty")).expect("publish release"),
        0
    );
    replace_directory(&case.path("destination"), &later.path("destination"));

    let advanced: Arc<dyn StorageBackend> =
        Arc::new(LocalFileBackend::new(case.path("destination")));
    // The control. An ordinary open of this destination now describes the later
    // authority, so the pinned read below is answering from its bytes and not
    // from storage.
    let ordinary = RepositoryAuthorityManager::open(identity.clone(), advanced.clone())
        .expect("open the advanced destination");
    assert_eq!(
        ordinary
            .read_authority()
            .metadata()
            .ref_state
            .default_ref
            .as_ref()
            .and_then(|name| name.as_utf8())
            .map(str::to_string),
        Some("refs/heads/release".to_string()),
        "the fixture must actually advance the destination, or this case proves nothing"
    );
    drop(ordinary);

    let reading = read_pinned_published_authority(&identity, advanced, Arc::new(pinned_bytes))
        .expect("a pinned reading of the published bytes");
    assert_eq!(
        reading
            .authority
            .ref_state
            .default_ref
            .as_ref()
            .and_then(|name| name.as_utf8())
            .map(str::to_string),
        Some("refs/heads/trunk".to_string()),
        "the reading describes the bytes it was pinned to, never the authority now in storage"
    );
    assert_eq!(
        reading.authority.repository_id.as_str(),
        RESERVED_ID,
        "the pinned reading keeps the reserved identity"
    );
    assert_eq!(
        reading.source_closure.body_count(),
        0,
        "the pinned closure is the pinned authority's, and this one references no bodies"
    );
}

#[cfg(unix)]
#[test]
fn a_declined_install_still_flushes_the_directory_before_it_returns() {
    // The declined path is where this matters. A writer that finds the link
    // already there is about to treat that record as durable and move on to the
    // irreversible compare-and-swap, while the writer that created the link may
    // not have flushed the directory entry yet and may never get to. Whoever
    // ACCEPTS the record has to be the one who made sure it survives.
    //
    // Observed by taking the flush's own ability to run away: with the parent
    // unreadable, opening it fails, so an implementation that flushes on this
    // path reports that failure and one that skips the flush returns a cheerful
    // `false` having touched nothing.
    use std::os::unix::fs::PermissionsExt;

    let case = Case::new();
    let home = case.path("declined");
    fs::create_dir_all(&home).expect("create the install directory");
    let target = home.join("intent.json");
    assert!(
        install_no_replace(&target, b"{\"first\":true}\n", "intent").expect("the first install"),
        "the first writer installs"
    );

    let original = fs::metadata(&home)
        .expect("read directory mode")
        .permissions();
    // Write and traverse, no read: the file is still reachable by name and the
    // directory can no longer be opened.
    fs::set_permissions(&home, fs::Permissions::from_mode(0o300))
        .expect("make the directory unreadable");
    let declined = install_no_replace(&target, b"{\"second\":true}\n", "intent");
    fs::set_permissions(&home, original).expect("restore the directory mode");

    let error = declined.expect_err(
        "a declined install must flush the directory it is about to let a caller trust",
    );
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("flush intent directory"),
        "the failure names the flush it could not perform: {rendered}"
    );
    assert_eq!(
        fs::read_to_string(&target).expect("the installed record is untouched"),
        "{\"first\":true}\n",
        "a declined install changes nothing it found"
    );
}
