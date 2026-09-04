// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Day-one instrument for the FIR-2729 bootstrap receive.
//!
//! This asks the one question every later phase of the capability depends on,
//! and it asks it at the library seam rather than over the wire, because the
//! wire cannot be built until the answer is known: **can an empty replica
//! commit the generation-zero-shaped transaction a bootstrap receive would
//! send, carrying real content, and then hold the result?**
//!
//! Four refusals are already known to sit between a Git-admitted store and an
//! empty hosted replica, and only the first has ever been observed. This probe
//! goes past the first three deliberately, by hand-building the transaction
//! instead of negotiating a pack, so that the fourth is reached and any fifth
//! is discovered here rather than three weeks into building routes on top of
//! an assumption.
//!
//! What it deliberately does NOT do: negotiate, build a pack, cross HTTP, or
//! prove anything about the protocol. It probes the storage boundary alone.
//! A pass here says route (a) is legal. It does not say route (a) works.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use kin_db::{LocalFileBackend, PersistedRepositoryAuthority, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, DefaultRefExpectation, DefaultRefMutation, GitExternalAuthorityDelta, Hash256,
    OperationId, RefExpectation, RefMutation, RefUpdatePolicy, RepositoryId, RepositoryTransaction,
    SemanticChange, SemanticChangeId, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

/// One fixture path with bytes nothing else in the tree could produce, so a
/// read-back that returns them cannot be a default, an empty state, or another
/// fixture's leftovers.
const PROBE_PATH: &str = "service/compose.yaml";
const PROBE_PATH_DIR: &str = "service";
const PROBE_BYTES: &[u8] = b"services:\n  api:\n    image: fir2729-probe-payload-marker\n";

fn git(working: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(working)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .unwrap_or_else(|error| panic!("git {args:?} failed to start: {error}"));
    assert!(status.success(), "git {args:?} exited {status}");
}

/// A hosted-shaped repository identity: a slug, not UUID text, which is what
/// the hosted daemon serves and what `--adopt-repository-id` now admits.
fn hosted_shaped_id() -> RepositoryId {
    RepositoryId::new(format!(
        "kin-fir2729-probe-{}",
        uuid::Uuid::new_v4().simple()
    ))
    .unwrap()
}

/// Every immutable body the transaction below will name, from both producers.
///
/// Two producers, and missing either one is a refusal at a different line:
/// the Git object closure the authority describes, and the blob each tree
/// delta introduces. They are collected together because the destination has
/// to hold the union before the transaction commits, not one or the other.
fn required_bodies(
    metadata: &PersistedRepositoryAuthority,
    changes: &[SemanticChange],
) -> BTreeSet<Hash256> {
    let mut hashes = BTreeSet::new();
    for record in &metadata.external_objects {
        hashes.insert(record.body_hash);
    }
    if let Some(authority) = metadata.git_external_authority.as_ref() {
        for entry in &authority.closure.objects {
            hashes.insert(entry.record.body_hash);
        }
    }
    for change in changes {
        for delta in &change.tree_deltas {
            if let Some(state) = delta.new_state() {
                if let Some(hash) = state.entry.blob_identity() {
                    hashes.insert(hash);
                }
            }
        }
    }
    hashes
}

/// Order changes parent-before-child, which every admission path requires and
/// which a map's iteration order does not give.
fn topological(changes: &[SemanticChange]) -> Vec<SemanticChange> {
    let mut ordered: Vec<SemanticChange> = Vec::with_capacity(changes.len());
    let mut placed: HashSet<SemanticChangeId> = HashSet::new();
    let mut remaining: Vec<SemanticChange> = changes.to_vec();
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut deferred = Vec::new();
        for change in remaining {
            if change.parents.iter().all(|parent| placed.contains(parent)) {
                placed.insert(change.id);
                ordered.push(change);
            } else {
                deferred.push(change);
            }
        }
        remaining = deferred;
        assert!(
            remaining.len() < before,
            "change closure has a cycle or a missing parent; {} changes could not be ordered",
            remaining.len()
        );
    }
    ordered
}

/// Build a Git worktree of `commits` commits. The first carries the probe
/// path and its marker bytes; each later one ADDS a new path, so the change
/// closure is a real chain rather than one change repeated.
fn build_publisher(root: &std::path::Path, commits: usize) -> std::path::PathBuf {
    assert!(commits >= 1, "a publisher needs at least one commit");
    let working = root.join("work");
    std::fs::create_dir_all(working.join("service")).unwrap();
    std::fs::write(working.join(PROBE_PATH), PROBE_BYTES).unwrap();
    git(&working, &["init", "--initial-branch=main"]);
    git(&working, &["config", "user.email", "probe@example.invalid"]);
    git(&working, &["config", "user.name", "FIR-2729 Probe"]);
    git(&working, &["add", "--all"]);
    git(&working, &["commit", "-s", "-m", "payload for the probe"]);
    for index in 1..commits {
        let path = format!("service/added-{index:03}.txt");
        std::fs::write(
            working.join(&path),
            format!("fir2729 probe payload for commit {index}\n"),
        )
        .unwrap();
        git(&working, &["add", "--all"]);
        git(&working, &["commit", "-s", "-m", &format!("add {path}")]);
    }
    working
}

#[test]
fn an_empty_replica_admits_the_bootstrap_transaction_a_git_admitted_store_would_send() {
    bootstrap_probe(1);
}

/// The same probe over a real chain of commits.
///
/// The single-commit arm exercises no ordering at all: one change is
/// trivially parent-before-child, so the closure ordering, the alias set, the
/// growing external-object closure and the ref target's distance from the root
/// are all untested by it. This arm is what says a history rather than a
/// snapshot bootstraps, which is the difference between "adoption at tip" and
/// "full history under the ceilings" in the sizing tables.
#[test]
fn an_empty_replica_admits_a_multi_commit_history_in_one_bootstrap_transaction() {
    bootstrap_probe(12);
}

/// Does the STORAGE seam carry ceilings of its own, or are bound 3's ceilings
/// purely a transfer-v1 artifact?
///
/// This is the question that decides increment 2's options. The pack caps a
/// transfer at 4096 external objects and 16 MiB of decoded bodies, and this
/// probe bypasses the pack entirely by committing at the storage boundary. So
/// if a publisher past BOTH caps still commits here, the ceilings are a
/// protocol choice and raising them is a protocol decision. If storage refuses
/// too, they are a real limit and segmentation is the only route.
///
/// One fixture crosses both caps at once: 4200 files of roughly 4 KiB each is
/// over 4096 objects and over 16 MiB.
#[test]
#[ignore = "builds a 4200-file repository; run explicitly with --ignored"]
fn the_storage_seam_admits_a_publisher_past_both_transfer_v1_ceilings() {
    bootstrap_probe_wide(4200, 4096);
}

fn bootstrap_probe_wide(files: usize, bytes_each: usize) {
    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let working = source_root.path().join("work");
    std::fs::create_dir_all(working.join("wide")).unwrap();
    std::fs::write(
        working.join(PROBE_PATH_DIR).join("compose.yaml"),
        PROBE_BYTES,
    )
    .ok();
    std::fs::create_dir_all(working.join("service")).unwrap();
    std::fs::write(working.join(PROBE_PATH), PROBE_BYTES).unwrap();
    let filler: Vec<u8> = (0..bytes_each).map(|i| b'a' + (i % 26) as u8).collect();
    for index in 0..files {
        // Vary the first bytes so every blob is a distinct object rather than
        // one object referenced 4200 times, which would measure nothing.
        let mut body = format!(
            "fir2729-wide-{index:06}
"
        )
        .into_bytes();
        body.extend_from_slice(&filler);
        std::fs::write(working.join(format!("wide/f{index:06}.txt")), &body).unwrap();
    }
    git(&working, &["init", "--initial-branch=main"]);
    git(&working, &["config", "user.email", "probe@example.invalid"]);
    git(&working, &["config", "user.name", "FIR-2729 Probe"]);
    git(&working, &["add", "--all"]);
    git(
        &working,
        &["commit", "-s", "-m", "wide payload for the ceiling probe"],
    );

    let init = kin_core::init_from_git_adopting(&working, &repository_id)
        .expect("a wide Git-admitted store may adopt a hosted repository identity");
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .expect("binding")
        .open_manager()
        .expect("open");

    let (metadata, changes, default_ref, target, generation) = {
        let lease = source.read_authority();
        let metadata = lease.metadata().clone();
        let changes: Vec<SemanticChange> = lease.snapshot().changes.values().cloned().collect();
        let default_ref = metadata.ref_state.default_ref.clone().expect("default ref");
        let target = metadata
            .ref_state
            .refs
            .iter()
            .find(|entry| entry.name == default_ref)
            .map(|entry| entry.target.clone())
            .expect("default ref resolves");
        let generation = lease.roots().generation;
        (metadata, changes, default_ref, target, generation)
    };
    let ordered_changes = topological(&changes);
    let git_authority = metadata
        .git_external_authority
        .clone()
        .expect("a Git-admitted store carries imported-Git authority");

    let bodies = required_bodies(&metadata, &ordered_changes);
    let object_count = metadata.external_objects.len();
    assert!(
        object_count > 4096,
        "the fixture must cross MAX_TRANSFER_EXTERNAL_OBJECTS or it measures nothing; got {object_count}"
    );

    let destination_root = tempfile::tempdir().unwrap();
    let destination = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(destination_root.path().to_path_buf())),
    )
    .expect("empty store opens");
    let (destination_roots, destination_generation) = {
        let lease = destination.read_authority();
        (lease.roots().clone(), lease.roots().generation)
    };

    let mut staged_bytes = 0u64;
    for hash in &bodies {
        let payload = source
            .load_source_blob(*hash)
            .expect("read")
            .unwrap_or_else(|| panic!("publisher missing body {hash}"));
        staged_bytes += payload.len() as u64;
        destination
            .save_source_blob(*hash, &payload)
            .expect("stage");
    }
    assert!(
        staged_bytes > 16 * 1024 * 1024,
        "the fixture must cross MAX_TRANSFER_DECODED_BODY_BYTES or it measures nothing; got {staged_bytes}"
    );
    eprintln!(
        "PROBE wide publisher: generation={generation} changes={} external_objects={object_count} \
         distinct_bodies={} staged_bytes={staged_bytes} ({:.2} MiB)",
        ordered_changes.len(),
        bodies.len(),
        staged_bytes as f64 / 1048576.0,
    );

    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: repository_id.clone(),
        expected_generation: destination_generation,
        expected_roots: destination_roots,
        actor: AuthorId::new("fir2729-bootstrap-probe"),
        reason: "probe: bootstrap past both transfer v1 ceilings".to_string(),
        external_objects: metadata.external_objects.clone(),
        git_authority_delta: Some(GitExternalAuthorityDelta::initialize(git_authority)),
        changes: ordered_changes.clone(),
        aliases: metadata.aliases.clone(),
        ref_mutations: vec![RefMutation {
            name: default_ref.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(default_ref),
        }),
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    match transaction.validate() {
        Ok(()) => eprintln!("PROBE wide model validate: OK"),
        Err(error) => panic!("PROBE WIDE STOPPED AT MODEL VALIDATION: {error}"),
    }
    let started = std::time::Instant::now();
    match destination.commit_repository_transaction(transaction) {
        Ok(receipt) => eprintln!(
            "PROBE WIDE RESULT: storage ADMITTED {object_count} objects and {:.2} MiB in one \
             transaction, outcome={:?} generation={} in {:.1}s. Bound 3's ceilings are a \
             transfer-v1 protocol choice, not a storage limit.",
            staged_bytes as f64 / 1048576.0,
            receipt.outcome,
            receipt.generation,
            started.elapsed().as_secs_f64(),
        ),
        Err(error) => panic!("PROBE WIDE STOPPED AT STORAGE ADMISSION: {error}"),
    }
}

fn bootstrap_probe(commits: usize) {
    let repository_id = hosted_shaped_id();

    // --- the publisher: a real Git worktree with real content, adopting the
    // hosted identity, exactly as the FIR-2724 fix made possible.
    let source_root = tempfile::tempdir().unwrap();
    let working = build_publisher(source_root.path(), commits);

    let init = kin_core::init_from_git_adopting(&working, &repository_id)
        .expect("a Git-admitted store may adopt a hosted repository identity");
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .expect("the store just created has a local authority binding")
        .open_manager()
        .expect("the store just created opens");

    // --- read everything the bootstrap would carry, from one coherent lease.
    let (
        metadata,
        source_changes,
        default_ref,
        source_target,
        source_generation,
        source_body_count,
    ) = {
        let lease = source.read_authority();
        let metadata = lease.metadata().clone();
        let changes: Vec<SemanticChange> = lease.snapshot().changes.values().cloned().collect();
        let default_ref = metadata
            .ref_state
            .default_ref
            .clone()
            .expect("a Git import publishes a default ref");
        let target = metadata
            .ref_state
            .refs
            .iter()
            .find(|entry| entry.name == default_ref)
            .map(|entry| entry.target.clone())
            .expect("the default ref resolves on the publisher");
        let generation = lease.roots().generation;
        let bodies = required_bodies(&metadata, &changes).len();
        (metadata, changes, default_ref, target, generation, bodies)
    };
    let ordered_changes = topological(&source_changes);

    // A probe whose subject is absent proves nothing, so refuse to grade
    // before the publisher is what this test is about.
    let git_authority = metadata
        .git_external_authority
        .clone()
        .expect("a Git-admitted store carries imported-Git authority; without one this probe has no subject");
    assert!(
        !ordered_changes.is_empty(),
        "the publisher admitted no changes; the probe would measure an empty transfer"
    );
    assert!(
        ordered_changes
            .iter()
            .any(|change| !change.tree_deltas.is_empty()),
        "the publisher's changes carry no tree deltas; this probe exists to test the PAYLOAD and there is none"
    );

    assert_eq!(
        ordered_changes.len(),
        commits,
        "the publisher must admit one change per commit, or this arm is not testing the history it thinks it is"
    );
    eprintln!(
        "PROBE publisher: commits={commits} repository={repository_id} generation={source_generation} \
         changes={} external_objects={} git_closure_objects={} aliases={} distinct_bodies={source_body_count}",
        ordered_changes.len(),
        metadata.external_objects.len(),
        git_authority.closure.objects.len(),
        metadata.aliases.len(),
    );

    // --- the destination: an empty replica under the same identity, which is
    // what an untouched hosted store is. `open` mints genesis authority.
    let destination_root = tempfile::tempdir().unwrap();
    let destination = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(destination_root.path().to_path_buf())),
    )
    .expect("an empty store mints genesis authority on open");

    let (destination_roots, destination_generation) = {
        let lease = destination.read_authority();
        let metadata = lease.metadata();
        // The five-field empty signature the real bootstrap will compare-and-swap
        // against. Asserting it here is what makes this an EMPTY-replica probe
        // rather than an any-replica one.
        assert!(
            metadata.git_external_authority.is_none(),
            "an empty replica must carry no imported-Git authority"
        );
        assert!(
            metadata.ref_state.refs.is_empty(),
            "an empty replica must publish no refs"
        );
        assert!(
            metadata.ref_state.default_ref.is_none(),
            "an empty replica must have adopted no default ref"
        );
        assert!(
            lease.snapshot().changes.is_empty(),
            "an empty replica must hold no changes"
        );
        assert_eq!(
            lease.roots().generation,
            0,
            "an empty replica must be at generation zero"
        );
        (lease.roots().clone(), lease.roots().generation)
    };

    // --- phase one: stage the bodies. Content addressed, grants no authority,
    // and it is the half kin-db's own API doc says to run before crossing the
    // authority boundary.
    let bodies = required_bodies(&metadata, &ordered_changes);
    let mut staged = 0usize;
    let mut staged_bytes = 0u64;
    for hash in &bodies {
        let payload = source
            .load_source_blob(*hash)
            .expect("reading a body the publisher's own authority names")
            .unwrap_or_else(|| panic!("publisher is missing body {hash} its authority names"));
        staged_bytes += payload.len() as u64;
        destination
            .save_source_blob(*hash, &payload)
            .expect("staging an immutable body into an empty replica");
        staged += 1;
    }
    eprintln!("PROBE staged: bodies={staged} bytes={staged_bytes}");

    // --- phase two: one transaction carrying authority AND the history it
    // describes, which bound 4 requires to be atomic. The workspace half is
    // deliberately absent: it is the publisher's local business and a hosted
    // replica runs with no workspace.
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: repository_id.clone(),
        expected_generation: destination_generation,
        expected_roots: destination_roots,
        actor: AuthorId::new("fir2729-bootstrap-probe"),
        reason: "probe: bootstrap an empty replica from a Git-admitted publisher".to_string(),
        external_objects: metadata.external_objects.clone(),
        git_authority_delta: Some(GitExternalAuthorityDelta::initialize(git_authority)),
        changes: ordered_changes.clone(),
        aliases: metadata.aliases.clone(),
        ref_mutations: vec![RefMutation {
            name: default_ref.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(source_target),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(default_ref.clone()),
        }),
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };

    // Model validation first, because a refusal here and a refusal from storage
    // are different news and reporting them as one would hide which.
    match transaction.validate() {
        Ok(()) => eprintln!("PROBE model validate: OK"),
        Err(error) => panic!("PROBE STOPPED AT MODEL VALIDATION: {error}"),
    }

    let receipt = match destination.commit_repository_transaction(transaction) {
        Ok(receipt) => receipt,
        Err(error) => panic!("PROBE STOPPED AT STORAGE ADMISSION: {error}"),
    };
    eprintln!(
        "PROBE committed: outcome={:?} generation={}",
        receipt.outcome, receipt.generation
    );

    // --- the payload assertion. Reading the head back is what the existing
    // hosted test already proves; this reads the BYTES back, which is the
    // thing no test in the tree does today.
    let lease = destination.read_authority();
    let metadata_after = lease.metadata();
    assert!(
        metadata_after.git_external_authority.is_some(),
        "the destination must hold imported-Git authority after the bootstrap"
    );
    assert_eq!(
        metadata_after.ref_state.default_ref.as_ref(),
        Some(&default_ref),
        "the destination must have adopted the publisher's default ref"
    );
    assert_eq!(
        lease.snapshot().changes.len(),
        ordered_changes.len(),
        "the destination must hold every change the bootstrap carried"
    );

    let probe_hash = ordered_changes
        .iter()
        .flat_map(|change| change.tree_deltas.iter())
        .filter_map(|delta| delta.new_state())
        .find(|state| state.path.as_bytes() == PROBE_PATH.as_bytes())
        .and_then(|state| state.entry.blob_identity())
        .expect("the publisher's history introduces the probe path");
    let served = destination
        .load_source_blob(probe_hash)
        .expect("reading the probe body back from the destination")
        .expect("the destination must serve the body its own authority names");
    assert_eq!(
        served.as_slice(),
        PROBE_BYTES,
        "the destination served different bytes than the publisher committed"
    );

    // The control that makes the assertion above able to fail: a body the
    // fixture never wrote must not resolve.
    let absent = Hash256::from_bytes([0x5a; 32]);
    assert!(
        destination.load_source_blob(absent).unwrap().is_none(),
        "a body nothing ever staged resolved, so the read-back proves nothing"
    );

    eprintln!("PROBE RESULT: bootstrap transaction ADMITTED and payload served back");
}
