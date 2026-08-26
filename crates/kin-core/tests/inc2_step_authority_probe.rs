// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Day-one instrument for FIR-2729 increment 2, the segmented bootstrap.
//!
//! Increment 2 turns a bootstrap into a sequence in which step N installs an
//! authority whose refs sit at commit N and whose closure is exactly what
//! those refs reach. Every estimate for it rests on one thing nothing in the
//! tree does today: **deriving a partial authority.**
//!
//! So this asks that question and nothing else. Can a step authority be built
//! for a mid-history commit, from the source authority's own closure manifest
//! rather than by reopening Git, and does `from_raw_parts` validate it?
//!
//! A pass says the planner can be built on a manifest walk. A failure says
//! each step needs a Git re-read, which changes increment 2's shape rather
//! than its size, and is worth knowing in a day rather than a fortnight.

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


/// Load bodies out of the publisher's own CAS, which is where a sender
/// deriving a step authority would read them.
struct ManagerBodyLoader<'a>(&'a kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>);

impl kin_model::GitObjectBodyLoader for ManagerBodyLoader<'_> {
    type Error = String;

    fn load_body(&mut self, body_hash: &Hash256) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load_source_blob(*body_hash).map_err(|e| e.to_string())
    }
}

/// Every object reachable from `root`, walked over the closure manifest the
/// source authority already carries.
///
/// This is the whole question the probe exists for. If the manifest's own
/// `dependencies` are enough to compute a step's object set, a sender never
/// reopens Git to plan a chunk.
fn reachable_from(
    authority: &kin_model::GitExternalAuthority,
    root: kin_model::ExternalObjectId,
) -> Vec<kin_model::ExternalObjectRecord> {
    let by_id: std::collections::HashMap<_, _> = authority
        .closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect();
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    let mut out = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(entry) = by_id.get(&id) else { continue };
        out.push(entry.record.clone());
        for dependency in &entry.dependencies {
            stack.push(dependency.target);
        }
    }
    out
}

#[test]
fn a_step_authority_for_a_mid_history_commit_validates_from_the_manifest_alone() {
    const COMMITS: usize = 12;
    const STEP_AT: usize = 6;

    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let working = build_publisher(source_root.path(), COMMITS);
    let init = kin_core::init_from_git_adopting(&working, &repository_id).unwrap();
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .unwrap()
        .open_manager()
        .unwrap();

    let (full, aliases, changes, default_ref) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        (
            metadata.git_external_authority.clone().expect("Git-admitted"),
            metadata.aliases.clone(),
            lease.snapshot().changes.values().cloned().collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    let ordered = topological(&changes);
    assert_eq!(ordered.len(), COMMITS, "the publisher must admit one change per commit");

    // The commit this step would publish, found through the alias rather than
    // by guessing: the STEP_AT-th change in parent-before-child order.
    let step_change = ordered[STEP_AT - 1].id;
    let step_oid = aliases
        .iter()
        .find(|alias| alias.change_id == step_change)
        .map(|alias| alias.oid)
        .expect("every Git-origin change has an alias");
    let step_object =
        kin_model::ExternalObjectId::new(kin_model::ExternalObjectKind::Commit, step_oid);

    let subset = reachable_from(&full, step_object);
    eprintln!(
        "INC2 PROBE: full closure {} objects, step {} of {} reaches {} objects",
        full.closure.objects.len(),
        STEP_AT,
        COMMITS,
        subset.len()
    );
    assert!(
        subset.len() < full.closure.objects.len(),
        "a mid-history step must reach FEWER objects than the whole history, or the walk \
         is not doing anything and this probe measures nothing"
    );
    assert!(
        subset.len() > 1,
        "a step must reach more than its own commit object, or the dependency walk is broken"
    );

    let mut loader = ManagerBodyLoader(&source);
    let step = kin_model::GitExternalAuthority::from_raw_parts(
        repository_id.clone(),
        full.object_format,
        vec![kin_model::GitRawRef {
            name: default_ref.clone(),
            target: kin_model::GitRawTarget::Direct {
                object: step_object,
            },
        }],
        kin_model::GitRawTarget::Symbolic {
            target: default_ref.clone(),
        },
        subset.clone(),
        &mut loader,
    );

    match step {
        Ok(step) => {
            eprintln!(
                "INC2 PROBE RESULT: step authority VALIDATES from the manifest walk alone. \
                 closure {} objects, {} commit projections, {} raw refs",
                step.closure.objects.len(),
                step.commit_projections.len(),
                step.raw_refs.len()
            );
            assert_eq!(
                step.closure.objects.len(),
                subset.len(),
                "the derived closure must be exactly the subset handed in, not a re-expansion"
            );
            assert_eq!(
                step.commit_projections.len(),
                STEP_AT,
                "a step at commit {STEP_AT} must project exactly that many commits, or the \
                 chunk planner cannot reason about what a step admits"
            );
            // The property the whole design rests on: this is a real authority,
            // not a truncation, so it hashes and can be compare-and-swapped.
            assert_ne!(
                step.closure.objects.len(),
                full.closure.objects.len(),
                "the step must differ from the full authority or nothing was segmented"
            );
        }
        Err(error) => {
            panic!(
                "INC2 PROBE RESULT: step authority does NOT validate from the manifest alone. \
                 This changes increment 2's shape: each step needs a Git re-read. Detail: {error}"
            );
        }
    }
}
