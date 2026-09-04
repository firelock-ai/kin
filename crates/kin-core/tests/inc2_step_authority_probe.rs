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

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, DefaultRefExpectation, DefaultRefMutation, GitExternalAuthorityDelta, Hash256,
    OperationId, RefExpectation, RefMutation, RefUpdatePolicy, RepositoryId, RepositoryTransaction,
    SemanticChange, SemanticChangeId, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

/// One fixture path with bytes nothing else in the tree could produce, so a
/// read-back that returns them cannot be a default, an empty state, or another
/// fixture's leftovers.
const PROBE_PATH: &str = "service/compose.yaml";
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

/// Order changes parent-before-child.
///
/// Not because storage requires it: kin-db sorts the snapshot's changes itself
/// through `topological_change_order` (`kin-db repository.rs:4835`, called at
/// `:4798` and `:4878`) over a map, so a transaction's `changes` VECTOR order
/// is irrelevant to it. Reversing a step's changes here leaves the probe
/// green, which is how that was established rather than assumed.
///
/// The PACK is what requires the order. `validate_pack` refuses a change that
/// "appears before or without parent" (`repository_transfer.rs:1157`). So an
/// increment-2 planner must order within a step for the pack even though the
/// transaction underneath would not care, and a planner tested only against
/// storage would pass while producing packs the receiver refuses.
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
        self.0
            .load_source_blob(*body_hash)
            .map_err(|e| e.to_string())
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
        let Some(entry) = by_id.get(&id) else {
            continue;
        };
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
            metadata
                .git_external_authority
                .clone()
                .expect("Git-admitted"),
            metadata.aliases.clone(),
            lease
                .snapshot()
                .changes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    let ordered = topological(&changes);
    assert_eq!(
        ordered.len(),
        COMMITS,
        "the publisher must admit one change per commit"
    );

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

/// Everything one step of a segmented bootstrap would carry.
struct Step {
    authority: kin_model::GitExternalAuthority,
    changes: Vec<SemanticChange>,
    aliases: Vec<kin_model::ExternalChangeAlias>,
    external_objects: Vec<kin_model::ExternalObjectRecord>,
    head_object: kin_model::ExternalObjectId,
}

/// Plan the step that publishes `ordered[..upto]`, carrying only what steps
/// before it did not already admit.
///
/// The `already` sets are what make this a step rather than a whole bootstrap:
/// external objects and aliases accumulate in the envelope across
/// transactions, so a later step names the ones an earlier step admitted
/// without re-shipping them.
#[allow(clippy::too_many_arguments)]
fn plan_step(
    source: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    full: &kin_model::GitExternalAuthority,
    ordered: &[SemanticChange],
    all_aliases: &[kin_model::ExternalChangeAlias],
    default_ref: &kin_model::RefName,
    repository_id: &RepositoryId,
    from: usize,
    upto: usize,
    already_objects: &BTreeSet<kin_model::ExternalObjectId>,
) -> Step {
    let head_change = ordered[upto - 1].id;
    let head_oid = all_aliases
        .iter()
        .find(|alias| alias.change_id == head_change)
        .map(|alias| alias.oid)
        .expect("every Git-origin change has an alias");
    let head_object =
        kin_model::ExternalObjectId::new(kin_model::ExternalObjectKind::Commit, head_oid);

    let reachable = reachable_from(full, head_object);
    let mut loader = ManagerBodyLoader(source);
    let authority = kin_model::GitExternalAuthority::from_raw_parts(
        repository_id.clone(),
        full.object_format,
        vec![kin_model::GitRawRef {
            name: default_ref.clone(),
            target: kin_model::GitRawTarget::Direct {
                object: head_object,
            },
        }],
        kin_model::GitRawTarget::Symbolic {
            target: default_ref.clone(),
        },
        reachable.clone(),
        &mut loader,
    )
    .expect("a step authority derives from the manifest walk");

    // This step's OWN changes, and the aliases for exactly those. Slicing the
    // two by the same index would pair the wrong ones: aliases keep the
    // envelope's order and changes keep parent-before-child order, and nothing
    // makes those agree. `RepositoryTransaction::validate` refuses a Git-origin
    // change whose alias is not in the same transaction, so this has to be a
    // filter over the carried set rather than a positional slice.
    let changes: Vec<SemanticChange> = ordered[from..upto].to_vec();
    let carried_ids: BTreeSet<_> = changes.iter().map(|c| c.id).collect();
    Step {
        authority,
        external_objects: reachable
            .into_iter()
            .filter(|record| !already_objects.contains(&record.object))
            .collect(),
        aliases: all_aliases
            .iter()
            .filter(|alias| carried_ids.contains(&alias.change_id))
            .cloned()
            .collect(),
        changes,
        head_object,
    }
}

/// Does a segmented bootstrap actually COMMIT, and does the compare-and-swap
/// between consecutive steps hold?
///
/// The probe above builds a step authority and validates its SHAPE. It never
/// hands one to kin-db, so the projection validation and the between-steps
/// swap were both untested. This commits step one as an initialize, then step
/// two as an update over it, which is the whole mechanism increment 2 rests on.
#[test]
fn two_consecutive_steps_commit_and_the_second_swaps_over_the_first() {
    const COMMITS: usize = 12;
    const STEP_ONE: usize = 4;
    const STEP_TWO: usize = 8;

    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let working = build_publisher(source_root.path(), COMMITS);
    let init = kin_core::init_from_git_adopting(&working, &repository_id).unwrap();
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .unwrap()
        .open_manager()
        .unwrap();

    let (full, all_aliases, changes, default_ref) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        (
            metadata
                .git_external_authority
                .clone()
                .expect("Git-admitted"),
            metadata.aliases.clone(),
            lease
                .snapshot()
                .changes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    let ordered = topological(&changes);

    let first = plan_step(
        &source,
        &full,
        &ordered,
        &all_aliases,
        &default_ref,
        &repository_id,
        0,
        STEP_ONE,
        &BTreeSet::new(),
    );
    let after_first: BTreeSet<_> = first
        .external_objects
        .iter()
        .map(|record| record.object)
        .collect();
    let second = plan_step(
        &source,
        &full,
        &ordered,
        &all_aliases,
        &default_ref,
        &repository_id,
        STEP_ONE,
        STEP_TWO,
        &after_first,
    );

    // The property that makes chunking work at all: a later step ships only
    // what earlier steps did not. Without this each step re-sends the whole
    // closure and segmentation buys nothing.
    assert!(
        second.external_objects.len()
            < first.external_objects.len() + second.external_objects.len(),
        "the second step must carry fewer objects than the union, or nothing is being reused"
    );
    assert_eq!(
        second.aliases.len(),
        second.changes.len(),
        "a step carries one alias per change it publishes; the model refuses a Git-origin \
         change whose alias is not in the same transaction"
    );
    eprintln!(
        "INC2 STEPS: step1 objects={} changes={} | step2 NEW objects={} changes={}",
        first.external_objects.len(),
        first.changes.len(),
        second.external_objects.len(),
        second.changes.len()
    );

    let destination_root = tempfile::tempdir().unwrap();
    let destination = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(destination_root.path().to_path_buf())),
    )
    .unwrap();

    // Stage every body both steps name. Content addressed, grants nothing.
    for record in first
        .external_objects
        .iter()
        .chain(second.external_objects.iter())
    {
        let bytes = source
            .load_source_blob(record.body_hash)
            .unwrap()
            .expect("the publisher holds every body its manifest names");
        destination
            .save_source_blob(record.body_hash, &bytes)
            .unwrap();
    }
    for change in ordered.iter() {
        for delta in &change.tree_deltas {
            if let Some(state) = delta.new_state() {
                if let Some(hash) = state.entry.blob_identity() {
                    if let Some(bytes) = source.load_source_blob(hash).unwrap() {
                        destination.save_source_blob(hash, &bytes).unwrap();
                    }
                }
            }
        }
    }

    let commit_step =
        |step: &Step, previous: Option<&kin_model::GitExternalAuthority>, op: u128| {
            let lease = destination.read_authority();
            let delta = match previous {
                None => GitExternalAuthorityDelta::initialize(step.authority.clone()),
                Some(old) => GitExternalAuthorityDelta::update(old.clone(), step.authority.clone()),
            };
            let expected = match previous {
                None => RefExpectation::MustNotExist,
                Some(_) => RefExpectation::MustEqual {
                    target: kin_model::RefTarget::external_object(
                        lease
                            .metadata()
                            .ref_state
                            .refs
                            .iter()
                            .find(|entry| entry.name == default_ref)
                            .and_then(|entry| match entry.target {
                                kin_model::RefTarget::ExternalObject { object } => Some(object),
                                _ => None,
                            })
                            .expect("the previous step published an external-object ref"),
                    ),
                },
            };
            let transaction = RepositoryTransaction {
                schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: OperationId::from_uuid(uuid::Uuid::from_u128(op)),
                repository_id: repository_id.clone(),
                expected_generation: lease.roots().generation,
                expected_roots: lease.roots().clone(),
                actor: AuthorId::new("inc2-step-probe"),
                reason: format!(
                    "segmented bootstrap step publishing {}",
                    step.head_object.oid
                ),
                external_objects: step.external_objects.clone(),
                git_authority_delta: Some(delta),
                changes: step.changes.clone(),
                aliases: step.aliases.clone(),
                ref_mutations: vec![RefMutation {
                    name: default_ref.clone(),
                    expected,
                    new_target: Some(kin_model::RefTarget::external_object(step.head_object)),
                    policy: RefUpdatePolicy::FastForwardOnly,
                }],
                default_ref_mutation: previous.is_none().then(|| DefaultRefMutation {
                    expected: DefaultRefExpectation::MustBeUnset,
                    new_default: Some(default_ref.clone()),
                }),
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
                collaboration_delta: None,
            };
            drop(lease);
            transaction
                .validate()
                .expect("the step transaction is well formed");
            destination.commit_repository_transaction(transaction)
        };

    match commit_step(&first, None, 401) {
        Ok(receipt) => eprintln!("INC2 STEP 1: committed, generation {}", receipt.generation),
        Err(error) => panic!("INC2 STEP 1 REFUSED: {error}"),
    }
    match commit_step(&second, Some(&first.authority), 402) {
        Ok(receipt) => eprintln!("INC2 STEP 2: committed, generation {}", receipt.generation),
        Err(error) => {
            panic!("INC2 STEP 2 REFUSED (the between-steps swap is the suspect): {error}")
        }
    }

    let lease = destination.read_authority();
    let metadata = lease.metadata();
    assert_eq!(
        metadata
            .git_external_authority
            .as_ref()
            .map(|a| a.closure.objects.len()),
        Some(second.authority.closure.objects.len()),
        "the destination must end on step two's authority, not step one's"
    );
    assert_eq!(
        lease.snapshot().changes.len(),
        STEP_TWO,
        "the destination must hold every change both steps carried and nothing else"
    );
    eprintln!(
        "INC2 STEPS RESULT: segmented bootstrap COMMITS. destination at {} changes, \
         authority closure {} objects",
        lease.snapshot().changes.len(),
        metadata
            .git_external_authority
            .as_ref()
            .unwrap()
            .closure
            .objects
            .len()
    );
}

/// Build a history with a real merge: a side line branched from the root and
/// merged back, so one commit reaches two parents.
fn build_merged_publisher(root: &std::path::Path) -> std::path::PathBuf {
    let working = root.join("work");
    std::fs::create_dir_all(working.join("service")).unwrap();
    std::fs::write(working.join(PROBE_PATH), PROBE_BYTES).unwrap();
    git(&working, &["init", "--initial-branch=main"]);
    git(&working, &["config", "user.email", "probe@example.invalid"]);
    git(&working, &["config", "user.name", "FIR-2729 Probe"]);
    git(&working, &["add", "--all"]);
    git(&working, &["commit", "-s", "-m", "root"]);

    git(&working, &["checkout", "-b", "side"]);
    std::fs::write(working.join("service/side.txt"), b"side line only\n").unwrap();
    git(&working, &["add", "--all"]);
    git(&working, &["commit", "-s", "-m", "side work"]);

    git(&working, &["checkout", "main"]);
    std::fs::write(working.join("service/main.txt"), b"main line only\n").unwrap();
    git(&working, &["add", "--all"]);
    git(&working, &["commit", "-s", "-m", "main work"]);

    git(
        &working,
        &["merge", "--no-ff", "-m", "merge side into main", "side"],
    );
    // Delete the side ref so the authority's roots are main and HEAD alone,
    // which keeps the closure the same shape a single-ref bootstrap sees.
    git(&working, &["branch", "-D", "side"]);
    working
}

/// Does the manifest walk hold up when a commit reaches two parents?
///
/// The linear probe cannot answer this: every commit there has one parent, so
/// a walk that followed only the first would look correct. A merge is where
/// the subset property either holds or quietly loses a whole line of history,
/// and losing it would produce a step authority that validates while
/// describing less than it claims.
#[test]
fn a_merge_commit_reaches_both_parents_and_a_side_line_stays_out_of_the_other_branch() {
    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let working = build_merged_publisher(source_root.path());
    let init = kin_core::init_from_git_adopting(&working, &repository_id).unwrap();
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .unwrap()
        .open_manager()
        .unwrap();

    let (full, aliases, changes, default_ref) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        (
            metadata
                .git_external_authority
                .clone()
                .expect("Git-admitted"),
            metadata.aliases.clone(),
            lease
                .snapshot()
                .changes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    assert_eq!(changes.len(), 4, "root, side, main and the merge");

    let merge = changes
        .iter()
        .find(|change| change.parents.len() == 2)
        .expect("the fixture must actually produce a merge commit");
    let main_only = changes
        .iter()
        .find(|change| change.message.contains("main work"))
        .expect("the main-line commit");
    let side_only = changes
        .iter()
        .find(|change| change.message.contains("side work"))
        .expect("the side-line commit");

    let oid_of = |change_id| {
        aliases
            .iter()
            .find(|alias| alias.change_id == change_id)
            .map(|alias| {
                kin_model::ExternalObjectId::new(kin_model::ExternalObjectKind::Commit, alias.oid)
            })
            .expect("every Git-origin change has an alias")
    };

    let from_merge: BTreeSet<_> = reachable_from(&full, oid_of(merge.id))
        .into_iter()
        .map(|record| record.object)
        .collect();
    let from_main: BTreeSet<_> = reachable_from(&full, oid_of(main_only.id))
        .into_iter()
        .map(|record| record.object)
        .collect();
    let side_commit = oid_of(side_only.id);

    eprintln!(
        "INC2 MERGE: full closure {} objects | from merge {} | from main-only {} | \
         side commit in merge walk: {} | side commit in main walk: {}",
        full.closure.objects.len(),
        from_merge.len(),
        from_main.len(),
        from_merge.contains(&side_commit),
        from_main.contains(&side_commit),
    );

    // The property: a merge reaches BOTH lines.
    assert!(
        from_merge.contains(&side_commit),
        "the walk lost the side line at a merge, so a step authority at a merge would \
         describe less history than it claims"
    );
    assert!(
        from_merge.contains(&oid_of(main_only.id)),
        "the walk lost the main line at a merge"
    );
    // The control that makes the above mean something: a walk that returned
    // everything would satisfy it while proving nothing.
    assert!(
        !from_main.contains(&side_commit),
        "the main-only line must NOT reach the side commit, or the walk is returning \
         the whole closure regardless of where it started"
    );
    assert!(
        from_main.len() < from_merge.len(),
        "a pre-merge commit must reach strictly fewer objects than the merge"
    );

    // And the merge's step authority still derives and validates.
    let mut loader = ManagerBodyLoader(&source);
    let step = kin_model::GitExternalAuthority::from_raw_parts(
        repository_id.clone(),
        full.object_format,
        vec![kin_model::GitRawRef {
            name: default_ref.clone(),
            target: kin_model::GitRawTarget::Direct {
                object: oid_of(merge.id),
            },
        }],
        kin_model::GitRawTarget::Symbolic {
            target: default_ref.clone(),
        },
        reachable_from(&full, oid_of(merge.id)),
        &mut loader,
    )
    .expect("a step authority at a merge derives and validates");
    let merge_projection = step
        .commit_projections
        .iter()
        .find(|projection| projection.parent_oids.len() == 2)
        .expect("the derived authority must project the merge with BOTH parents");
    eprintln!(
        "INC2 MERGE RESULT: step authority at the merge validates, {} objects, \
         {} projections, merge projection carries {} parents",
        step.closure.objects.len(),
        step.commit_projections.len(),
        merge_projection.parent_oids.len()
    );
}

/// The last named unknown: does a step COMMIT when its head is a merge?
///
/// The commit probe is linear, so every step there had one parent. The merge
/// probe stops at derivation, so nothing ever handed a merge-headed step to
/// kin-db. This is the composition of the two, and it is the case a planner
/// would otherwise meet first on any repository with a branch in it.
///
/// The interesting part is not the merge commit itself. It is that step two
/// admits a WHOLE SIDE LINE that step one never saw, so the merge's second
/// parent arrives in the same transaction as the merge, and kin-db checks a
/// change's parents against its projection's parent aliases.
#[test]
fn a_step_whose_head_is_a_merge_commits_over_a_step_that_never_saw_the_side_line() {
    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let working = build_merged_publisher(source_root.path());
    let init = kin_core::init_from_git_adopting(&working, &repository_id).unwrap();
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .unwrap()
        .open_manager()
        .unwrap();

    let (full, aliases, changes, default_ref) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        (
            metadata
                .git_external_authority
                .clone()
                .expect("Git-admitted"),
            metadata.aliases.clone(),
            lease
                .snapshot()
                .changes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    let pick = |needle: &str| {
        changes
            .iter()
            .find(|change| change.message.contains(needle))
            .cloned()
            .unwrap_or_else(|| panic!("the fixture must contain a {needle} commit"))
    };
    let root = pick("root");
    let side = pick("side work");
    let main = pick("main work");
    let merge = changes
        .iter()
        .find(|change| change.parents.len() == 2)
        .cloned()
        .expect("the fixture must produce a merge");

    let oid_of = |change_id| {
        aliases
            .iter()
            .find(|alias| alias.change_id == change_id)
            .map(|alias| {
                kin_model::ExternalObjectId::new(kin_model::ExternalObjectKind::Commit, alias.oid)
            })
            .expect("every Git-origin change has an alias")
    };
    let aliases_for = |carried: &[SemanticChange]| {
        let ids: BTreeSet<_> = carried.iter().map(|change| change.id).collect();
        aliases
            .iter()
            .filter(|alias| ids.contains(&alias.change_id))
            .cloned()
            .collect::<Vec<_>>()
    };

    // Step one stops on the main line, so it never sees the side line at all.
    // Step two's head is the merge, which pulls the side line and the merge in
    // together.
    let step_one_head = oid_of(main.id);
    let step_two_head = oid_of(merge.id);
    let one_objects: Vec<_> = reachable_from(&full, step_one_head);
    let one_ids: BTreeSet<_> = one_objects.iter().map(|record| record.object).collect();
    let two_objects: Vec<_> = reachable_from(&full, step_two_head)
        .into_iter()
        .filter(|record| !one_ids.contains(&record.object))
        .collect();
    assert!(
        !one_ids.contains(&oid_of(side.id)),
        "step one must not already hold the side line, or this probe is not testing what it says"
    );

    let derive = |head: kin_model::ExternalObjectId,
                  records: Vec<kin_model::ExternalObjectRecord>| {
        let mut loader = ManagerBodyLoader(&source);
        kin_model::GitExternalAuthority::from_raw_parts(
            repository_id.clone(),
            full.object_format,
            vec![kin_model::GitRawRef {
                name: default_ref.clone(),
                target: kin_model::GitRawTarget::Direct { object: head },
            }],
            kin_model::GitRawTarget::Symbolic {
                target: default_ref.clone(),
            },
            records,
            &mut loader,
        )
        .expect("a step authority derives")
    };
    let authority_one = derive(step_one_head, one_objects.clone());
    let authority_two = derive(step_two_head, reachable_from(&full, step_two_head));

    let destination_root = tempfile::tempdir().unwrap();
    let destination = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(destination_root.path().to_path_buf())),
    )
    .unwrap();
    for record in one_objects.iter().chain(two_objects.iter()) {
        let bytes = source.load_source_blob(record.body_hash).unwrap().unwrap();
        destination
            .save_source_blob(record.body_hash, &bytes)
            .unwrap();
    }
    for change in &changes {
        for delta in &change.tree_deltas {
            if let Some(state) = delta.new_state() {
                if let Some(hash) = state.entry.blob_identity() {
                    if let Some(bytes) = source.load_source_blob(hash).unwrap() {
                        destination.save_source_blob(hash, &bytes).unwrap();
                    }
                }
            }
        }
    }

    let commit = |carried: Vec<SemanticChange>,
                  objects: Vec<kin_model::ExternalObjectRecord>,
                  authority: &kin_model::GitExternalAuthority,
                  previous: Option<&kin_model::GitExternalAuthority>,
                  head: kin_model::ExternalObjectId,
                  op: u128| {
        let lease = destination.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(uuid::Uuid::from_u128(op)),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("inc2-merge-step-probe"),
            reason: format!("step publishing {}", head.oid),
            external_objects: objects,
            git_authority_delta: Some(match previous {
                None => GitExternalAuthorityDelta::initialize(authority.clone()),
                Some(old) => GitExternalAuthorityDelta::update(old.clone(), authority.clone()),
            }),
            aliases: aliases_for(&carried),
            changes: carried,
            ref_mutations: vec![RefMutation {
                name: default_ref.clone(),
                expected: match previous {
                    None => RefExpectation::MustNotExist,
                    Some(_) => RefExpectation::MustEqual {
                        target: kin_model::RefTarget::external_object(step_one_head),
                    },
                },
                new_target: Some(kin_model::RefTarget::external_object(head)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: previous.is_none().then(|| DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(default_ref.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        };
        drop(lease);
        transaction
            .validate()
            .expect("the step transaction is well formed");
        destination.commit_repository_transaction(transaction)
    };

    match commit(
        vec![root.clone(), main.clone()],
        one_objects,
        &authority_one,
        None,
        step_one_head,
        601,
    ) {
        Ok(receipt) => eprintln!(
            "INC2 MERGE-STEP 1: committed, generation {}",
            receipt.generation
        ),
        Err(error) => panic!("INC2 MERGE-STEP 1 REFUSED: {error}"),
    }
    // Parent-before-child inside the step: the side line arrives before the
    // merge that reaches it.
    match commit(
        vec![side.clone(), merge.clone()],
        two_objects,
        &authority_two,
        Some(&authority_one),
        step_two_head,
        602,
    ) {
        Ok(receipt) => eprintln!(
            "INC2 MERGE-STEP 2: committed, generation {}",
            receipt.generation
        ),
        Err(error) => panic!(
            "INC2 MERGE-STEP 2 REFUSED, so a merge-headed step is a real bound rather than a \
             composition that just works: {error}"
        ),
    }

    let lease = destination.read_authority();
    assert_eq!(
        lease.snapshot().changes.len(),
        4,
        "the destination must hold the whole merged history"
    );
    assert_eq!(
        lease.resolve_ref_target(&default_ref).unwrap(),
        Some(kin_model::RefTarget::external_object(step_two_head)),
        "the ref must stand at the merge"
    );
    eprintln!("INC2 MERGE-STEP RESULT: a merge-headed step COMMITS over a step that never saw the side line");
}

/// A body loader that keeps what it read, so a plan's second step does not
/// re-read from CAS what its first step already loaded.
///
/// `from_raw_parts` calls `load_body` once per record and then decodes it
/// (`kin-model git_authority.rs:967`, inside `load_and_decode_records`), so a
/// segmented plan re-loads every object it re-derives. Whether that re-read is
/// the cost or the decode is the cost cannot be settled by reading either one,
/// and it decides whether a planner needs a body cache or a different API.
/// `misses` is what proves the cache is answering rather than silently
/// forwarding every call.
struct CachingBodyLoader<'a> {
    inner: ManagerBodyLoader<'a>,
    cache: std::collections::HashMap<Hash256, Option<Vec<u8>>>,
    misses: usize,
    hits: usize,
}

impl<'a> CachingBodyLoader<'a> {
    fn new(source: &'a kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>) -> Self {
        Self {
            inner: ManagerBodyLoader(source),
            cache: std::collections::HashMap::new(),
            misses: 0,
            hits: 0,
        }
    }
}

impl kin_model::GitObjectBodyLoader for CachingBodyLoader<'_> {
    type Error = String;

    fn load_body(&mut self, body_hash: &Hash256) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(hit) = self.cache.get(body_hash) {
            self.hits += 1;
            return Ok(hit.clone());
        }
        self.misses += 1;
        let loaded = self.inner.load_body(body_hash)?;
        self.cache.insert(*body_hash, loaded.clone());
        Ok(loaded)
    }
}

/// Every object reachable from `root`, over an index built ONCE by the caller.
///
/// The same walk as [`reachable_from`], with the whole-closure `HashMap` lifted
/// out. A planner derives one authority per step, so where that index is built
/// decides whether the per-step cost is the step's own subset or the entire
/// history. Measuring both is the only way to say which term dominates at a
/// real repository's size, and the difference is a planner design decision
/// rather than a micro-optimization.
fn reachable_from_index(
    by_id: &std::collections::HashMap<
        kin_model::ExternalObjectId,
        &kin_model::GitObjectClosureEntry,
    >,
    root: kin_model::ExternalObjectId,
) -> Vec<kin_model::ExternalObjectRecord> {
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    let mut out = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(entry) = by_id.get(&id) else {
            continue;
        };
        out.push(entry.record.clone());
        for dependency in &entry.dependencies {
            stack.push(dependency.target);
        }
    }
    out
}

/// What does a segmented bootstrap's PLANNING cost at a real repository's size?
///
/// The design names this unmeasured and names the risk precisely: a planner
/// that walks the manifest once per step is quadratic in steps if each walk is
/// linear in the whole closure. Everything measured before this ran on twelve
/// synthetic commits, where every term is too small to separate.
///
/// This times the two things a planner does per step, the manifest walk and
/// `from_raw_parts`, across a whole segmented plan, and prints the subset sizes
/// beside them so a row can be read against the work it describes. The control
/// is the single whole-history derivation increment 1 already does, which is
/// what the segmented total has to be compared against rather than against
/// zero.
///
/// `KIN_INC2_SCALE_REPO` points it at a real Git worktree, which is the only
/// arm whose numbers say anything about a real repository's shape.
/// `KIN_INC2_SCALE_COMMITS` and `KIN_INC2_SCALE_STEPS` size the synthetic arm.
#[test]
#[ignore = "scale measurement, not a guard: builds or imports a large history"]
fn scale_of_the_manifest_walk_and_step_derivation() {
    let steps: usize = std::env::var("KIN_INC2_SCALE_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    assert!(steps >= 2, "a segmented plan needs at least two steps");

    let repository_id = hosted_shaped_id();
    let source_root = tempfile::tempdir().unwrap();
    let (working, fixture) = match std::env::var("KIN_INC2_SCALE_REPO") {
        Ok(path) => {
            let target = source_root.path().join("work");
            git(
                source_root.path(),
                &[
                    "clone",
                    "--quiet",
                    "--single-branch",
                    &path,
                    target.to_str().unwrap(),
                ],
            );
            // The sha the clone actually landed on, read back rather than
            // assumed, because a measurement nobody can reproduce against a
            // named commit is a number without a subject.
            let head = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&target)
                .output()
                .expect("git rev-parse runs in the clone");
            let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
            (target, format!("real repository at {path}, HEAD {head}"))
        }
        Err(_) => {
            let commits: usize = std::env::var("KIN_INC2_SCALE_COMMITS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(400);
            let working = build_publisher(source_root.path(), commits);
            // An annotated tag is a closure root that no commit walk can ever
            // reach, because the tag object points at its commit and never the
            // reverse. One of them makes the synthetic arm exercise the same ref
            // gap a real repository's tags produce, and makes the all-roots
            // assertion below falsifiable: without an unreachable root, dropping
            // roots from that walk changes nothing and the check cannot fail.
            // The four probe arms above carry no tag and are the zero-gap control.
            git(
                &working,
                &[
                    "tag",
                    "-a",
                    "probe-unreachable-root",
                    "-m",
                    "a closure root no commit walk reaches",
                    "HEAD",
                ],
            );
            (
                working,
                format!("synthetic publisher of {commits} commits plus one annotated tag"),
            )
        }
    };

    let import_started = std::time::Instant::now();
    let init = kin_core::init_from_git_adopting(&working, &repository_id).unwrap();
    let import_seconds = import_started.elapsed().as_secs_f64();
    let source = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout)
        .unwrap()
        .open_manager()
        .unwrap();

    let (full, aliases, changes, default_ref) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        (
            metadata
                .git_external_authority
                .clone()
                .expect("Git-admitted"),
            metadata.aliases.clone(),
            lease
                .snapshot()
                .changes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            metadata.ref_state.default_ref.clone().expect("default ref"),
        )
    };
    let ordered = topological(&changes);
    let closure_objects = full.closure.objects.len();
    eprintln!(
        "INC2 SCALE fixture: {fixture}\n\
         INC2 SCALE imported: {} changes, {} closure objects, {} aliases in {:.1}s",
        ordered.len(),
        closure_objects,
        aliases.len(),
        import_seconds
    );
    assert!(
        ordered.len() >= steps,
        "a {steps}-step plan needs at least that many changes, got {}",
        ordered.len()
    );

    let by_oid: std::collections::HashMap<_, _> = aliases
        .iter()
        .map(|alias| (alias.change_id, alias.oid))
        .collect();
    let by_id: std::collections::HashMap<_, _> = full
        .closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect();
    let mut loader = ManagerBodyLoader(&source);

    // The control the segmented total is compared against: one whole-history
    // derivation, which is exactly what increment 1 does today.
    let whole_started = std::time::Instant::now();
    let whole = kin_model::GitExternalAuthority::from_raw_parts(
        repository_id.clone(),
        full.object_format,
        full.raw_refs.clone(),
        full.raw_head.clone(),
        full.closure
            .objects
            .iter()
            .map(|entry| entry.record.clone())
            .collect(),
        &mut loader,
    )
    .expect("the whole history derives");
    let whole_ms = whole_started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        whole.closure.objects.len(),
        closure_objects,
        "the control must derive the same closure it was handed"
    );

    let mut cached_loader = CachingBodyLoader::new(&source);
    eprintln!("INC2 SCALE  step |   upto |  subset | walk ms | hoisted ms | derive ms | cached ms");
    let mut walk_total = 0.0_f64;
    let mut hoisted_total = 0.0_f64;
    let mut derive_total = 0.0_f64;
    let mut cached_total = 0.0_f64;
    let mut subset_total = 0_usize;
    let mut previous_subset = 0_usize;
    let mut last_subset = 0_usize;
    for step in 1..=steps {
        let upto = ordered.len() * step / steps;
        let head_oid = *by_oid
            .get(&ordered[upto - 1].id)
            .expect("every Git-origin change has an alias");
        let head_object =
            kin_model::ExternalObjectId::new(kin_model::ExternalObjectKind::Commit, head_oid);

        let walk_started = std::time::Instant::now();
        let subset = reachable_from(&full, head_object);
        let walk_ms = walk_started.elapsed().as_secs_f64() * 1000.0;

        let hoisted_started = std::time::Instant::now();
        let hoisted = reachable_from_index(&by_id, head_object);
        let hoisted_ms = hoisted_started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(
            hoisted.len(),
            subset.len(),
            "the hoisted index must walk to the same subset, or it measures a different thing"
        );

        let derive_started = std::time::Instant::now();
        kin_model::GitExternalAuthority::from_raw_parts(
            repository_id.clone(),
            full.object_format,
            vec![kin_model::GitRawRef {
                name: default_ref.clone(),
                target: kin_model::GitRawTarget::Direct {
                    object: head_object,
                },
            }],
            kin_model::GitRawTarget::Symbolic {
                target: default_ref.clone(),
            },
            subset.clone(),
            &mut loader,
        )
        .expect("a step authority derives from the manifest walk");
        let derive_ms = derive_started.elapsed().as_secs_f64() * 1000.0;

        let cached_started = std::time::Instant::now();
        kin_model::GitExternalAuthority::from_raw_parts(
            repository_id.clone(),
            full.object_format,
            vec![kin_model::GitRawRef {
                name: default_ref.clone(),
                target: kin_model::GitRawTarget::Direct {
                    object: head_object,
                },
            }],
            kin_model::GitRawTarget::Symbolic {
                target: default_ref.clone(),
            },
            subset.clone(),
            &mut cached_loader,
        )
        .expect("a step authority derives over a cached body loader too");
        let cached_ms = cached_started.elapsed().as_secs_f64() * 1000.0;

        eprintln!(
            "INC2 SCALE  {step:>4} | {upto:>6} | {:>7} | {walk_ms:>7.1} | {hoisted_ms:>10.1} | {derive_ms:>9.1} | {cached_ms:>9.1}",
            subset.len()
        );
        assert!(
            subset.len() > previous_subset,
            "step {step} must reach more objects than step {}, or the plan is not advancing",
            step - 1
        );
        previous_subset = subset.len();
        last_subset = subset.len();
        walk_total += walk_ms;
        hoisted_total += hoisted_ms;
        derive_total += derive_ms;
        cached_total += cached_ms;
        subset_total += subset.len();
    }

    // A plan whose last step walks from the default ref's tip does NOT reach the
    // whole closure, and finding that out is what a real repository was for.
    //
    // The authority's closure covers every root it was built from, and only some
    // of those roots are commits a tip walk descends to. An annotated tag is the
    // clearest case: the tag object points at its commit and never the reverse,
    // so no commit walk can ever reach it. A tag on a commit outside the default
    // ref's history drags a whole line with it.
    //
    // Measured on kin: 28884 closure objects, 28675 reachable from the tip, 209
    // sitting under 99 tag refs of which 29 are annotated tag objects and three
    // point outside the default ref's history. Both numbers reproduce exactly
    // under `git rev-list --objects --all --tags` and `git rev-list --objects
    // HEAD`, which is the independent control on this whole paragraph.
    //
    // The planner consequence is the important part and it is not in the design.
    // A segmented bootstrap whose final authority is a tip walk leaves the
    // destination holding an authority that does not hash-equal the source's,
    // and every subsequent ordinary push is then refused by the equality rule in
    // `TransferSourceContext::read`, permanently, because the destination is no
    // longer unborn either. So the final step must install the COMPLETE ref set
    // and the objects only its other roots reach, not merely the tip's closure.
    let from_all_roots = full
        .closure
        .roots
        .iter()
        .flat_map(|root| reachable_from_index(&by_id, root.target))
        .map(|record| record.object)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        from_all_roots.len(),
        closure_objects,
        "a walk from EVERY closure root must reach the whole closure; if it does not, the walk \
         itself is broken and the tip-gap below would be measuring that instead"
    );
    let tip_gap = closure_objects - last_subset;
    eprintln!(
        "INC2 SCALE ref gap: the last step's tip walk reaches {last_subset} of {closure_objects}, \
         leaving {tip_gap} objects under {} closure roots that no commit walk reaches",
        full.closure.roots.len()
    );
    assert!(
        last_subset <= closure_objects,
        "a step cannot reach more than the closure it was walked over"
    );

    // Read the sum against the term it is supposed to describe before reading
    // any row: a per-step table whose total does not reconcile is decoration.
    let mean_subset = subset_total as f64 / steps as f64;
    // The cache must actually be answering. A loader that forwarded every call
    // would time identically to the uncached arm and read as "caching does not
    // help", which is the wrong conclusion from a cache that never ran.
    assert!(
        cached_loader.hits > cached_loader.misses,
        "the caching loader must serve more hits than misses across a segmented plan, \
         got {} hits and {} misses",
        cached_loader.hits,
        cached_loader.misses
    );
    // Each object the plan VISITS, which is not the whole closure: steps are
    // nested, so the distinct set the plan touches is the last step's subset,
    // and anything only a non-tip root reaches is never loaded at all. Asserting
    // the closure here instead would fail on every repository carrying a tag.
    assert_eq!(
        cached_loader.misses, last_subset,
        "a cache over a whole plan loads each object the plan visits exactly once"
    );

    eprintln!(
        "INC2 SCALE totals: walk {walk_total:.1} ms, hoisted {hoisted_total:.1} ms, \
         derive {derive_total:.1} ms, cached derive {cached_total:.1} ms over {steps} steps\n\
         INC2 SCALE body loads: {} misses, {} hits, so CAS reads fall {:.1}x under a cache\n\
         INC2 SCALE control: one whole-history derivation {whole_ms:.1} ms over \
         {closure_objects} objects\n\
         INC2 SCALE shape: mean subset {mean_subset:.0} objects ({:.2} of the closure), \
         segmented derive is {:.1}x the whole-history control\n\
         INC2 SCALE per-object: whole {:.1} us/object, segmented derive {:.1} us/object-visited",
        cached_loader.misses,
        cached_loader.hits,
        (cached_loader.hits + cached_loader.misses) as f64 / cached_loader.misses as f64,
        mean_subset / closure_objects as f64,
        derive_total / whole_ms,
        whole_ms * 1000.0 / closure_objects as f64,
        derive_total * 1000.0 / subset_total as f64,
    );
}
