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
