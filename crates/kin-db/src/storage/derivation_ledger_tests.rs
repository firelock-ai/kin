// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Owed derivation ledger. A record rides the compare-and-swap of the tree it
// describes, a transaction that moves a workspace off an owed body overtakes
// its record, a re-derivation pays one workspace against its exact
// predecessor, and a non-empty ledger moves the snapshot and frame versions
// while an empty one moves nothing.

use crate::storage::derivation_ledger::{
    OwedDerivationCause, OwedDerivationLedger, OwedDerivationUpdate, RederivationPayment,
};

fn owed_path(path: &str) -> RepoPath {
    RepoPath::from_utf8(path).unwrap()
}

/// A standalone publication of `body` at `path` in the first workspace: its
/// exact tree moves and nothing else does, the shape a daemon's tree admission
/// publishes before any parse of the new bytes.
fn publish_body_transaction<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
    workspace: WorkspaceId,
    path: &str,
    body: &[u8],
) -> RepositoryTransaction {
    let body_hash = digest(body);
    manager.save_source_blob(body_hash, body).unwrap();
    let current = manager
        .read_authority()
        .metadata()
        .workspaces
        .iter()
        .find(|candidate| candidate.workspace_id == workspace)
        .expect("the fixture holds the workspace")
        .clone();
    let path = owed_path(path);
    let artifact = current
        .tree
        .artifact_at_path(&path)
        .expect("the fixture tree holds the path")
        .clone();
    let tree_deltas = vec![TreeDelta::Updated {
        artifact_id: artifact.artifact_id,
        old: LocatedEntry::new(path.clone(), artifact.entry),
        new: LocatedEntry::new(path, TreeEntry::blob(body_hash, false)),
    }];
    let tree = current.tree.apply(&tree_deltas).unwrap();
    let mutation = WorkspaceMutation {
        workspace_id: current.workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: current.generation,
            head: current.head.clone(),
            base_target: current.base_target.clone(),
            base_tree_hash: current.base_tree_hash,
            tree_hash: current.tree_hash,
            semantic_overlay_hash: current.semantic_overlay_hash,
            admission_policy: current.admission_policy,
        },
        new_generation: current.generation + 1,
        new_head: current.head.clone(),
        new_base_target: current.base_target.clone(),
        new_base_tree_hash: current.base_tree_hash,
        tree_deltas,
        new_tree_hash: compute_resolved_tree_hash(&tree).unwrap(),
        semantic_delta: WorkspaceSemanticDelta::default(),
        new_shared_admission_policy: current.shared_admission_policy.clone(),
        new_admission_policy: current.admission_policy,
    };
    let mut transaction = transaction_shell(manager, operation);
    transaction.workspace_mutation = Some(mutation);
    transaction
}

/// A second workspace, detached at the first workspace's base and holding the
/// same exact tree.
fn second_workspace_transaction<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
    workspace: u128,
) -> RepositoryTransaction {
    let first = manager.read_authority().metadata().workspaces[0].clone();
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(workspace));
    let overlay =
        FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
    let policy = EffectiveAdmissionPolicyStamp {
        shared: first.shared_admission_policy.stamp(),
        local: overlay.stamp(),
    };
    let base = first
        .base_target
        .clone()
        .expect("the fixture workspace has a base");
    let tree_deltas = first
        .tree
        .artifacts()
        .map(|artifact| TreeDelta::Added {
            artifact_id: artifact.artifact_id,
            new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
        })
        .collect();
    let mutation = WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: WorkspaceHead::Detached {
            target: base.clone(),
        },
        new_base_target: Some(base),
        new_base_tree_hash: first.base_tree_hash,
        tree_deltas,
        new_tree_hash: first.tree_hash,
        semantic_delta: WorkspaceSemanticDelta::default(),
        new_shared_admission_policy: first.shared_admission_policy.clone(),
        new_admission_policy: policy,
    };
    let mut transaction = transaction_shell(manager, operation);
    transaction.workspace_mutation = Some(mutation);
    transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
    transaction
}

fn owed_records<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
) -> Vec<(WorkspaceId, String, Hash256, u64, OwedDerivationCause)> {
    manager
        .read_authority()
        .metadata()
        .owed_derivations
        .records()
        .iter()
        .map(|record| {
            (
                record.workspace_id(),
                record.path().to_string(),
                record.body(),
                record.recorded_at(),
                record.cause(),
            )
        })
        .collect()
}

/// The top-level element count of one MessagePack array body.
fn message_pack_array_len(body: &[u8]) -> usize {
    match body[0] {
        b @ 0x90..=0x9f => (b & 0x0f) as usize,
        0xdc => u16::from_be_bytes([body[1], body[2]]) as usize,
        0xdd => u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize,
        other => panic!("not a MessagePack array: first byte {other:#x}"),
    }
}

fn header_version(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}

/// A record commits with the tree it describes. A publication whose
/// compare-and-swap is refused, because another writer moved authority first,
/// records nothing: the ledger keeps the earlier record and gains no record
/// for the refused body.
#[test]
fn owed_derivation_a_refused_publication_records_nothing() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed0_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    let recorded_at = manager.read_authority().roots().generation;
    let expected = vec![(
        workspace,
        "src/lib.rs".to_string(),
        digest(a),
        recorded_at,
        OwedDerivationCause::Publication,
    )];
    assert_eq!(owed_records(&manager), expected);

    // Another writer moves authority on before this manager publishes again.
    let other = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    other
        .commit_repository_transaction(binding_history_followup(&other, 0x0ed0_0002))
        .unwrap();
    let b = b"pub fn kin() -> u32 { 2 }\n";
    let stale = publish_body_transaction(&manager, 0x0ed0_0003, workspace, "src/lib.rs", b);
    manager
        .commit_repository_transaction_owing(
            stale,
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(b))],
                Vec::new(),
            ),
        )
        .expect_err("a publication planned before another writer moved authority must refuse");
    drop(manager);
    drop(other);

    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert_eq!(
        owed_records(&reopened),
        expected,
        "the refused publication must record nothing, and the earlier record must stand"
    );
}

/// Every transaction drops a record whose exact body its successor tree no
/// longer names, and keeps one whose body it still names. The store reopens
/// valid either way.
#[test]
fn owed_derivation_a_transaction_that_moves_the_body_overtakes_its_record() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed1_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    // A transaction that leaves the owed body alone leaves the record.
    manager
        .commit_repository_transaction(binding_history_followup(&manager, 0x0ed1_0002))
        .unwrap();
    manager
        .commit_repository_transaction(publish_body_transaction(
            &manager,
            0x0ed1_0003,
            workspace,
            "tools/check.py",
            b"print('ledger')\n",
        ))
        .unwrap();
    assert_eq!(owed_records(&manager).len(), 1);

    // An ordinary transaction that moves the path to another body carries no
    // update of its own, and overtakes the record anyway.
    manager
        .commit_repository_transaction(publish_body_transaction(
            &manager,
            0x0ed1_0004,
            workspace,
            "src/lib.rs",
            b"pub fn kin() -> u32 { 3 }\n",
        ))
        .unwrap();
    assert!(owed_records(&manager).is_empty());
    drop(manager);
    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert!(owed_records(&reopened).is_empty());
}

/// A record rides its own publication's frame, and the journal replays it
/// exactly. A commit that pays the workspace clears it in its own frame, and a
/// frame that leaves the ledger alone keeps its version 4 body.
#[test]
fn owed_derivation_frames_replay_the_ledger_exactly() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed2_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    assert_eq!(
        acknowledged_frame_count(&directory),
        1,
        "a publication that records owed work is a frame, not a full snapshot"
    );
    let owing = manager.read_authority().roots().generation;
    let frame = std::fs::read(frame_path(&directory, 2)).unwrap();
    assert_eq!(
        header_version(&frame),
        crate::storage::AuthorityFrame::OWED_DERIVATION_VERSION,
        "a frame that moves the ledger declares version 5"
    );
    let decoded = crate::storage::AuthorityFrame::from_bytes(&frame).unwrap();
    assert!(!decoded.owed_derivations.is_unchanged());
    let recorded = manager.read_authority().metadata().owed_derivations.clone();
    drop(manager);

    let reopened = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    reopened
        .persistence()
        .set_journal_byte_bound_for_test(Some(u64::MAX));
    assert_eq!(
        reopened.read_authority().metadata().owed_derivations,
        recorded
    );
    assert_eq!(owed_records(&reopened)[0].3, owing);

    // Paying needs the workspace's own mutation; this one moves another path,
    // so it is the payment that clears the record, not an overtaking.
    reopened
        .commit_repository_transaction_owing(
            publish_body_transaction(
                &reopened,
                0x0ed2_0002,
                workspace,
                "tools/check.py",
                b"print('paid')\n",
            ),
            &OwedDerivationUpdate::pay(workspace),
        )
        .unwrap();
    assert!(owed_records(&reopened).is_empty());
    assert_eq!(acknowledged_frame_count(&directory), 2);
    let paying = std::fs::read(frame_path(&directory, 3)).unwrap();
    assert_eq!(
        header_version(&paying),
        crate::storage::AuthorityFrame::OWED_DERIVATION_VERSION,
        "the frame that empties the ledger still moves it"
    );

    reopened
        .commit_repository_transaction(binding_history_followup(&reopened, 0x0ed2_0003))
        .unwrap();
    assert_eq!(acknowledged_frame_count(&directory), 3);
    let untouched = std::fs::read(frame_path(&directory, 4)).unwrap();
    assert_eq!(
        header_version(&untouched),
        crate::storage::AuthorityFrame::BINDING_HISTORY_VERSION,
        "a frame that leaves the ledger alone keeps its version 4 body"
    );
    drop(reopened);
    let again = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert!(again
        .read_authority()
        .metadata()
        .owed_derivations
        .is_empty());
}

/// A non-empty ledger declares versions an older binary refuses at the header:
/// snapshot 19 without a section, where that binary reads at most 18, and
/// frame 5, where it reads at most 4. An empty ledger adds no element to the
/// envelope and moves no version, so a store that owes nothing keeps its bytes.
#[test]
fn owed_derivation_a_ledger_moves_versions_and_an_empty_one_moves_nothing() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let owes_nothing = manager.read_authority().snapshot().clone();
    let quiet_bytes = owes_nothing.to_bytes().unwrap();
    assert_eq!(header_version(&quiet_bytes), GraphSnapshot::BINDING_HISTORY_VERSION);
    let quiet_envelope =
        rmp_serde::to_vec(owes_nothing.repository_authority.as_ref().unwrap()).unwrap();
    assert_eq!(
        message_pack_array_len(&quiet_envelope),
        12,
        "an envelope with no merge record, lineage or owed work keeps its twelve elements"
    );

    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed3_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    let owing = manager.read_authority().snapshot().clone();
    let owing_bytes = owing.to_bytes().unwrap();
    assert_eq!(
        header_version(&owing_bytes),
        GraphSnapshot::OWED_DERIVATION_VERSION
    );
    assert!(
        header_version(&owing_bytes) > 18,
        "a binary that reads at most snapshot version 18 must refuse this at the header"
    );
    let decoded = GraphSnapshot::from_bytes(&owing_bytes).unwrap();
    assert_eq!(
        decoded.repository_authority.as_ref().unwrap().owed_derivations,
        owing.repository_authority.as_ref().unwrap().owed_derivations
    );

    // The same state with its ledger emptied serializes exactly as a state
    // that never had one: version 17 and no trailing element.
    let mut emptied = owing.clone();
    emptied
        .repository_authority
        .as_mut()
        .unwrap()
        .owed_derivations = OwedDerivationLedger::default();
    assert_eq!(emptied.wire_version(), GraphSnapshot::BINDING_HISTORY_VERSION);
    emptied.version = emptied.wire_version();
    let emptied_envelope =
        rmp_serde::to_vec(emptied.repository_authority.as_ref().unwrap()).unwrap();
    let owing_envelope =
        rmp_serde::to_vec(owing.repository_authority.as_ref().unwrap()).unwrap();
    assert_eq!(
        message_pack_array_len(&owing_envelope),
        message_pack_array_len(&emptied_envelope) + 3,
        "owed work fills the merge and lineage positions and appends the ledger"
    );
    let round_trip = GraphSnapshot::from_bytes(&emptied.to_bytes().unwrap()).unwrap();
    assert_eq!(round_trip.to_bytes().unwrap(), emptied.to_bytes().unwrap());
}

/// Storage checks every owed body against the transaction that claims it, and
/// carries a legacy obligation only while the successor still owes it.
#[test]
fn owed_derivation_updates_are_checked_against_their_successor() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    let roots = manager.read_authority().roots().clone();

    // A body this transaction did not publish is refused.
    let error = manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed6_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("tools/check.py"), digest(b"print('kin')\n"))],
                Vec::new(),
            ),
        )
        .unwrap_err();
    assert!(error.to_string().contains("not a body this transaction published"), "{error}");
    // Paying needs the workspace's own mutation.
    let error = manager
        .commit_repository_transaction_owing(
            binding_history_followup(&manager, 0x0ed6_0002),
            &OwedDerivationUpdate::pay(workspace),
        )
        .unwrap_err();
    assert!(error.to_string().contains("own mutation"), "{error}");
    assert_eq!(manager.read_authority().roots(), &roots);

    // A legacy obligation the successor still names is carried at this
    // generation; one it no longer names is overtaken and dropped.
    let check = owed_path("tools/check.py");
    let stale_legacy = (owed_path("compose.yaml"), digest(b"not what the tree holds"));
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed6_0003, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                vec![(check.clone(), digest(b"print('kin')\n")), stale_legacy],
            ),
        )
        .unwrap();
    let generation = manager.read_authority().roots().generation;
    assert_eq!(
        owed_records(&manager),
        vec![
            (
                workspace,
                "src/lib.rs".to_string(),
                digest(a),
                generation,
                OwedDerivationCause::Publication,
            ),
            (
                workspace,
                "tools/check.py".to_string(),
                digest(b"print('kin')\n"),
                generation,
                OwedDerivationCause::Legacy,
            ),
        ]
    );
}

/// A re-derivation of `workspace` that moves it, standing in for the overlay
/// change a real upgrade makes: it publishes `body` at `tools/check.py` and
/// leaves `src/lib.rs` alone, so a record at `src/lib.rs` leaves the ledger
/// only by being paid.
fn rederivation_transaction<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
    workspace: WorkspaceId,
    body: &[u8],
) -> RepositoryTransaction {
    publish_body_transaction(manager, operation, workspace, "tools/check.py", body)
}

fn rederivation_payment(workspace: WorkspaceId) -> RederivationPayment {
    RederivationPayment {
        workspace_id: workspace,
        hydration_version: 30,
    }
}

/// A payment is scoped to one workspace. A re-derivation that pays workspace A
/// drops A's records and records A's payment, while B's record, made at a
/// generation at or below A's payment, stays live and the store stays valid.
///
/// Falsify by paying every workspace's records: B's record is dropped.
#[test]
fn owed_derivation_paying_one_workspace_leaves_another_owed() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let first = manager.read_authority().metadata().workspaces[0].workspace_id;
    manager
        .commit_repository_transaction(second_workspace_transaction(&manager, 0x0ed4_0001, 0x5ec0))
        .unwrap();
    let second = WorkspaceId::from_uuid(Uuid::from_u128(0x5ec0));
    let b = b"pub fn kin() -> u32 { 2 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed4_0002, second, "src/lib.rs", b),
            &OwedDerivationUpdate::owe(
                second,
                vec![(owed_path("src/lib.rs"), digest(b))],
                Vec::new(),
            ),
        )
        .unwrap();
    let second_recorded_at = manager.read_authority().roots().generation;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed4_0003, first, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                first,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    let paid_through = manager.read_authority().roots().generation;
    assert!(
        second_recorded_at <= paid_through,
        "the other workspace's record must predate the payment, or scoping proves nothing"
    );

    let rederivation =
        rederivation_transaction(&manager, 0x0ed4_0004, first, b"print('rederived')\n");
    let paying_operation = rederivation.operation_id;
    manager
        .commit_rederived_repository_transaction(
            rederivation,
            &FixedRederivation::accepting(),
            rederivation_payment(first),
        )
        .unwrap();
    let expected = vec![(
        second,
        "src/lib.rs".to_string(),
        digest(b),
        second_recorded_at,
        OwedDerivationCause::Publication,
    )];
    assert_eq!(
        owed_records(&manager),
        expected,
        "paying the first workspace must leave the second workspace's record owed"
    );
    let ledger = manager.read_authority().metadata().owed_derivations.clone();
    let payment = ledger.payment_for(first).expect("the payment is recorded");
    assert_eq!(payment.paid_through(), paid_through);
    assert_eq!(payment.operation_id(), paying_operation);
    assert_eq!(payment.hydration_version(), 30);
    assert!(ledger.payment_for(second).is_none());
    crate::storage::derivation_ledger::validate_metadata(manager.read_authority().metadata())
        .unwrap();
    drop(manager);

    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert_eq!(reopened.read_authority().metadata().owed_derivations, ledger);
    // A later record of the paid workspace carries a later generation and is
    // owed again.
    let c = b"pub fn kin() -> u32 { 3 }\n";
    reopened
        .commit_repository_transaction_owing(
            publish_body_transaction(&reopened, 0x0ed4_0005, first, "src/lib.rs", c),
            &OwedDerivationUpdate::owe(
                first,
                vec![(owed_path("src/lib.rs"), digest(c))],
                Vec::new(),
            ),
        )
        .unwrap();
    assert_eq!(owed_records(&reopened).len(), 2);
}

/// A re-derivation planned before a later publication landed refuses at its
/// compare-and-swap, pays nothing, and leaves the later record owed. One that
/// lands pays through its exact predecessor, and a publication after it
/// records at a later generation.
///
/// Falsify by paying through the successor's generation: the payment names a
/// generation its operation did not commit from, and the commit refuses.
#[test]
fn owed_derivation_a_payment_pays_exactly_its_predecessor() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let stale = rederivation_transaction(&manager, 0x0ed5_0001, workspace, b"print('stale')\n");

    let other = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    let a = b"pub fn kin() -> u32 { 1 }\n";
    other
        .commit_repository_transaction_owing(
            publish_body_transaction(&other, 0x0ed5_0002, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    let recorded = owed_records(&other);
    assert_eq!(recorded.len(), 1);

    manager
        .commit_rederived_repository_transaction(
            stale,
            &FixedRederivation::accepting(),
            rederivation_payment(workspace),
        )
        .expect_err("a re-derivation planned before the publication must refuse");
    drop(manager);
    drop(other);
    let reopened = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    assert_eq!(
        owed_records(&reopened),
        recorded,
        "the refused re-derivation paid nothing"
    );
    assert!(reopened
        .read_authority()
        .metadata()
        .owed_derivations
        .payments()
        .is_empty());

    let predecessor = reopened.read_authority().roots().generation;
    reopened
        .commit_rederived_repository_transaction(
            rederivation_transaction(&reopened, 0x0ed5_0003, workspace, b"print('paid')\n"),
            &FixedRederivation::accepting(),
            rederivation_payment(workspace),
        )
        .unwrap();
    assert!(owed_records(&reopened).is_empty());
    let paid_through = reopened
        .read_authority()
        .metadata()
        .owed_derivations
        .payment_for(workspace)
        .expect("the payment is recorded")
        .paid_through();
    assert_eq!(
        paid_through, predecessor,
        "the payment names the exact predecessor its compare-and-swap was taken against"
    );
    let b = b"pub fn kin() -> u32 { 2 }\n";
    reopened
        .commit_repository_transaction_owing(
            publish_body_transaction(&reopened, 0x0ed5_0004, workspace, "src/lib.rs", b),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(b))],
                Vec::new(),
            ),
        )
        .unwrap();
    let after = owed_records(&reopened);
    assert_eq!(after.len(), 1);
    assert!(
        after[0].3 > paid_through,
        "a record made after the payment carries a later generation"
    );
}

/// Only a re-derivation its verifier proved, and that moves the workspace it
/// pays, pays anything. One the verifier declined and one that leaves the
/// workspace as it was both commit, pay nothing, and record no payment.
///
/// Falsify by paying without the verifier's witness: the declined
/// re-derivation drops the record.
#[test]
fn owed_derivation_an_unproven_rederivation_pays_nothing() {
    let directory = TempDir::new().unwrap();
    let (_backend, manager) = framed_local_repository(&directory);
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed8_0001, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                Vec::new(),
            ),
        )
        .unwrap();
    let recorded = owed_records(&manager);
    assert_eq!(recorded.len(), 1);

    let before = manager.read_authority().roots().generation;
    manager
        .commit_rederived_repository_transaction(
            rederivation_transaction(&manager, 0x0ed8_0002, workspace, b"print('declined')\n"),
            &FixedRederivation::declining(),
            rederivation_payment(workspace),
        )
        .unwrap();
    assert_eq!(manager.read_authority().roots().generation, before + 1);
    assert_eq!(
        owed_records(&manager),
        recorded,
        "a re-derivation the verifier declined pays nothing"
    );
    assert!(manager
        .read_authority()
        .metadata()
        .owed_derivations
        .payments()
        .is_empty());

    manager
        .commit_rederived_repository_transaction(
            binding_history_followup(&manager, 0x0ed8_0003),
            &FixedRederivation::accepting(),
            rederivation_payment(workspace),
        )
        .unwrap();
    assert_eq!(
        owed_records(&manager),
        recorded,
        "a re-derivation that leaves the workspace as it was pays nothing"
    );
    assert!(manager
        .read_authority()
        .metadata()
        .owed_derivations
        .payments()
        .is_empty());
}

/// A ledger forged out of shape is refused, not repaired, by the full
/// validation and by the envelope-only read alike.
#[test]
fn owed_derivation_a_forged_ledger_is_refused() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    manager
        .commit_repository_transaction(second_workspace_transaction(&manager, 0x0ed7_0001, 0x5ec0))
        .unwrap();
    let other_workspace_operation = manager
        .read_authority()
        .metadata()
        .operation_log
        .last()
        .expect("the second workspace's creation is logged")
        .clone();
    let a = b"pub fn kin() -> u32 { 1 }\n";
    manager
        .commit_repository_transaction_owing(
            publish_body_transaction(&manager, 0x0ed7_0002, workspace, "src/lib.rs", a),
            &OwedDerivationUpdate::owe(
                workspace,
                vec![(owed_path("src/lib.rs"), digest(a))],
                vec![(owed_path("tools/check.py"), digest(b"print('kin')\n"))],
            ),
        )
        .unwrap();
    let metadata = manager.read_authority().metadata().clone();
    let generation = metadata.roots.generation;
    assert_eq!(generation, 3, "the fixture made three operations");
    let owing_operation = metadata
        .operation_log
        .last()
        .expect("the owing publication is logged")
        .operation_id;
    let mut value = serde_json::to_value(&metadata).unwrap();
    // A payment through the generation before both records, naming the
    // operation that committed from it and moved the paid workspace, is the
    // shape a payment leaves, and it validates beside them.
    value["owed_derivations"]["payments"] = serde_json::json!([{
        "workspace_id": workspace,
        "paid_through": generation - 1,
        "operation_id": owing_operation,
        "hydration_version": 30,
    }]);
    let valid: PersistedRepositoryAuthority = serde_json::from_value(value.clone()).unwrap();
    crate::storage::derivation_ledger::validate_metadata(&valid).unwrap();
    assert_eq!(valid.owed_derivations.records().len(), 2);
    assert_eq!(valid.owed_derivations.payments().len(), 1);

    let other_paid_through = other_workspace_operation.roots_before.generation;
    let other_operation_id = other_workspace_operation.operation_id;
    let forgeries: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        (
            "a body the tree does not name",
            Box::new(|value| {
                value["owed_derivations"]["records"][0]["body"] =
                    serde_json::to_value(digest(b"forged")).unwrap();
            }),
        ),
        (
            "records out of order",
            Box::new(|value| {
                value["owed_derivations"]["records"]
                    .as_array_mut()
                    .unwrap()
                    .swap(0, 1);
            }),
        ),
        (
            "a record for a workspace the repository does not hold",
            Box::new(|value| {
                value["owed_derivations"]["records"][0]["workspace_id"] =
                    serde_json::to_value(WorkspaceId::from_uuid(Uuid::from_u128(0xdead))).unwrap();
            }),
        ),
        (
            "a record after the generation that holds it",
            Box::new(move |value| {
                value["owed_derivations"]["records"][0]["recorded_at"] = (generation + 1).into();
            }),
        ),
        (
            "a record at or below its workspace's payment",
            Box::new(move |value| {
                value["owed_derivations"]["records"][0]["recorded_at"] = (generation - 1).into();
            }),
        ),
        (
            "a payment for a workspace the repository does not hold",
            Box::new(|value| {
                value["owed_derivations"]["payments"][0]["workspace_id"] =
                    serde_json::to_value(WorkspaceId::from_uuid(Uuid::from_u128(0xdead))).unwrap();
            }),
        ),
        (
            "a payment that is not before the generation that holds it",
            Box::new(move |value| {
                value["owed_derivations"]["payments"][0]["paid_through"] = generation.into();
            }),
        ),
        (
            "a payment that names no logged operation",
            Box::new(|value| {
                value["owed_derivations"]["payments"][0]["operation_id"] =
                    serde_json::to_value(OperationId::from_uuid(Uuid::from_u128(0xbeef))).unwrap();
            }),
        ),
        (
            "a payment through a generation its operation did not commit from",
            Box::new(move |value| {
                value["owed_derivations"]["payments"][0]["paid_through"] =
                    (generation - 2).into();
            }),
        ),
        (
            "a payment naming a real operation that moved another existing workspace",
            Box::new(move |value| {
                value["owed_derivations"]["payments"][0]["operation_id"] =
                    serde_json::to_value(other_operation_id).unwrap();
                value["owed_derivations"]["payments"][0]["paid_through"] =
                    other_paid_through.into();
            }),
        ),
    ];
    for (name, forge) in forgeries {
        let mut forged = value.clone();
        forge(&mut forged);
        let forged: PersistedRepositoryAuthority = serde_json::from_value(forged).unwrap();
        assert!(
            crate::storage::derivation_ledger::validate_metadata(&forged).is_err(),
            "{name} was accepted"
        );
    }

    // The envelope-only read validates the ledger too. The same valid state is
    // served; a forged ledger written past the writer's own gate is refused.
    let served = RepositoryAuthorityMetadata::open(repository_id(), Arc::clone(&backend))
        .unwrap()
        .expect("an authority with no journal reads cheaply");
    assert_eq!(
        served.metadata().owed_derivations,
        metadata.owed_derivations
    );
    let mut forged_value = serde_json::to_value(&metadata).unwrap();
    forged_value["owed_derivations"]["records"][0]["body"] =
        serde_json::to_value(digest(b"forged")).unwrap();
    let forged_metadata: PersistedRepositoryAuthority =
        serde_json::from_value(forged_value).unwrap();
    let mut forged_snapshot = manager.read_authority().snapshot().clone();
    forged_snapshot.repository_authority = Some(forged_metadata);
    forged_snapshot.version = forged_snapshot.wire_version();
    let forged_backend = Arc::new(MemoryBackend::default());
    *forged_backend.snapshot.lock() = Some((forged_snapshot.to_bytes_pre_validated().unwrap(), 1));
    let refusal = RepositoryAuthorityMetadata::open(repository_id(), forged_backend)
        .err()
        .expect("the envelope-only read must refuse a ledger the full open refuses");
    assert!(
        refusal.to_string().contains("owed derivation ledger"),
        "{refusal}"
    );
}
