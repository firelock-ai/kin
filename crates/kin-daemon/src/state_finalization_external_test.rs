// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_model::{
    ExternalReference, ExternalReferenceDelta, RepositoryTransaction, WorkspaceExpectation,
    WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

fn reference(symbol: &str) -> ExternalReference {
    ExternalReference::new_resolved("finalization-fixture-v1", "package:example@1", symbol).unwrap()
}

/// Real local authority publication. Synthetic resolved coordinates isolate
/// finalization, not a language resolver or session process acceptance claim.
fn commit_external_transition(
    state: &DaemonState,
    delta: Vec<ExternalReferenceDelta>,
) -> (RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze) {
    let binding = state.local_repository_authority_binding().unwrap();
    let authority = binding.open_manager().unwrap();
    let lease = authority.read_authority();
    let roots = lease.roots().clone();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == binding.workspace_id())
        .unwrap()
        .clone();
    drop(lease);
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: binding.repository_id().clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("finalization-fixture"),
        reason: "publish exact external endpoints".into(),
        external_objects: Vec::new(),
        changes: Vec::new(),
        aliases: Vec::new(),
        git_authority_delta: None,
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace.generation + 1,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: workspace.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::new_with_external_references(
                Vec::new(),
                Vec::new(),
                delta,
            )
            .unwrap(),
            new_shared_admission_policy: workspace.shared_admission_policy,
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    authority
        .commit_repository_transaction_and_freeze(transaction)
        .unwrap()
}

fn finalize(
    state: &DaemonState,
    receipt: &RepositoryCommitReceipt,
    freeze: &LocalRepositoryAuthorityFreeze,
) -> LocalRepositoryFinalization {
    let tree = state.graph.resolved_tree();
    state
        .finalize_local_repository_commit(
            receipt,
            freeze,
            &TransactionDelta::default(),
            &tree,
            &tree,
        )
        .unwrap()
}

#[test]
fn exact_finalization_installs_external_endpoints_and_replay_keeps_generation() {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let state = DaemonState::open(init.layout.clone()).unwrap();
    let expected = reference("added");
    let (receipt, freeze) = commit_external_transition(
        &state,
        vec![ExternalReferenceDelta::Added {
            new: expected.clone(),
        }],
    );
    let finalized = finalize(&state, &receipt, &freeze);
    assert!(
        finalized.graph_changed,
        "external-only publication changed the live graph"
    );
    assert!(finalized.generation_advanced);
    assert_eq!(
        state
            .graph
            .semantic_observation()
            .external_references
            .get(&expected.id),
        Some(&expected)
    );
    let again = finalize(&state, &receipt, &freeze);
    assert!(!again.graph_changed);
    assert!(!again.generation_advanced);
    assert_eq!(
        state.snapshot_generation.load(Ordering::SeqCst),
        receipt.generation
    );
    drop(freeze);
    let reopened = DaemonState::open(init.layout).unwrap();
    assert_eq!(
        reopened.graph.semantic_observation().external_references,
        state.graph.semantic_observation().external_references
    );
}

#[test]
fn exact_finalization_removes_retired_and_live_only_endpoints_but_keeps_survivors() {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let initial = DaemonState::open(init.layout.clone()).unwrap();
    let old = reference("retired");
    let kept = reference("kept");
    let (_, initial_freeze) = commit_external_transition(
        &initial,
        vec![
            ExternalReferenceDelta::Added { new: old.clone() },
            ExternalReferenceDelta::Added { new: kept.clone() },
        ],
    );
    drop(initial_freeze);
    drop(initial);
    // Cold open supplies the actual predecessor even before finalization is fixed.
    let state = DaemonState::open(init.layout.clone()).unwrap();
    let extra = reference("live-only");
    state
        .graph
        .apply_transaction_delta(&TransactionDelta {
            external_reference_deltas: vec![ExternalReferenceDelta::Added { new: extra }],
            ..Default::default()
        })
        .unwrap();
    let new = reference("replacement");
    let (receipt, freeze) = commit_external_transition(
        &state,
        vec![
            ExternalReferenceDelta::Removed { old },
            ExternalReferenceDelta::Added { new: new.clone() },
        ],
    );
    let finalized = finalize(&state, &receipt, &freeze);
    assert!(finalized.graph_changed);
    let after = state.graph.semantic_observation();
    assert_eq!(after.external_references.len(), 2);
    assert_eq!(after.external_references.get(&kept.id), Some(&kept));
    assert_eq!(after.external_references.get(&new.id), Some(&new));
    let durable = freeze
        .authority()
        .workspace_graph_snapshot(&state.cached_workspace_id.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(after.external_references, durable.external_references);
    drop(freeze);
    let reopened = DaemonState::open(init.layout).unwrap();
    assert_eq!(
        after.external_references,
        reopened.graph.semantic_observation().external_references
    );
}
