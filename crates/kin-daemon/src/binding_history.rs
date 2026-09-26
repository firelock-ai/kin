// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Local derived observations remain qualified only through checked semantic
//! transitions. Durable exact-tree publication captures these observations
//! before retirement, including bindings that no native commit recorded.

use crate::state::DaemonState;
use kin_model::EntityStore as _;

pub(crate) fn restore_exact_authority(state: &DaemonState) {
    if state.storage_backend.is_some() {
        return;
    }
    let result = (|| -> crate::Result<()> {
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
        let authority = context.open()?;
        let lease = authority.read_authority();
        if let Some(snapshot) = lease.workspace_graph_snapshot(&context.workspace_id())? {
            let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot)?;
            state.graph.restore_binding_history_from(&graph);
        }
        Ok(())
    })();
    if let Err(error) = result {
        tracing::debug!(%error, "binding history exact authority restoration unavailable");
    }
}

pub(crate) struct Derivation<'a> {
    state: &'a DaemonState,
    before: kin_db::GraphSnapshot,
}

impl<'a> Derivation<'a> {
    pub(crate) fn begin(state: &'a DaemonState) -> Self {
        if matches!(
            state.graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Unproven
        ) {
            restore_exact_authority(state);
        }
        Self {
            state,
            before: state.graph.semantic_observation(),
        }
    }
}

impl Drop for Derivation<'_> {
    fn drop(&mut self) {
        let load = |digest: kin_model::Hash256| -> Result<Option<Vec<u8>>, kin_db::KinDbError> {
            let hash = kin_blobs::Hash256::from_bytes(*digest.as_bytes());
            if let Ok(bytes) = self.state.blobs.read(&hash) {
                return Ok(Some(bytes));
            }
            let context =
                crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(
                    self.state,
                )
                .map_err(|error| kin_db::KinDbError::StorageError(error.to_string()))?;
            context.open()?.load_source_blob(digest)
        };
        if let Err(error) = self.state.graph.qualify_binding_history_derivation(
            &self.before,
            &kin_index::binding_history::LocalBindingHistoryVerifier,
            &load,
        ) {
            tracing::debug!(%error, "binding history derivation remains unknown");
        }
    }
}

/// An actual live observation retained while a local writer holds its
/// coordination, graph-authority and persistence gates. It is not a request
/// field, a reparse of current bytes, or a substitute for an unknown interval.
pub(crate) struct SameTreeCapture {
    pub(crate) observed: kin_db::GraphSnapshot,
    pub(crate) roots: kin_model::RootBundle,
    pub(crate) mutation: Option<kin_model::WorkspaceMutation>,
    qualification_lost: bool,
}

pub(crate) fn capture_review_predecessor(
    state: &DaemonState,
    authority: &crate::local_repository_authority::ActiveLocalRepositoryAuthority,
) -> Result<Option<SameTreeCapture>, kin_db::KinDbError> {
    capture_same_tree_predecessor(state, authority, false)
}

/// Materialization also records qualification loss. Unlike a review with its
/// own collaboration mutation, it needs an explicit authority publication
/// when an Unknown live interval replaces a Checked durable observation.
fn capture_same_tree_predecessor(
    state: &DaemonState,
    authority: &crate::local_repository_authority::ActiveLocalRepositoryAuthority,
    capture_unknown: bool,
) -> Result<Option<SameTreeCapture>, kin_db::KinDbError> {
    use kin_model::{
        ExternalReferenceDelta, WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta,
    };
    let observed = state.graph.semantic_observation();
    if !capture_unknown && observed.verified_binding_history.is_none() {
        // Do not restore from matching durable bytes here: that would bless a
        // potentially unobserved mutation interval before this review arrived.
        return Ok(None);
    }
    let lease = authority.manager.read_authority();
    let Some(selected) = lease.workspace_graph_snapshot(&authority.workspace_id)? else {
        if capture_unknown {
            return Err(kin_db::KinDbError::StorageError(
                "session materialization has no selected authority graph".into(),
            ));
        }
        return Ok(None);
    };
    if state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst)
        != lease.roots().generation
    {
        return Err(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(
            "same-tree observation belongs to another repository generation".into(),
        )));
    }
    if !kin_db::storage::binding_history::is_checked_derivation_of(&selected, &observed)? {
        if !capture_unknown {
            return Ok(None);
        }
        if observed.resolved_tree != selected.resolved_tree
            || observed.verified_binding_history.is_some()
        {
            return Err(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(
                "session observation is not bound to the selected authority predecessor".into(),
            )));
        }
    }
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .expect("selected workspace is admitted");
    let semantic = kin_core::diff_workspace_semantics(
        &selected.entities,
        &selected.relations,
        &observed.entities,
        &observed.relations,
    )
    .map_err(|error| kin_db::KinDbError::StorageError(error.to_string()))?;
    let mut references = Vec::new();
    for (id, old) in &selected.external_references {
        match observed.external_references.get(id) {
            None => references.push(ExternalReferenceDelta::Removed { old: old.clone() }),
            Some(new) if old != new => {
                return Err(kin_db::KinDbError::StorageError(
                    "review observation rewrote an immutable external reference".into(),
                ))
            }
            _ => {}
        }
    }
    for (id, new) in &observed.external_references {
        if !selected.external_references.contains_key(id) {
            references.push(ExternalReferenceDelta::Added { new: new.clone() });
        }
    }
    let semantic = WorkspaceSemanticDelta::new_with_external_references(
        semantic.entity_deltas().to_vec(),
        semantic.relation_deltas().to_vec(),
        references,
    )?;
    let qualification_lost = capture_unknown
        && observed.verified_binding_history.is_none()
        && selected.verified_binding_history.is_some();
    let mutation = if semantic.is_empty() {
        None
    } else {
        Some(WorkspaceMutation {
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
            new_generation: workspace.generation.checked_add(1).ok_or_else(|| {
                kin_db::KinDbError::StorageError("review workspace generation exhausted".into())
            })?,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: workspace.tree_hash,
            semantic_delta: semantic,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        })
    };
    Ok(Some(SameTreeCapture {
        observed,
        roots: lease.roots().clone(),
        mutation,
        qualification_lost,
    }))
}

pub(crate) fn restore_review_publication(
    state: &DaemonState,
    authority: &crate::local_repository_authority::ActiveLocalRepositoryAuthority,
) -> Result<(), kin_db::KinDbError> {
    let lease = authority.manager.read_authority();
    if state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst)
        != lease.roots().generation
    {
        return Err(kin_db::KinDbError::StorageError(
            "review finalization does not name the committed repository generation".into(),
        ));
    }
    if let Some(snapshot) = lease.workspace_graph_snapshot(&authority.workspace_id)? {
        let admitted = kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot)?;
        // An ordinary Unknown publication has no capability to copy. A checked
        // one restores only if the actual live semantic maps still equal it.
        state.graph.restore_binding_history_from(&admitted);
    }
    Ok(())
}

/// Capture the actual live same-tree observation before creating a disposable
/// session base. Caller holds coordination and graph-authority mutation gates.
/// No native change or review record is manufactured, and matching semantics
/// plus matching qualification need no repository operation.
pub(crate) fn capture_session_materialization(
    state: &DaemonState,
) -> crate::Result<kin_model::RootBundle> {
    use kin_model::{
        AuthorId, OperationId, RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    if state.storage_backend.is_some() {
        return Err(kin_db::KinDbError::StorageError(
            "local session materialization is unavailable for hosted snapshot authority".into(),
        )
        .into());
    }
    let _persistence = state
        .persist_lock
        .lock()
        .map_err(|_| kin_db::KinDbError::StorageError("daemon persistence lock poisoned".into()))?;
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open_bound(state)
            .map_err(|refusal| {
                kin_db::KinDbError::StorageError(format!("{:#}", refusal.into_error()))
            })?;
    let mut capture = capture_same_tree_predecessor(state, &authority, true)?
        .ok_or_else(|| kin_db::KinDbError::StorageError("session observation is absent".into()))?;
    if capture.mutation.is_none() && !capture.qualification_lost {
        return Ok(capture.roots);
    }
    let operation_id = OperationId::new();
    // Empty workspace mutations are correctly rejected by the model. Record
    // this real loss of qualification as provenance instead of inventing a
    // source edit or review. The ordinary transaction clears history.
    let loss_event = if capture.mutation.is_none() {
        Some(kin_cli::provenance::plan_audit_event(
            state.graph.as_ref(),
            "kin-daemon-session-materialization",
            "session_materialization_history_unproven",
            None,
            Some(serde_json::json!({
                "repository_id": authority.repository_id,
                "workspace_id": authority.workspace_id,
                "authority_roots": capture.roots,
                "operation_id": operation_id,
                "intent": "retain an unobserved live interval before disposable session materialization"
            }).to_string()),
        ).map_err(|error| kin_db::KinDbError::StorageError(error.to_string()))?)
    } else {
        None
    };
    let collaboration_delta =
        loss_event
            .as_ref()
            .map(|(actor, event)| kin_model::CollaborationDelta {
                actors: actor
                    .iter()
                    .map(|actor| kin_model::Keyed::new(actor.actor_id, actor.clone()))
                    .collect(),
                audit_events: vec![event.clone()],
                ..Default::default()
            });
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: capture.roots.generation,
        expected_roots: capture.roots,
        actor: AuthorId::new("kin-session-materialize"),
        reason: "capture observed semantics before disposable session materialization".into(),
        external_objects: vec![],
        git_authority_delta: None,
        changes: vec![],
        aliases: vec![],
        ref_mutations: vec![],
        default_ref_mutation: None,
        workspace_mutation: capture.mutation.take(),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta,
    };
    let receipt = if capture.observed.verified_binding_history.is_some() {
        authority
            .manager
            .commit_repository_transaction_with_observed_binding_history(
                transaction,
                authority.workspace_id,
                &capture.observed,
                &kin_index::binding_history::LocalBindingHistoryVerifier,
            )?
    } else {
        authority
            .manager
            .commit_repository_transaction(transaction)?
    };
    state.record_repository_authority_commit(receipt.generation)?;
    if let Some((actor, event)) = loss_event {
        use kin_model::graph::ProvenanceStore as _;
        if let Some(actor) = actor {
            state.graph.create_actor(&actor)?;
        }
        state.graph.record_audit_event(&event)?;
    }
    restore_review_publication(state, &authority)?;
    state.bump_version();
    state.mark_dirty();
    state.emit_event(crate::state::DaemonEvent::RepositoryAuthorityChanged {
        repository_id: receipt.repository_id.to_string(),
        operation_id: receipt.operation_id,
        previous_generation: receipt.roots_before.generation,
        new_generation: receipt.generation,
    });
    Ok(receipt.roots_after)
}
