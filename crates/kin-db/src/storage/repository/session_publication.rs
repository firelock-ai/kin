// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use crate::storage::binding_history::{
    graph_digest, restore_prepared_successor, BindingHistoryVerifier,
};
use crate::storage::session_publication::{
    invalid, CapturedSessionGraph, PreparedSessionPublication, PreparedSessionRecord,
    SessionPublicationBinding, SessionPublicationLocator,
};

fn validate_scope(
    transaction: &RepositoryTransaction,
    workspace: WorkspaceId,
) -> Result<(), KinDbError> {
    transaction.validate()?;
    if transaction
        .workspace_mutation
        .as_ref()
        .map(|mutation| mutation.workspace_id)
        != Some(workspace)
        || !transaction.external_objects.is_empty()
        || transaction.git_authority_delta.is_some()
        || !transaction.changes.is_empty()
        || !transaction.aliases.is_empty()
        || !transaction.ref_mutations.is_empty()
        || transaction.default_ref_mutation.is_some()
        || transaction.local_overlay_delta.is_some()
        || transaction.merge_transaction_delta.is_some()
        || transaction.collaboration_delta.is_some()
    {
        return Err(invalid(
            "preparation requires one workspace-only local transaction",
        ));
    }
    Ok(())
}

impl RepositoryAuthorityManager<LocalFileBackend> {
    /// Admit a real in-process semantic observation and its exact successor,
    /// then acknowledge immutable preparation without publishing the target.
    /// The caller retains projection custody separately; no session sidecar
    /// can mint this handle or select its binding-history qualification.
    pub fn prepare_session_publication(
        &self,
        transaction: RepositoryTransaction,
        workspace: WorkspaceId,
        binding: SessionPublicationBinding,
        observed: &GraphSnapshot,
        verifier: &dyn BindingHistoryVerifier,
    ) -> Result<PreparedSessionPublication, KinDbError> {
        self.prepare_session_publication_inner(
            transaction,
            workspace,
            binding,
            None,
            observed,
            verifier,
        )
    }

    /// Prepare a v2 record with an explicit runtime recovery locator. This
    /// records the caller's retained observation; it does not itself establish
    /// filesystem custody. A retry must supply the same locator and binding.
    pub fn prepare_session_publication_with_locator(
        &self,
        transaction: RepositoryTransaction,
        workspace: WorkspaceId,
        binding: SessionPublicationBinding,
        locator: SessionPublicationLocator,
        observed: &GraphSnapshot,
        verifier: &dyn BindingHistoryVerifier,
    ) -> Result<PreparedSessionPublication, KinDbError> {
        locator.validate()?;
        self.prepare_session_publication_inner(
            transaction,
            workspace,
            binding,
            Some(locator),
            observed,
            verifier,
        )
    }

    fn prepare_session_publication_inner(
        &self,
        transaction: RepositoryTransaction,
        workspace: WorkspaceId,
        binding: SessionPublicationBinding,
        recovery_locator: Option<SessionPublicationLocator>,
        observed: &GraphSnapshot,
        verifier: &dyn BindingHistoryVerifier,
    ) -> Result<PreparedSessionPublication, KinDbError> {
        binding.validate()?;
        validate_scope(&transaction, workspace)?;
        let transaction_hash = transaction.transaction_hash()?;
        self.publication.prepare_exclusive(|current| {
            // Prepare under the in-process writer permit. CAS admission takes
            // its own shared backend locks; acquire the exclusive freeze only
            // afterwards and compare exact durable bytes before acknowledgement.
            let prior = self.backend.load_session_publication(
                self.repository_id.as_str(),
                Some(transaction.operation_id),
            )?;
            if let Some((bytes, payload_sha256, committed)) = prior {
                let record = PreparedSessionRecord::decode(&bytes)?;
                if committed
                    || record.receipt.transaction_hash != transaction_hash
                    || record.workspace != workspace
                    || record.binding != binding
                    || record.recovery_locator != recovery_locator
                    || record.observed_digest != graph_digest(observed)?
                {
                    return Err(invalid(
                        "operation already names another or completed preparation",
                    ));
                }
                let handle = PreparedSessionPublication {
                    record,
                    payload_sha256,
                };
                self.prepared_session_decision(current, &handle)?;
                let frozen = self.freeze_exact_state(current)?;
                if current.durable_identity() != Some(frozen._lock.identity()) {
                    return Err(invalid("preparation authority bytes changed"));
                }
                self.backend
                    .install_session_publication(&frozen._lock, &handle.record)?;
                return Ok(handle);
            }
            let selected = current
                .workspace_graph_snapshot(&workspace)?
                .ok_or_else(|| invalid("selected workspace is absent"))?;
            let captured = CapturedSessionGraph::capture(observed);
            let compact = captured.graph();
            if compact.resolved_tree != selected.resolved_tree {
                return Err(invalid(
                    "observation does not name the exact predecessor tree",
                ));
            }
            compact.validate_authority_free_storage_admission()?;
            validate_tree_bodies(
                self.backend.as_ref(),
                &self.repository_id,
                &compact.resolved_tree,
                None,
                "prepared observation",
            )?;
            let load_body = |digest| self.load_source_blob(digest);
            if !verifier.verify_graph_transition(observed, observed, &load_body)? {
                return Err(invalid(
                    "observed source/semantic graph did not pass compiled admission",
                ));
            }
            let candidate = self.backend.load_unacknowledged_session_candidate(
                self.repository_id.as_str(),
                transaction.operation_id,
            )?;
            if let Some(candidate) = &candidate {
                if candidate.receipt.transaction_hash != transaction_hash
                    || candidate.binding != binding
                    || candidate.recovery_locator != recovery_locator
                    || candidate.workspace != workspace
                    || candidate.observed_digest != graph_digest(observed)?
                {
                    return Err(invalid(
                        "unacknowledged operation candidate names different inputs",
                    ));
                }
            }
            let decision = prepare_repository_commit_decision_with_history(
                current,
                &transaction,
                transaction_hash,
                &self.repository_id,
                self.backend.as_ref(),
                NativeAdmissionSource::LocalWorkspace,
                None,
                candidate.map(|candidate| candidate.receipt.operation.committed_at),
            )?;
            let decision = self.qualify_binding_history_decision(
                current,
                &transaction,
                decision,
                verifier,
                Some((workspace, observed)),
            )?;
            let AuthorityCommitDecision::Publish { next, output } = decision else {
                return Err(invalid(
                    "completed legacy operation cannot become a new preparation",
                ));
            };
            let successor = next
                .workspace_graph_snapshot(&workspace)?
                .ok_or_else(|| invalid("successor workspace is absent"))?;
            let frozen = self.freeze_exact_state(current)?;
            if current.durable_identity() != Some(frozen._lock.identity()) {
                return Err(invalid("preparation authority bytes changed"));
            }
            let record = PreparedSessionRecord {
                version: if recovery_locator.is_some() { 2 } else { 1 },
                binding,
                recovery_locator,
                workspace,
                predecessor_authority: frozen._lock.identity().session_binding()?,
                predecessor_backend_generation: frozen._lock.identity().head_generation(),
                transaction,
                observed: captured,
                observed_digest: graph_digest(observed)?,
                successor_graph_digest: graph_digest(&successor)?,
                successor_history: next.metadata().binding_history.clone(),
                receipt: output,
            };
            let payload_sha256 = self
                .backend
                .install_session_publication(&frozen._lock, &record)?;
            Ok(PreparedSessionPublication {
                record,
                payload_sha256,
            })
        })
    }

    /// Load one required local preparation. Unknown/absent records are never
    /// recomputed from the current workspace or optional query cache.
    pub fn load_prepared_session_publication(
        &self,
        operation: OperationId,
    ) -> Result<Option<PreparedSessionPublication>, KinDbError> {
        self.load_session_publication_inner(Some(operation))
    }

    /// Startup callers must inspect this before admitting new observations.
    /// This DB-only API does not itself implement daemon startup fencing.
    pub fn active_prepared_session_publication(
        &self,
    ) -> Result<Option<PreparedSessionPublication>, KinDbError> {
        self.load_session_publication_inner(None)
    }

    fn load_session_publication_inner(
        &self,
        operation: Option<OperationId>,
    ) -> Result<Option<PreparedSessionPublication>, KinDbError> {
        self.publication.prepare_exclusive(|current| {
            let Some((bytes, payload_sha256, committed)) = self.backend.load_session_publication(self.repository_id.as_str(), operation)? else { return Ok(None); };
            let record = PreparedSessionRecord::decode(&bytes)?;
            let handle = PreparedSessionPublication { record, payload_sha256 };
            let decision = self.prepared_session_decision(current, &handle)?;
            if committed != matches!(decision, AuthorityCommitDecision::IdempotentReplay { .. }) {
                return Err(invalid("prepared status differs from manager authority; reopen exact durable authority before retry"));
            }
            Ok(Some(handle))
        })
    }

    fn prepared_session_decision(
        &self,
        current: &RepositoryAuthorityState,
        handle: &PreparedSessionPublication,
    ) -> Result<
        AuthorityCommitDecision<RepositoryAuthorityState, RepositoryCommitReceipt>,
        KinDbError,
    > {
        let record = &handle.record;
        validate_scope(&record.transaction, record.workspace)?;
        if record.transaction.repository_id != self.repository_id {
            return Err(invalid("handle belongs to another repository"));
        }
        let decision = prepare_repository_commit_decision_with_history(
            current,
            &record.transaction,
            record.receipt.transaction_hash,
            &self.repository_id,
            self.backend.as_ref(),
            NativeAdmissionSource::LocalWorkspace,
            None,
            Some(record.receipt.operation.committed_at.clone()),
        )?;
        match decision {
            AuthorityCommitDecision::IdempotentReplay { output } => {
                if output.operation != record.receipt.operation {
                    return Err(invalid("completed operation differs from preparation"));
                }
                Ok(AuthorityCommitDecision::IdempotentReplay { output })
            }
            AuthorityCommitDecision::Publish { mut next, output } => {
                if current
                    .durable_identity()
                    .map(DurableAuthorityIdentity::session_binding)
                    .transpose()?
                    .as_deref()
                    != Some(&record.predecessor_authority)
                    || output != record.receipt
                {
                    return Err(invalid("prepared predecessor or resulting receipt changed"));
                }
                let selected = current
                    .workspace_graph_snapshot(&record.workspace)?
                    .ok_or_else(|| invalid("prepared workspace is absent"))?;
                let observed = record.observed.graph();
                if selected.resolved_tree != observed.resolved_tree {
                    return Err(invalid("prepared observation tree differs"));
                }
                observed.validate_authority_free_storage_admission()?;
                validate_tree_bodies(
                    self.backend.as_ref(),
                    &self.repository_id,
                    &observed.resolved_tree,
                    None,
                    "prepared observation",
                )?;
                restore_prepared_successor(
                    current.metadata(),
                    next.snapshot
                        .repository_authority
                        .as_mut()
                        .expect("admitted authority"),
                    record.workspace,
                    record.observed_digest,
                    &record.successor_history,
                )?;
                let successor = next
                    .workspace_graph_snapshot(&record.workspace)?
                    .ok_or_else(|| invalid("prepared successor is absent"))?;
                if graph_digest(&successor)? != record.successor_graph_digest {
                    return Err(invalid("prepared successor graph changed"));
                }
                Ok(AuthorityCommitDecision::Publish { next, output })
            }
        }
    }

    /// Publish only the exact acknowledged transaction/proof. An uncertain
    /// response retains durable evidence and requires this path (or cold
    /// load/replay), never an ordinary replan at a later head.
    pub fn commit_prepared_session_publication(
        &self,
        handle: &PreparedSessionPublication,
    ) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze), KinDbError> {
        self.publication.commit_durably_prepared(
            |current| {
                let Some((bytes, digest, _)) = self.backend.load_session_publication(
                    self.repository_id.as_str(),
                    Some(handle.operation_id()),
                )?
                else {
                    return Err(invalid("handle has no acknowledged preparation"));
                };
                if digest != handle.payload_sha256
                    || PreparedSessionRecord::decode(&bytes)?.content_digest()?
                        != handle.record.content_digest()?
                {
                    return Err(invalid("handle differs from immutable preparation"));
                }
                self.prepared_session_decision(current, handle)
            },
            |_, current| self.freeze_exact_state(current),
            |persistence, _, next| match persistence
                .persist_prepared_session_and_freeze(next, &handle.payload_sha256)
            {
                RetainedPersistOutcome::Committed { retained } => {
                    RetainedPersistOutcome::Committed {
                        retained: LocalRepositoryAuthorityFreeze {
                            state: Arc::clone(next),
                            _lock: retained,
                        },
                    }
                }
                RetainedPersistOutcome::NotCommitted(error) => {
                    RetainedPersistOutcome::NotCommitted(error)
                }
                RetainedPersistOutcome::Indeterminate(error) => {
                    RetainedPersistOutcome::Indeterminate(error)
                }
            },
        )
    }
}

impl RepositorySnapshotPersistence<LocalFileBackend> {
    fn persist_prepared_session_and_freeze(
        &self,
        next: &RepositoryAuthorityState,
        digest: &str,
    ) -> RetainedPersistOutcome<LocalAuthorityFreezeLock> {
        self.persist_and_freeze_inner(next, Some(digest))
    }
}
