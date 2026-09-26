// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_db::storage::{
    PreparedSessionPublication, SessionPublicationBinding, SessionPublicationLocator,
};

/// The operation owner's custody must drop before the retained authority freeze
/// if an acknowledged publication cannot finish. In the daemon that custody is
/// armed to stop the process before queued writers can resume.
pub struct PreparedSessionWorkspaceCommit<C> {
    custody: C,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
}

impl<C> PreparedSessionWorkspaceCommit<C> {
    /// Called only after finalization and authenticated WAL cleanup succeeded.
    /// The owner still owes its explicit serving-fence completion before it
    /// releases coordinator/persistence custody or returns the receipt.
    pub fn into_parts(self) -> (C, RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze) {
        (self.custody, self.receipt, self.authority_freeze)
    }
}

struct Acknowledged<C> {
    // Declaration order matters on failure: stop before dropping other custody.
    custody: C,
    handle: PreparedSessionPublication,
}

/// Publish one newly observed session using required immutable preparation.
///
/// `revalidate_and_arm` runs after the final projection identity checks and
/// before the DB acknowledgement or projection WAL. It must recheck the retained
/// session inputs and return request-independent custody whose unresolved Drop
/// prevents ordinary service from continuing. Existing acknowledged operations
/// belong to exact prepared recovery; they cannot be reconstructed here.
///
/// `release_unacknowledged` runs only after the manager positively proves that
/// this preparation is absent, no other preparation is active and its original
/// roots remain selected. At that point no WAL or primary mutation has occurred.
/// On every other preparation/commit/finalization error custody stays armed and
/// is dropped under the projection freeze. A caller must never supply a guard
/// that releases ordinary mutation capability on such a drop.
#[allow(clippy::too_many_arguments)]
pub fn publish_prepared_session_workspace<C>(
    root: &Path,
    previous_tree: &ResolvedTree,
    target_tree: &ResolvedTree,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
    workspace: WorkspaceId,
    binding: SessionPublicationBinding,
    locator: SessionPublicationLocator,
    observed: &kin_db::GraphSnapshot,
    revalidate_and_arm: impl FnOnce() -> Result<C>,
    release_unacknowledged: impl FnOnce(C),
    finalize: impl FnOnce(
        &RepositoryCommitReceipt,
        &LocalRepositoryAuthorityFreeze,
        &mut C,
    ) -> Result<()>,
) -> Result<(usize, PreparedSessionWorkspaceCommit<C>)> {
    let operation = transaction.operation_id;
    if authority
        .load_prepared_session_publication(operation)
        .map_err(db_error)?
        .is_some()
    {
        return Err(KinError::RepositoryConflict(
            "acknowledged session operation requires exact prepared recovery".into(),
        ));
    }
    let previous_owned =
        load_repository_projection_entries(authority, previous_tree, "previous session workspace")?;
    let target_owned =
        load_repository_projection_entries(authority, target_tree, "target session workspace")?;
    let previous_entries = validated_source_entries(
        previous_owned
            .iter()
            .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
    )?;
    let entries = validated_source_entries(
        target_owned
            .iter()
            .map(|entry| (&entry.path, entry.kind, entry.content.as_slice())),
    )?;
    validate_repository_projection_transaction(
        previous_tree,
        target_tree,
        &previous_entries,
        &entries,
        &transaction,
        GraphOnlyTransitionPolicy::AllowExactMetadataTransition,
    )?;
    let marker = ReconciliationAuthorityCommit {
        repository_id: transaction.repository_id.clone(),
        operation_id: operation,
        transaction_hash: transaction.transaction_hash().map_err(db_error)?,
    };
    let expected_roots = transaction.expected_roots.clone();
    let materialized_count = entries.len();
    project_reconciled_source_tree_and_publish(
        root, &previous_entries, &entries, &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingRepositoryFrozen(authority),
            graph_only_transition: Some(GraphOnlyWorkspaceTransition { previous_tree, target_tree, scope: None }),
            ..ReconciledProjectionOptions::default()
        },
        || {}, || {}, || {}, Some(marker), None,
        || {
            let custody = revalidate_and_arm()?;
            match authority.prepare_session_publication_with_locator(
                transaction, workspace, binding, locator, observed,
                &kin_index::binding_history::LocalBindingHistoryVerifier,
            ) {
                Ok(handle) => Ok(Acknowledged { custody, handle }),
                Err(error) => {
                    // Err alone does not establish absence: acknowledgement
                    // may have become durable before its response failed.
                    let absent = authority.load_prepared_session_publication(operation)
                        .and_then(|record| {
                            if record.is_some() { return Ok(false); }
                            authority.active_prepared_session_publication().map(|active| {
                                active.is_none() && authority.read_authority().roots() == &expected_roots
                            })
                        });
                    if matches!(absent, Ok(true)) {
                        release_unacknowledged(custody);
                    } else {
                        // For an actual daemon owner this does not return.
                        drop(custody);
                    }
                    Err(db_error(error))
                }
            }
        },
        |acknowledged| {
            let result = authority.commit_prepared_session_publication(&acknowledged.handle)
                .or_else(|first| {
                    authority.commit_prepared_session_publication(&acknowledged.handle)
                        .map_err(|second| KinError::RepositoryCommitIndeterminate(format!(
                            "prepared session commit failed: {first}; exact prepared retry: {second}; authenticated projection WAL retained"
                        )))
                });
            match result {
                Ok((receipt, authority_freeze)) => ProjectionAuthorityCommit::Committed(
                    PreparedSessionWorkspaceCommit { custody: acknowledged.custody, receipt, authority_freeze }
                ),
                Err(error) => {
                    // Do not downgrade to an ordinary transaction retry or
                    // remove the required preparation after a refused commit.
                    drop(acknowledged);
                    ProjectionAuthorityCommit::Indeterminate(error)
                }
            }
        },
        |committed| finalize(&committed.receipt, &committed.authority_freeze, &mut committed.custody),
    ).map(|(_, committed)| (materialized_count, committed))
}

fn db_error(error: impl std::fmt::Display) -> KinError {
    KinError::Other(error.to_string())
}
