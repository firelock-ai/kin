// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_db::storage::PreparedSessionPublication;

/// Whether recovery published a saved target or recovered an original receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedRecoveryDisposition {
    ActivePublished,
    CompletedCurrent,
    /// Never install this receipt's old roots: the freeze names later authority.
    HistoricalReceipt,
}

/// Armed custody drops before the authority freeze on every unresolved return.
pub struct PreparedSessionWorkspaceRecovery<C> {
    custody: C,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    disposition: PreparedRecoveryDisposition,
}
impl<C> PreparedSessionWorkspaceRecovery<C> {
    pub fn into_parts(
        self,
    ) -> (
        C,
        RepositoryCommitReceipt,
        LocalRepositoryAuthorityFreeze,
        PreparedRecoveryDisposition,
    ) {
        (
            self.custody,
            self.receipt,
            self.authority_freeze,
            self.disposition,
        )
    }
}

// Field order matters. Keep outer projection custody while the inner engine
// owns C, and C first while this owner holds an additional authority freeze.
struct RecoveryOwner<C> {
    custody: Option<C>,
    projection: Option<ExactProjectionFreeze>,
    authority: Option<LocalRepositoryAuthorityFreeze>,
}

/// Recover a manager-loaded immutable preparation with already-armed caller
/// custody (or `()` before startup admits readers). Active input validation
/// runs under retained projection custody. Completed recovery never opens the
/// disposable session. A historical finalizer must not reinstall old roots.
#[allow(clippy::too_many_arguments)]
pub fn recover_prepared_session_workspace<C>(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    supplied: PreparedSessionPublication,
    custody: C,
    validate_active: impl FnOnce(&ExactProjectionFreeze, &PreparedSessionPublication) -> Result<()>,
    finalize: impl FnOnce(
        PreparedRecoveryDisposition,
        &RepositoryCommitReceipt,
        &LocalRepositoryAuthorityFreeze,
        &mut C,
    ) -> Result<()>,
) -> Result<PreparedSessionWorkspaceRecovery<C>> {
    #[cfg(any(unix, windows))]
    {
        let mut owner = RecoveryOwner {
            custody: Some(custody),
            projection: None,
            authority: None,
        };
        owner.projection = Some(open_retained_with_custody(root, &mut owner.custody)?);
        let projection = owner.projection.as_ref().expect("retained projection");
        let prepared = authority
            .load_prepared_session_publication(supplied.operation_id())
            .map_err(recovery_error)?
            .ok_or_else(|| recovery_error("required preparation is absent"))?;
        if prepared.transaction() != supplied.transaction()
            || prepared.binding() != supplied.binding()
            || prepared.expected_receipt() != supplied.expected_receipt()
        {
            return Err(recovery_error(
                "supplied handle differs from acknowledged preparation",
            ));
        }
        let active = authority
            .active_prepared_session_publication()
            .map_err(recovery_error)?;
        if let Some(active) = &active {
            if active.operation_id() != prepared.operation_id()
                || active.transaction_hash() != prepared.transaction_hash()
            {
                return Err(recovery_error("another prepared operation remains active"));
            }
        }
        let marker = ReconciliationAuthorityCommit {
            repository_id: prepared.transaction().repository_id.clone(),
            operation_id: prepared.operation_id(),
            transaction_hash: prepared.transaction_hash(),
        };
        // Authenticate all descriptors/actions before cleanup or rollback.
        let transactions = preflight_wals(&projection.projection, Some(&marker), None)?;
        if active.is_none() {
            let (receipt, authority_freeze) = authority
                .commit_prepared_session_publication(&prepared)
                .map_err(recovery_error)?;
            let mut completed = PreparedSessionWorkspaceRecovery {
                custody: owner.custody.take().expect("armed recovery owner"),
                receipt,
                authority_freeze,
                disposition: PreparedRecoveryDisposition::CompletedCurrent,
            };
            validate_original_receipt(&prepared, &completed.receipt)?;
            completed
                .authority_freeze
                .ensure_no_active_session_publication()
                .map_err(recovery_error)?;
            if completed.authority_freeze.roots() != &completed.receipt.roots_after {
                completed.disposition = PreparedRecoveryDisposition::HistoricalReceipt;
            }
            if !repository_authority_state_contains_commit(
                completed.authority_freeze.authority(),
                &marker,
            )? {
                return Err(recovery_error(
                    "completed preparation has no exact installed operation",
                ));
            }
            finalize(
                completed.disposition,
                &completed.receipt,
                &completed.authority_freeze,
                &mut completed.custody,
            )?;
            for transaction in transactions {
                projection
                    .projection
                    .cleanup_reconciliation_transaction(transaction)?;
            }
            projection.revalidate_namespace()?;
            return Ok(completed);
        }
        if prepared.recovery_locator().map_err(recovery_error)?
            != supplied.recovery_locator().map_err(recovery_error)?
        {
            return Err(recovery_error("active recovery locator differs"));
        }
        validate_active(projection, &prepared)?;
        let transaction = prepared.transaction();
        let mutation = transaction
            .workspace_mutation
            .as_ref()
            .ok_or_else(|| recovery_error("prepared transaction has no workspace"))?;
        let previous_tree = {
            let selected = authority.read_authority();
            if selected.roots() != &transaction.expected_roots {
                return Err(recovery_error(
                    "active recovery does not name current predecessor roots",
                ));
            }
            selected
                .workspace_graph_snapshot(&mutation.workspace_id)
                .map_err(recovery_error)?
                .ok_or_else(|| recovery_error("prepared predecessor workspace is absent"))?
                .resolved_tree
        };
        let target_tree = previous_tree
            .apply(&mutation.tree_deltas)
            .map_err(recovery_error)?;
        if compute_resolved_tree_hash(&target_tree).map_err(recovery_error)?
            != mutation.new_tree_hash
        {
            return Err(recovery_error("saved target tree hash differs"));
        }
        // Source reads acquire backend locks; finish before the exclusive freeze.
        let previous_owned = load_repository_projection_entries(
            authority,
            &previous_tree,
            "prepared recovery predecessor",
        )?;
        let target_owned = load_repository_projection_entries(
            authority,
            &target_tree,
            "prepared recovery target",
        )?;
        let previous_entries = validated_source_entries(
            previous_owned
                .iter()
                .map(|e| (&e.path, e.kind, e.content.as_slice())),
        )?;
        let entries = validated_source_entries(
            target_owned
                .iter()
                .map(|e| (&e.path, e.kind, e.content.as_slice())),
        )?;
        validate_repository_projection_transaction(
            &previous_tree,
            &target_tree,
            &previous_entries,
            &entries,
            transaction,
            GraphOnlyTransitionPolicy::AllowExactMetadataTransition,
        )?;
        owner.authority = Some(
            authority
                .freeze_current_authority(&transaction.expected_roots)
                .map_err(recovery_error)?,
        );
        for wal in &transactions {
            if wal.manifest.state != ReconciliationTransactionState::Pending {
                return Err(recovery_error(
                    "active preparation has a committed projection descriptor",
                ));
            }
            if repository_authority_state_contains_commit(
                owner.authority.as_ref().unwrap().authority(),
                &marker,
            )? {
                return Err(recovery_error(
                    "active preparation unexpectedly has committed authority",
                ));
            }
        }
        for wal in &transactions {
            projection
                .projection
                .rollback_reconciliation_manifest(wal)?;
        }
        // Keep the old WAL until the engine proves that rollback restored an
        // exact predecessor and safe target namespace. An authenticated prefix
        // alone cannot attest that no final action record was lost.
        projection.revalidate_namespace()?;
        // Keep projection/caller custody; release only this backend freeze
        // before the manager must acquire its own exact prepared commit lock.
        drop(owner.authority.take());
        let custody = owner.custody.take().expect("armed recovery owner");
        let saved_receipt = prepared.expected_receipt().clone();
        struct Acknowledged<C> {
            custody: C,
            handle: PreparedSessionPublication,
        }
        project_reconciled_source_tree_and_publish(
            root,
            &previous_entries,
            &entries,
            &should_preserve_checkout_path,
            ReconciledProjectionOptions {
                open_mode: ProjectionOpenMode::ExistingRetained(projection),
                graph_only_transition: Some(GraphOnlyWorkspaceTransition {
                    previous_tree: &previous_tree,
                    target_tree: &target_tree,
                    scope: None,
                }),
                ..ReconciledProjectionOptions::default()
            },
            || {},
            || {},
            || {},
            Some(marker),
            None,
            || {
                // This boundary follows the engine's complete exact source
                // and namespace preflight, under the same projection freeze.
                for wal in transactions {
                    projection
                        .projection
                        .cleanup_reconciliation_transaction(wal)?;
                }
                Ok(Acknowledged {
                    custody,
                    handle: prepared,
                })
            },
            |ack| match authority
                .commit_prepared_session_publication(&ack.handle)
                .or_else(|_| authority.commit_prepared_session_publication(&ack.handle))
            {
                Ok((receipt, authority_freeze)) => {
                    ProjectionAuthorityCommit::Committed(PreparedSessionWorkspaceRecovery {
                        custody: ack.custody,
                        receipt,
                        authority_freeze,
                        disposition: PreparedRecoveryDisposition::ActivePublished,
                    })
                }
                Err(error) => {
                    drop(ack);
                    ProjectionAuthorityCommit::Indeterminate(recovery_error(error))
                }
            },
            |committed| {
                let mut expected = saved_receipt;
                expected.outcome = committed.receipt.outcome.clone();
                if committed.receipt != expected
                    || committed.authority_freeze.roots() != &committed.receipt.roots_after
                {
                    return Err(recovery_error(
                        "active recovery moved beyond its saved target",
                    ));
                }
                finalize(
                    committed.disposition,
                    &committed.receipt,
                    &committed.authority_freeze,
                    &mut committed.custody,
                )
            },
        )
        .map(|(_, committed)| committed)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (
            root,
            authority,
            supplied,
            custody,
            validate_active,
            finalize,
        );
        Err(unsupported_safe_projection_error())
    }
}

/// Resolve ordinary/committed authenticated WAL before hydration, without a
/// disposable session. Active preparation must use the exact prepared path.
/// The no-active fact is checked under the held local authority record lock.
pub fn recover_repository_projection_before_hydration(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
) -> Result<()> {
    recover_repository_projection_before_hydration_with_session_finalizer(
        root,
        authority,
        |_, _| Ok(()),
    )
}

/// Finalize exact completed session bookkeeping before its authenticated WAL
/// is removed. The callback runs under retained projection and current local
/// authority custody, and must be idempotent: refusal retains every WAL for
/// retry. Ordinary WAL and preparations without a WAL invoke no callback.
///
/// A saved preparation may name a historical receipt. The supplied freeze is
/// current authority; callers must not reinstall the preparation's old roots.
/// The callback must not reopen the manager/backend while that freeze is held.
pub fn recover_repository_projection_before_hydration_with_session_finalizer(
    root: &Path,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    mut finalize_session: impl FnMut(
        &PreparedSessionPublication,
        &LocalRepositoryAuthorityFreeze,
    ) -> Result<()>,
) -> Result<()> {
    #[cfg(any(unix, windows))]
    {
        let projection = open_retained(root)?;
        let (roots, transactions) = {
            let selected = authority.read_authority();
            (
                selected.roots().clone(),
                preflight_wals(&projection.projection, None, Some(&selected))?,
            )
        };
        // The manager loader acquires its publication/backend locks. Finish
        // every required record read before taking the exclusive freeze.
        let mut preparations = Vec::new();
        let mut loaded = HashSet::new();
        for wal in &transactions {
            let Some(marker) = &wal.manifest.authority_commit else {
                continue;
            };
            if let Some(prepared) = authority
                .load_prepared_session_publication(marker.operation_id)
                .map_err(recovery_error)?
            {
                if prepared.operation_id() != marker.operation_id
                    || prepared.transaction_hash() != marker.transaction_hash
                    || prepared.transaction().repository_id != marker.repository_id
                    || wal.manifest.checkout_projection_commit.is_some()
                {
                    return Err(recovery_error(
                        "completed WAL marker differs from exact saved preparation",
                    ));
                }
                if loaded.insert(marker.operation_id) {
                    preparations.push(prepared);
                }
            }
        }
        let frozen = authority
            .freeze_current_authority(&roots)
            .map_err(recovery_error)?;
        frozen
            .ensure_no_active_session_publication()
            .map_err(recovery_error)?;
        for prepared in &preparations {
            let marker = ReconciliationAuthorityCommit {
                repository_id: prepared.transaction().repository_id.clone(),
                operation_id: prepared.operation_id(),
                transaction_hash: prepared.transaction_hash(),
            };
            if !repository_authority_state_contains_commit(frozen.authority(), &marker)? {
                return Err(recovery_error(
                    "saved preparation has no exact completed operation under current freeze",
                ));
            }
        }
        let decisions = transactions
            .iter()
            .map(|wal| {
                let committed = match &wal.manifest.authority_commit {
                    Some(marker) => {
                        repository_authority_state_contains_commit(frozen.authority(), marker)?
                    }
                    None => false,
                };
                let checkout = match &wal.manifest.checkout_projection_commit {
                    Some(marker) => projection
                        .projection
                        .checkout_projection_commit_is_installed_with_authority(
                            marker,
                            Some(frozen.authority()),
                        )?,
                    None => false,
                };
                Ok(committed
                    || checkout
                    || wal.manifest.state == ReconciliationTransactionState::Committed)
            })
            .collect::<Result<Vec<_>>>()?;
        // Validate all dispositions before any callback or namespace change.
        // Finish all bookkeeping before cleaning any evidence, so a later
        // callback refusal leaves earlier completed sessions retryable too.
        for prepared in &preparations {
            finalize_session(prepared, &frozen)?;
        }
        for (wal, committed) in transactions.into_iter().zip(decisions) {
            if !committed {
                projection
                    .projection
                    .rollback_reconciliation_manifest(&wal)?;
            }
            projection
                .projection
                .cleanup_reconciliation_transaction(wal)?;
        }
        projection.revalidate_namespace()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, authority, finalize_session);
        Err(unsupported_safe_projection_error())
    }
}

fn validate_original_receipt(
    prepared: &PreparedSessionPublication,
    receipt: &RepositoryCommitReceipt,
) -> Result<()> {
    let mut expected = prepared.expected_receipt().clone();
    expected.outcome = RepositoryCommitOutcome::IdempotentReplay;
    if receipt != &expected {
        return Err(recovery_error(
            "recovery did not return the original exact receipt",
        ));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn open_retained(root: &Path) -> Result<ExactProjectionFreeze> {
    open_retained_with_custody(root, &mut None::<()>)
}

#[cfg(any(unix, windows))]
fn open_retained_with_custody<C>(
    root: &Path,
    custody: &mut Option<C>,
) -> Result<ExactProjectionFreeze> {
    let projection = ProjectionRoot::open_existing_with_custody(
        root,
        PROJECTION_LOCK_WAIT_DEADLINE,
        ExistingReconciliationDisposition::RetainPrepared,
        custody,
    )?;
    let acquired = ProjectionAcquisition::new(custody, projection);
    let root_identity = tracked_open_directory_identity(&acquired.held().root)
        .map_err(|e| KinError::io(root, e))?;
    let freeze = ExactProjectionFreeze {
        projection: acquired.release(),
        root_identity,
    };
    let acquired = ProjectionAcquisition::new(custody, freeze);
    acquired.held().revalidate_namespace()?;
    Ok(acquired.release())
}

#[cfg(any(unix, windows))]
fn preflight_wals(
    projection: &ProjectionRoot,
    expected: Option<&ReconciliationAuthorityCommit>,
    authority: Option<&RepositoryAuthorityState>,
) -> Result<Vec<ReconciliationTransaction>> {
    projection.revalidate_projection_lock()?;
    let root_identity =
        tracked_open_directory_identity(&projection.root).map_err(recovery_error)?;
    let mut names = projection
        .control
        .entries()
        .map_err(recovery_error)?
        .map(|entry| entry.map(|e| e.file_name()).map_err(recovery_error))
        .collect::<Result<Vec<_>>>()?;
    names.retain(|name| name.to_str().is_some_and(|text| text.starts_with("tx-")));
    names.sort();
    if expected.is_some() && names.len() > 1 {
        return Err(recovery_error(
            "multiple WALs cannot name one prepared attempt",
        ));
    }
    let mut transactions = Vec::new();
    for name in names {
        let directory = open_directory_nofollow_for_removal(&projection.control, &name)
            .map_err(recovery_error)?;
        let identity = tracked_open_directory_identity(&directory).map_err(recovery_error)?;
        let manifest = projection
            .load_reconciliation_manifest(&name, &directory)?
            .ok_or_else(|| {
                recovery_error("missing projection descriptor; retain incomplete WAL for diagnosis")
            })?;
        if !matches!(
            manifest.schema,
            RECONCILIATION_MANIFEST_SCHEMA | LEGACY_RECONCILIATION_MANIFEST_SCHEMA
        ) || name != std::ffi::OsStr::new(&format!("tx-{}", manifest.transaction_id))
            || manifest.root_identity != root_identity
            || manifest.kin_control_identity != projection.kin_control_identity
            || manifest.control_identity != projection.control_identity
            || manifest.transaction_identity != identity
            || !manifest.actions.is_empty()
        {
            return Err(recovery_error(
                "WAL descriptor does not name this exact projection",
            ));
        }
        if let Some(expected) = expected {
            if manifest.authority_commit.as_ref() != Some(expected)
                || manifest.checkout_projection_commit.is_some()
            {
                return Err(recovery_error(
                    "WAL operation/hash differs from required preparation",
                ));
            }
        }
        if manifest.schema == LEGACY_RECONCILIATION_MANIFEST_SCHEMA && expected.is_none() {
            let repository_committed = match (&manifest.authority_commit, authority) {
                (Some(marker), Some(authority)) => {
                    repository_authority_state_contains_commit(authority, marker)?
                }
                _ => false,
            };
            let checkout_committed = match &manifest.checkout_projection_commit {
                Some(marker) => projection
                    .checkout_projection_commit_is_installed_with_authority(marker, authority)?,
                None => false,
            };
            if !(repository_committed
                || checkout_committed
                || (manifest.state == ReconciliationTransactionState::Committed
                    && manifest.authority_commit.is_none()
                    && manifest.checkout_projection_commit.is_none()))
            {
                return Err(recovery_error("legacy pending reconciliation WAL has no complete action watermark; retain evidence for exact recovery"));
            }
        }
        let (actions, action_log_bytes, action_tail_authentication) =
            projection.load_reconciliation_actions(&name, &directory, &manifest)?;
        let mut manifest = manifest;
        manifest.actions = actions;
        transactions.push(ReconciliationTransaction {
            name,
            directory,
            identity,
            manifest,
            action_log_bytes,
            action_tail_authentication,
            action_recording_failed: false,
        });
    }
    Ok(transactions)
}

fn recovery_error(error: impl std::fmt::Display) -> KinError {
    KinError::Other(format!("prepared projection recovery: {error}"))
}
