// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Owed derivation work, held in repository authority.
//!
//! A standalone tree publication moves a workspace's exact bytes into
//! authority without their semantics. Nothing durable then holds a derivation
//! of those bytes, so a daemon that stops before a commit leaves the next one
//! serving the spans the previous bytes produced. The ledger records that such
//! a derivation is owed, and for which exact body.
//!
//! It is receiver-local derived bookkeeping, like binding history: it folds
//! into no root, and no transaction, change, transfer or hosted snapshot
//! carries it. What makes it authority rather than a sidecar is where it is
//! written. Every write happens inside the one compare-and-swap that commits
//! the tree it describes, so a record is durable exactly when its tree is, a
//! refused publication records nothing, and a record leaves the ledger only
//! through a transaction that pays or overtakes it from its exact predecessor.
//! Nothing here matches a record by its bytes alone.
//!
//! Every generation here is a logical authority generation,
//! `RootBundle::generation`. A storage backend's cursor never reaches this
//! module.

use std::collections::{BTreeMap, BTreeSet};

use kin_model::{
    Hash256, OperationId, RepoPath, RepositoryTransaction, TreeDelta, TreeEntry, WorkspaceId,
    WorkspaceState,
};
use serde::{Deserialize, Serialize};

use super::repository::PersistedRepositoryAuthority;
use crate::error::KinDbError;

/// Why a derivation is owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwedDerivationCause {
    /// A standalone publication moved these bytes into the workspace tree
    /// without their semantics.
    Publication,
    /// A record a daemon from an earlier build kept beside the store, carried
    /// into authority by this build's first daemon start that found it still
    /// owed.
    Legacy,
}

/// One exact body a workspace tree names that no durable derivation holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwedDerivation {
    workspace_id: WorkspaceId,
    path: RepoPath,
    body: Hash256,
    /// The logical generation of the transaction that recorded it.
    recorded_at: u64,
    cause: OwedDerivationCause,
}

impl OwedDerivation {
    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn path(&self) -> &RepoPath {
        &self.path
    }

    pub fn body(&self) -> Hash256 {
        self.body
    }

    /// The logical generation of the transaction that recorded this record.
    pub fn recorded_at(&self) -> u64 {
        self.recorded_at
    }

    pub fn cause(&self) -> OwedDerivationCause {
        self.cause
    }

    fn key(&self) -> (WorkspaceId, &RepoPath) {
        (self.workspace_id, &self.path)
    }
}

/// The re-derivation that last paid one workspace's owed work.
///
/// Its commit was a compare-and-swap on the generation it pays through, so
/// "recorded at or below `paid_through`" means exactly "present when that
/// commit landed", and every record of the workspace carries a later
/// generation than the payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationPayment {
    workspace_id: WorkspaceId,
    /// The logical generation of the predecessor the paying commit was
    /// compared and swapped against.
    paid_through: u64,
    operation_id: OperationId,
    /// The replay semantics version the paying derivation ran under.
    hydration_version: u32,
}

impl DerivationPayment {
    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn paid_through(&self) -> u64 {
        self.paid_through
    }

    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub fn hydration_version(&self) -> u32 {
        self.hydration_version
    }
}

/// Owed derivation work, and the re-derivations that paid it, per workspace.
///
/// Empty on every store that owes nothing and was never re-derived, and an
/// empty ledger is not serialized at all, so such a store keeps the exact
/// bytes and the exact snapshot and frame versions it had before the ledger
/// existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwedDerivationLedger {
    /// At most one record per workspace and path, in that order.
    records: Vec<OwedDerivation>,
    /// At most one payment per workspace, in workspace order.
    payments: Vec<DerivationPayment>,
}

impl OwedDerivationLedger {
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.payments.is_empty()
    }

    pub fn records(&self) -> &[OwedDerivation] {
        &self.records
    }

    pub fn payments(&self) -> &[DerivationPayment] {
        &self.payments
    }

    /// Every record one workspace owes, in path order.
    pub fn records_for(
        &self,
        workspace_id: WorkspaceId,
    ) -> impl Iterator<Item = &OwedDerivation> + '_ {
        self.records
            .iter()
            .filter(move |record| record.workspace_id == workspace_id)
    }

    /// The re-derivation that last paid one workspace, if any did.
    pub fn payment_for(&self, workspace_id: WorkspaceId) -> Option<&DerivationPayment> {
        self.payments
            .iter()
            .find(|payment| payment.workspace_id == workspace_id)
    }

    fn sort(&mut self) {
        self.records
            .sort_by(|left, right| left.key().cmp(&right.key()));
        self.payments.sort_by_key(|payment| payment.workspace_id);
    }
}

/// What one commit does to one workspace's owed derivation work, beside
/// dropping the records its successor tree no longer names, which every
/// commit does.
///
/// A trusted side input, shaped like the binding-history verifier: compiled
/// code hands it to one commit, it is never a transaction field, so no request,
/// transfer or replica can supply one, and storage checks it against the exact
/// successor it commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedDerivationUpdate {
    workspace_id: WorkspaceId,
    effect: OwedDerivationEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OwedDerivationEffect {
    /// Record bodies owed a derivation. `published` are bodies this commit's
    /// own workspace mutation wrote, each replacing its path's record.
    /// `legacy` are obligations an earlier build recorded outside authority;
    /// each is recorded only while the successor tree names it and no record
    /// holds its path.
    Owe {
        published: Vec<(RepoPath, Hash256)>,
        legacy: Vec<(RepoPath, Hash256)>,
    },
    /// This commit carries the workspace's derivation to durable history, so
    /// every record of the workspace is paid.
    Pay,
    /// This commit re-derives the workspace's served state from exact bytes:
    /// every record of the workspace is paid, and the payment is recorded
    /// against the exact predecessor the commit was compared and swapped
    /// against.
    PayRederived { hydration_version: u32 },
}

impl OwedDerivationUpdate {
    /// Record `published` as owed by `workspace_id` at the successor's
    /// generation, and carry each `legacy` obligation the successor still owes.
    pub fn owe(
        workspace_id: WorkspaceId,
        published: Vec<(RepoPath, Hash256)>,
        legacy: Vec<(RepoPath, Hash256)>,
    ) -> Self {
        Self {
            workspace_id,
            effect: OwedDerivationEffect::Owe { published, legacy },
        }
    }

    /// Pay every record `workspace_id` owes, because this commit carries the
    /// workspace's derivation into history.
    pub fn pay(workspace_id: WorkspaceId) -> Self {
        Self {
            workspace_id,
            effect: OwedDerivationEffect::Pay,
        }
    }

    /// The payment a re-derivation commit makes. Crate-private: the one path
    /// that re-derives a workspace from exact bytes constructs it, after its
    /// verifier proved the re-derivation it pays for.
    pub(crate) fn pay_rederived(payment: RederivationPayment) -> Self {
        Self {
            workspace_id: payment.workspace_id,
            effect: OwedDerivationEffect::PayRederived {
                hydration_version: payment.hydration_version,
            },
        }
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
}

/// What a re-derivation commit pays: the workspace it re-derives, and the
/// replay semantics version its derivation runs under.
///
/// The commit records the payment only when its own transaction moves that
/// workspace and its verifier proves the workspace's committed graph is the
/// complete derivation of its tree. Otherwise it pays nothing and every record
/// stays owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RederivationPayment {
    pub workspace_id: WorkspaceId,
    pub hydration_version: u32,
}

fn invalid(reason: impl std::fmt::Display) -> KinDbError {
    KinDbError::StorageError(format!("owed derivation ledger: {reason}"))
}

fn workspace_in(
    workspaces: &[WorkspaceState],
    workspace_id: WorkspaceId,
) -> Option<&WorkspaceState> {
    workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
}

/// Whether `workspace`'s exact tree holds `body` at `path` as a file.
fn names_body(workspace: &WorkspaceState, path: &RepoPath, body: Hash256) -> bool {
    workspace.tree.artifact_at_path(path).is_some_and(
        |artifact| matches!(artifact.entry, TreeEntry::Blob { hash, .. } if hash == body),
    )
}

/// Refuse a ledger out of canonical order, one naming a workspace the envelope
/// does not hold or a body its workspace tree does not name, and one whose
/// generations break `paid_through < recorded_at <= generation`. A payment
/// must also name the operation that made it: one committed from the
/// generation it pays through that moved the workspace it pays.
///
/// Run on every full open, on the envelope-only read, and on every commit, so
/// a ledger any reader is handed always describes the exact trees beside it.
pub(crate) fn validate_metadata(metadata: &PersistedRepositoryAuthority) -> Result<(), KinDbError> {
    let ledger = &metadata.owed_derivations;
    let generation = metadata.roots.generation;
    let mut previous_payment: Option<WorkspaceId> = None;
    for payment in &ledger.payments {
        if previous_payment.is_some_and(|previous| previous >= payment.workspace_id) {
            return Err(invalid(
                "payments must be unique per workspace and in workspace order",
            ));
        }
        previous_payment = Some(payment.workspace_id);
        if workspace_in(&metadata.workspaces, payment.workspace_id).is_none() {
            return Err(invalid(format!(
                "a payment names workspace {}, which this repository does not hold",
                payment.workspace_id
            )));
        }
        if payment.paid_through >= generation {
            return Err(invalid(format!(
                "a payment through generation {} is not before generation {generation}, which \
                 holds it",
                payment.paid_through
            )));
        }
        let paying = metadata
            .operation_log
            .iter()
            .rev()
            .find(|operation| operation.operation_id == payment.operation_id)
            .ok_or_else(|| {
                invalid(format!(
                    "a payment names operation {}, which the log does not hold",
                    payment.operation_id
                ))
            })?;
        if paying.roots_before.generation != payment.paid_through {
            return Err(invalid(format!(
                "operation {} committed from generation {}, not the generation {} its payment \
                 names",
                payment.operation_id, paying.roots_before.generation, payment.paid_through
            )));
        }
        // A payment is the paying derivation's claim about one workspace, so
        // the operation it names must be one that moved that workspace. An
        // operation of another workspace, however real, pays nothing here.
        if paying
            .workspace_mutation
            .as_ref()
            .map(|mutation| mutation.workspace_id)
            != Some(payment.workspace_id)
        {
            return Err(invalid(format!(
                "operation {} did not move workspace {}, which its payment names",
                payment.operation_id, payment.workspace_id
            )));
        }
    }
    let mut previous: Option<(WorkspaceId, &RepoPath)> = None;
    for record in &ledger.records {
        let key = record.key();
        if previous.is_some_and(|previous| previous >= key) {
            return Err(invalid(
                "records must be unique per workspace and path, in that order",
            ));
        }
        previous = Some(key);
        let Some(workspace) = workspace_in(&metadata.workspaces, record.workspace_id) else {
            return Err(invalid(format!(
                "a record names workspace {}, which this repository does not hold",
                record.workspace_id
            )));
        };
        if !names_body(workspace, &record.path, record.body) {
            return Err(invalid(format!(
                "a record owes {} at body {}, which workspace {} does not name there",
                record.path, record.body, record.workspace_id
            )));
        }
        if record.recorded_at > generation {
            return Err(invalid(format!(
                "a record for {} was recorded at generation {}, after generation {generation}, \
                 which holds it",
                record.path, record.recorded_at
            )));
        }
        if let Some(payment) = ledger.payment_for(record.workspace_id) {
            if record.recorded_at <= payment.paid_through {
                return Err(invalid(format!(
                    "a record for {} at generation {} is at or below the payment through \
                     generation {}",
                    record.path, record.recorded_at, payment.paid_through
                )));
            }
        }
    }
    Ok(())
}

/// Drop every record whose workspace the successor no longer holds or whose
/// exact path and body its workspace tree no longer names, and every payment
/// of a workspace the successor no longer holds.
///
/// Every transaction runs this over the successor it prepares. Checkout,
/// rollback, stash, merge, transfer and any other workspace transition
/// therefore overtake a record the moment they move its workspace off that
/// body, and a record never outlives the bytes it owes a derivation for.
pub(crate) fn retain_named(metadata: &mut PersistedRepositoryAuthority) {
    let workspaces = &metadata.workspaces;
    let ledger = &mut metadata.owed_derivations;
    ledger.records.retain(|record| {
        workspace_in(workspaces, record.workspace_id)
            .is_some_and(|workspace| names_body(workspace, &record.path, record.body))
    });
    ledger
        .payments
        .retain(|payment| workspace_in(workspaces, payment.workspace_id).is_some());
}

/// Apply one commit's trusted update to the successor envelope it prepared.
///
/// `metadata` is the successor, already holding its roots and its appended
/// operation, and `predecessor_generation` is the logical generation its
/// compare-and-swap was taken against. Records are stamped with the
/// successor's own generation.
pub(crate) fn apply_update(
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
    update: &OwedDerivationUpdate,
    predecessor_generation: u64,
) -> Result<(), KinDbError> {
    let generation = metadata.roots.generation;
    let workspace_id = update.workspace_id;
    let Some(workspace) = workspace_in(&metadata.workspaces, workspace_id) else {
        return Err(invalid(format!(
            "the update names workspace {workspace_id}, which the successor does not hold"
        )));
    };
    let own_mutation = transaction
        .workspace_mutation
        .as_ref()
        .filter(|mutation| mutation.workspace_id == workspace_id);
    let ledger = &mut metadata.owed_derivations;
    match &update.effect {
        OwedDerivationEffect::Owe { published, legacy } => {
            let mutation = own_mutation.ok_or_else(|| {
                invalid(format!(
                    "owed derivations for workspace {workspace_id} ride only that workspace's \
                     own mutation"
                ))
            })?;
            // Keyed once, because one publication can move every file of a
            // large checkout and each owed body is checked against it.
            let written: BTreeMap<&RepoPath, Hash256> = mutation
                .tree_deltas
                .iter()
                .filter_map(TreeDelta::new_state)
                .filter_map(|new| match new.entry {
                    TreeEntry::Blob { hash, .. } => Some((&new.path, hash)),
                    _ => None,
                })
                .collect();
            let mut fresh: BTreeMap<RepoPath, OwedDerivation> = BTreeMap::new();
            for (path, body) in published {
                if written.get(path) != Some(body) || !names_body(workspace, path, *body) {
                    return Err(invalid(format!(
                        "{path} at body {body} is not a body this transaction published"
                    )));
                }
                fresh.insert(
                    path.clone(),
                    OwedDerivation {
                        workspace_id,
                        path: path.clone(),
                        body: *body,
                        recorded_at: generation,
                        cause: OwedDerivationCause::Publication,
                    },
                );
            }
            let held: BTreeSet<RepoPath> = ledger
                .records_for(workspace_id)
                .map(|record| record.path.clone())
                .collect();
            for (path, body) in legacy {
                if fresh.contains_key(path)
                    || held.contains(path)
                    || !names_body(workspace, path, *body)
                {
                    continue;
                }
                fresh.insert(
                    path.clone(),
                    OwedDerivation {
                        workspace_id,
                        path: path.clone(),
                        body: *body,
                        recorded_at: generation,
                        cause: OwedDerivationCause::Legacy,
                    },
                );
            }
            ledger.records.retain(|record| {
                record.workspace_id != workspace_id || !fresh.contains_key(&record.path)
            });
            ledger.records.extend(fresh.into_values());
        }
        OwedDerivationEffect::Pay => {
            if own_mutation.is_none() {
                return Err(invalid(format!(
                    "a commit pays workspace {workspace_id}'s owed derivations only when it \
                     carries that workspace's own mutation"
                )));
            }
            ledger
                .records
                .retain(|record| record.workspace_id != workspace_id);
        }
        OwedDerivationEffect::PayRederived { hydration_version } => {
            // A payment names the operation that made it, and that operation
            // must move the workspace it pays. A re-derivation that leaves the
            // workspace as it was served re-derived nothing the workspace
            // owes, so it pays nothing and records nothing.
            if own_mutation.is_none() {
                return Ok(());
            }
            ledger
                .records
                .retain(|record| record.workspace_id != workspace_id);
            ledger
                .payments
                .retain(|payment| payment.workspace_id != workspace_id);
            ledger.payments.push(DerivationPayment {
                workspace_id,
                paid_through: predecessor_generation,
                operation_id: transaction.operation_id,
                hydration_version: *hydration_version,
            });
        }
    }
    ledger.sort();
    Ok(())
}
