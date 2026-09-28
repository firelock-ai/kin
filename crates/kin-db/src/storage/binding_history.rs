// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Checked binding history is derived evidence over an exact authority view.
//! It is not a creation stamp, and absence is never a measured zero.

use kin_model::{Hash256, OperationId, WorkspaceSnapshotBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    format::GraphSnapshot,
    repository::{PersistedRepositoryAuthority, RepositoryAuthorityState},
};
use crate::error::KinDbError;

pub const BINDING_HISTORY_PROTOCOL: u32 = 1;
pub const BINDING_HISTORY_AUTHORITY_SCHEMA: u32 = 5;

/// A trusted, compiled semantic verifier. This is deliberately not a wire
/// input or a `RepositoryTransaction` field. Storage supplies both immutable
/// states while holding its publication lock and constructs all proof bytes.
pub trait BindingHistoryVerifier {
    fn verify_graph_transition(
        &self,
        _before: &GraphSnapshot,
        _after: &GraphSnapshot,
        _load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    ) -> Result<bool, KinDbError> {
        Ok(false)
    }

    fn verify_transition(
        &self,
        transition: BindingHistoryTransition<'_>,
    ) -> Result<BindingHistoryDecision, KinDbError>;
}

pub enum BindingHistoryDecision {
    Unknown,
    Qualified {
        protocol: u32,
        workspaces: Vec<kin_model::WorkspaceId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingHistoryEligibility {
    NewNativeGenesis,
    NewHistoryGenesis,
    CheckedPredecessor,
    /// The transition re-derived the selected graph from exact bytes, so a
    /// lineage may start at it whatever preceded it. Only
    /// [`super::repository::RepositoryAuthorityManager::commit_rederived_repository_transaction`]
    /// makes a transition eligible this way, and the [`RederivationVerifier`]
    /// it is handed still has to re-derive the committed graph before anything
    /// is qualified.
    Rederivation,
}

/// A trusted, compiled verifier that re-derives one committed workspace graph
/// from exact bytes. The only kind of verifier a re-derivation commit accepts.
///
/// Deliberately a separate trait from [`BindingHistoryVerifier`]. A lineage
/// that starts part way through the operation log proves nothing about the
/// operations before it, so its first step must establish the whole selected
/// graph. A transition verifier checks what one operation changed, over state
/// some earlier operation left, and over a store no build ever checked that
/// state is exactly what is unproven. Keeping the two apart means no
/// transition verifier can be handed to
/// [`super::repository::RepositoryAuthorityManager::commit_rederived_repository_transaction`].
pub trait RederivationVerifier {
    /// Whether `after`, the graph the committed successor selects for one
    /// workspace, is exactly this build's complete derivation of its own tree
    /// from the bytes `load_body` returns, owing no local binding debt.
    ///
    /// `Ok(false)` leaves the workspace unproven. An error aborts the commit,
    /// so it is for a failure to look, never for a graph that did not match.
    fn verify_rederived_graph(
        &self,
        after: &GraphSnapshot,
        load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    ) -> Result<bool, KinDbError>;
}

/// The transition protocol over a [`RederivationVerifier`]: it offers the
/// verifier each workspace the transition makes eligible as a re-derivation,
/// with the graph the committed successor selects for it, and qualifies
/// exactly the workspaces the verifier accepts.
pub(super) struct RederivationTransitionVerifier<'a>(pub(super) &'a dyn RederivationVerifier);

impl BindingHistoryVerifier for RederivationTransitionVerifier<'_> {
    fn verify_transition(
        &self,
        transition: BindingHistoryTransition<'_>,
    ) -> Result<BindingHistoryDecision, KinDbError> {
        let mut workspaces = Vec::new();
        for workspace in &transition.successor().metadata().workspaces {
            if transition.eligibility(workspace.workspace_id)
                != Some(BindingHistoryEligibility::Rederivation)
            {
                continue;
            }
            let Some(after) = transition
                .successor()
                .workspace_graph_snapshot(&workspace.workspace_id)?
            else {
                continue;
            };
            let load_body = |digest| transition.load_source_blob(digest);
            if self.0.verify_rederived_graph(&after, &load_body)? {
                workspaces.push(workspace.workspace_id);
            }
        }
        Ok(BindingHistoryDecision::Qualified {
            protocol: BINDING_HISTORY_PROTOCOL,
            workspaces,
        })
    }
}

#[derive(Clone, Copy)]
pub struct BindingHistoryTransition<'a> {
    pub(super) predecessor: &'a RepositoryAuthorityState,
    pub(super) successor: &'a RepositoryAuthorityState,
    pub(super) transaction: &'a kin_model::RepositoryTransaction,
    pub(super) observed: Option<(kin_model::WorkspaceId, &'a GraphSnapshot)>,
    pub(super) load_body: &'a dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    /// Set only by the re-derivation publication path. Never a transaction
    /// field, so no request can ask for it.
    pub(super) rederivation: bool,
}

impl BindingHistoryTransition<'_> {
    pub fn predecessor(&self) -> &RepositoryAuthorityState {
        self.predecessor
    }
    pub fn successor(&self) -> &RepositoryAuthorityState {
        self.successor
    }
    pub fn observed_predecessor(
        &self,
        workspace: kin_model::WorkspaceId,
    ) -> Option<&GraphSnapshot> {
        self.observed
            .filter(|(id, _)| *id == workspace)
            .map(|(_, graph)| graph)
    }
    pub fn transaction(&self) -> &kin_model::RepositoryTransaction {
        self.transaction
    }
    pub fn load_source_blob(&self, digest: Hash256) -> Result<Option<Vec<u8>>, KinDbError> {
        (self.load_body)(digest)
    }
    pub fn eligibility(
        &self,
        workspace: kin_model::WorkspaceId,
    ) -> Option<BindingHistoryEligibility> {
        if self.successor.metadata().schema_version < BINDING_HISTORY_AUTHORITY_SCHEMA {
            return None;
        }
        if self.rederivation {
            // A lineage restarts only where the successor holds the workspace
            // it would qualify; the verifier proves the rest.
            return self
                .successor
                .metadata()
                .workspaces
                .iter()
                .any(|item| item.workspace_id == workspace)
                .then_some(BindingHistoryEligibility::Rederivation);
        }
        if self.predecessor.binding_history_genesis {
            return Some(
                if self.successor.metadata().git_external_authority.is_some()
                    || !self.transaction.external_objects.is_empty()
                    || self.successor.snapshot().changes.len() > 1
                    || self.successor.snapshot().changes.len() != self.transaction.changes.len()
                    || self
                        .transaction
                        .changes
                        .iter()
                        .any(|change| !matches!(change.origin, kin_model::ChangeOrigin::Native))
                {
                    BindingHistoryEligibility::NewHistoryGenesis
                } else {
                    BindingHistoryEligibility::NewNativeGenesis
                },
            );
        }
        self.predecessor
            .metadata()
            .binding_history
            .iter()
            .any(|proof| proof.scope.workspace_id == workspace)
            .then_some(BindingHistoryEligibility::CheckedPredecessor)
    }
}

/// Whether `metadata` holds a witness in which `operation`, as a
/// re-derivation, proved `workspace`'s selected graph from exact bytes.
pub(super) fn rederived_by(
    metadata: &PersistedRepositoryAuthority,
    workspace: kin_model::WorkspaceId,
    operation: kin_model::OperationId,
) -> bool {
    metadata.binding_history.iter().any(|witness| {
        witness.scope.workspace_id == workspace
            && witness.proof.last().is_some_and(|step| {
                step.operation_id == operation
                    && step.qualification == BindingHistoryQualification::CheckedRederivation
            })
    })
}

pub(super) fn checked_witnesses(
    transition: BindingHistoryTransition<'_>,
    verifier: &dyn BindingHistoryVerifier,
) -> Result<Vec<BindingHistoryWitness>, KinDbError> {
    let BindingHistoryDecision::Qualified {
        protocol,
        mut workspaces,
    } = verifier.verify_transition(transition)?
    else {
        return Ok(Vec::new());
    };
    if protocol != BINDING_HISTORY_PROTOCOL {
        return Err(invalid("verifier protocol is unsupported"));
    }
    workspaces.sort();
    if workspaces.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("verifier returned duplicate workspaces"));
    }
    let mut result = Vec::with_capacity(workspaces.len());
    for workspace in workspaces {
        let eligibility = transition.eligibility(workspace).ok_or_else(|| {
            invalid("unknown predecessor cannot be qualified by a later transition")
        })?;
        if let Some(observed) = transition.observed_predecessor(workspace) {
            let Some(authority) = transition
                .predecessor
                .workspace_graph_snapshot(&workspace)?
            else {
                return Err(invalid("observed workspace predecessor is absent"));
            };
            if !is_checked_derivation_of(&authority, observed)? {
                continue;
            }
        }
        let metadata = transition.successor.metadata();
        let selected = transition
            .successor
            .workspace_graph_snapshot(&workspace)?
            .ok_or_else(|| invalid("qualified workspace is absent"))?;
        let scope = metadata
            .workspaces
            .iter()
            .find(|item| item.workspace_id == workspace)
            .ok_or_else(|| invalid("qualified workspace is absent"))?
            .snapshot_binding(metadata.roots.clone())?;
        let graph_digest = graph_digest(&selected)?;
        // A re-derivation starts its own lineage: the selected graph was derived
        // again from exact bytes, so nothing an earlier proof covered, and
        // nothing an earlier unproven operation did, is carried into it.
        let old = (eligibility != BindingHistoryEligibility::Rederivation)
            .then(|| {
                transition
                    .predecessor
                    .metadata()
                    .binding_history
                    .iter()
                    .find(|proof| proof.scope.workspace_id == workspace)
            })
            .flatten();
        let mut proof = old.map_or_else(Vec::new, |old| old.proof.clone());
        let prior = old.map_or(Hash256::from_bytes([0; 32]), |old| old.lineage_digest);
        let operation = metadata
            .operation_log
            .last()
            .ok_or_else(|| invalid("qualified transition has no committed operation"))?;
        if operation.operation_id != transition.transaction.operation_id
            || operation.roots_before != *transition.predecessor.roots()
            || operation.roots_after != *transition.successor.roots()
        {
            return Err(invalid(
                "qualified transition differs from the DB-held operation",
            ));
        }
        let step = BindingHistoryStep {
            operation_id: operation.operation_id,
            operation_identity: operation.identity_hash()?,
            qualification: match eligibility {
                BindingHistoryEligibility::NewNativeGenesis => {
                    BindingHistoryQualification::NewNativeGenesis
                }
                BindingHistoryEligibility::NewHistoryGenesis => {
                    BindingHistoryQualification::CheckedHistoryGenesis
                }
                BindingHistoryEligibility::CheckedPredecessor => {
                    BindingHistoryQualification::CheckedTransition
                }
                BindingHistoryEligibility::Rederivation => {
                    BindingHistoryQualification::CheckedRederivation
                }
            },
            observed_graph_digest: transition
                .observed_predecessor(workspace)
                .map(self::graph_digest)
                .transpose()?,
            selected_binding: selected_binding(&scope)?,
            graph_digest,
        };
        let lineage_digest = canonical_digest(
            b"kin.binding-history.checked-operation.v1\0",
            &(
                prior,
                &step,
                &operation.roots_before,
                &operation.roots_after,
            ),
        )?;
        proof.push(step);
        let witness = BindingHistoryWitness {
            protocol,
            scope,
            graph_digest,
            proof,
            lineage_digest,
        };
        witness.validate_lineage(metadata)?;
        result.push(witness);
    }
    Ok(result)
}

/// This certificate is deliberately outside the roots it names: including
/// those roots in their own inputs would be circular. Storage validates the
/// authority binding; materialization validates the selected graph binding.
///
/// The persisted certificate belongs to the trusted local storage boundary:
/// it is not a signature against a privileged writer replacing repository
/// bytes. Ordinary transactions contain no certificate field, transfer strips
/// certificates, and only the trusted checked-publication implementation can
/// construct one. Read admission also checks the complete contiguous operation
/// lineage; an arbitrary hash or a matching current graph is not a proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingHistoryWitness {
    protocol: u32,
    scope: WorkspaceSnapshotBinding,
    graph_digest: Hash256,
    proof: Vec<BindingHistoryStep>,
    /// Digest of the complete checked lineage, including its genesis.
    lineage_digest: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingHistoryStep {
    operation_id: OperationId,
    /// Identity of the actual validated operation, including its transaction.
    operation_identity: Hash256,
    qualification: BindingHistoryQualification,
    observed_graph_digest: Option<Hash256>,
    selected_binding: Hash256,
    graph_digest: Hash256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum BindingHistoryQualification {
    NewNativeGenesis,
    CheckedHistoryGenesis,
    CheckedTransition,
    /// A lineage that starts part way through the operation log, at an
    /// operation whose selected graph a trusted verifier re-derived from exact
    /// bytes and found equal. Operations before it stay unproven: the proof
    /// names none of them.
    CheckedRederivation,
}

fn canonical_digest(domain: &[u8], value: &impl Serialize) -> Result<Hash256, KinDbError> {
    let mut hash = Sha256::new();
    hash.update(domain);
    super::canonical_hash::canonical_hash_into(&mut hash, value).map_err(invalid)?;
    Ok(Hash256::from_bytes(hash.finalize().into()))
}

fn selected_binding(scope: &WorkspaceSnapshotBinding) -> Result<Hash256, KinDbError> {
    canonical_digest(b"kin.binding-history.selected-authority.v1\0", scope)
}

impl BindingHistoryWitness {
    /// The workspace whose selected graph this witness proves.
    pub fn workspace_id(&self) -> kin_model::WorkspaceId {
        self.scope.workspace_id
    }

    fn validate_lineage(&self, metadata: &PersistedRepositoryAuthority) -> Result<(), KinDbError> {
        if self.proof.is_empty() || self.proof.len() > metadata.operation_log.len() {
            return Err(invalid("unqualified or incomplete operation lineage"));
        }
        // A proof names every operation from its own start to the head. It
        // starts at genesis, or at a checked re-derivation part way through the
        // log; the operations before a re-derivation are not part of it.
        let offset = metadata.operation_log.len() - self.proof.len();
        let mut prior = Hash256::from_bytes([0; 32]);
        let mut previous_roots = None;
        for (position, (step, operation)) in self
            .proof
            .iter()
            .zip(&metadata.operation_log[offset..])
            .enumerate()
        {
            let index = offset + position;
            if step.operation_id != operation.operation_id
                || step.operation_identity != operation.identity_hash()?
                || operation.repository_id != metadata.repository_id
                || operation.roots_before.generation != index as u64
                || operation.roots_after.generation != index as u64 + 1
                || previous_roots.is_some_and(|roots| roots != &operation.roots_before)
            {
                return Err(invalid(
                    "operation lineage is not contiguous or identity-bound",
                ));
            }
            match (index, position, step.qualification) {
                (0, 0, BindingHistoryQualification::NewNativeGenesis)
                    if operation.git_authority_delta.is_none() => {}
                (0, 0, BindingHistoryQualification::CheckedHistoryGenesis) => {}
                (_, 0, BindingHistoryQualification::CheckedRederivation) => {}
                (_, 1.., BindingHistoryQualification::CheckedTransition) => {}
                _ => return Err(invalid("unqualified lineage genesis or transition")),
            }
            prior = canonical_digest(
                b"kin.binding-history.checked-operation.v1\0",
                &(prior, step, &operation.roots_before, &operation.roots_after),
            )?;
            previous_roots = Some(&operation.roots_after);
        }
        let last = self.proof.last().expect("nonempty proof checked above");
        if previous_roots != Some(&metadata.roots)
            || last.selected_binding != selected_binding(&self.scope)?
            || last.graph_digest != self.graph_digest
            || prior != self.lineage_digest
        {
            return Err(invalid(
                "lineage does not qualify the selected authority and graph",
            ));
        }
        Ok(())
    }
}

/// A capability constructed only after storage and selected-graph admission.
/// It is never deserialized or accepted as an input from a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBindingHistory {
    witness: BindingHistoryWitness,
    selected_graph_digest: Hash256,
    runtime_lineage: Hash256,
}

impl VerifiedBindingHistory {
    pub(crate) fn validate_selected(&self, snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
        if graph_digest(snapshot)? != self.selected_graph_digest {
            return Err(invalid("runtime capability no longer names this graph"));
        }
        Ok(())
    }

    pub(crate) fn observation(&self) -> kin_model::BindingHistoryObservation {
        kin_model::BindingHistoryObservation::Checked {
            lineage: self.runtime_lineage,
            generation: self.witness.scope.roots.generation,
        }
    }
}

fn invalid(reason: impl std::fmt::Display) -> KinDbError {
    KinDbError::StorageError(format!("binding history witness: {reason}"))
}

pub(crate) fn validate_metadata(metadata: &PersistedRepositoryAuthority) -> Result<(), KinDbError> {
    if metadata.schema_version < BINDING_HISTORY_AUTHORITY_SCHEMA
        && !metadata.binding_history.is_empty()
    {
        return Err(invalid("requires authority schema 5"));
    }
    let mut previous = None;
    for witness in &metadata.binding_history {
        if witness.protocol != BINDING_HISTORY_PROTOCOL {
            return Err(invalid("unsupported protocol"));
        }
        witness.scope.validate()?;
        let id = witness.scope.workspace_id;
        if previous.is_some_and(|previous| previous >= id) {
            return Err(invalid("workspace witnesses must be unique and sorted"));
        }
        previous = Some(id);
        let workspace = metadata
            .workspaces
            .iter()
            .find(|w| w.workspace_id == id)
            .ok_or_else(|| invalid("selected workspace is absent"))?;
        let expected = workspace.snapshot_binding(metadata.roots.clone())?;
        if witness.scope != expected || witness.scope.repository_id != metadata.repository_id {
            return Err(invalid("authority or workspace binding differs"));
        }
        witness.validate_lineage(metadata)?;
    }
    Ok(())
}

/// Restore only proof bytes previously constructed by checked preparation.
/// The required local record authenticates their custody, not a wire hash or
/// Boolean. Recheck exact predecessor proof prefixes and observation binding
/// before normal metadata/selected-graph admission creates any capability.
pub(in crate::storage) fn restore_prepared_successor(
    predecessor: &PersistedRepositoryAuthority,
    successor: &mut PersistedRepositoryAuthority,
    workspace: kin_model::WorkspaceId,
    observed_digest: Hash256,
    witnesses: &[BindingHistoryWitness],
) -> Result<(), KinDbError> {
    for witness in witnesses {
        let prior = predecessor
            .binding_history
            .iter()
            .find(|prior| prior.scope.workspace_id == witness.scope.workspace_id)
            .ok_or_else(|| invalid("prepared transition has no qualified predecessor"))?;
        if witness.proof.len() != prior.proof.len() + 1
            || !witness.proof.starts_with(&prior.proof)
            || witness.proof.last().map(|step| step.observed_graph_digest)
                != Some(if witness.scope.workspace_id == workspace {
                    Some(observed_digest)
                } else {
                    None
                })
        {
            return Err(invalid(
                "prepared proof changes its predecessor or observed graph",
            ));
        }
    }
    successor.binding_history = witnesses.to_vec();
    validate_metadata(successor)
}

/// Hash only the semantic graph selected by a workspace, once at publication
/// or materialization. Query paths use the resulting immutable capability.
pub(crate) fn graph_digest(snapshot: &GraphSnapshot) -> Result<Hash256, KinDbError> {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.binding-history.selected-graph.v1\0");
    for result in [
        super::canonical_hash::canonical_hash_into(&mut hasher, &snapshot.entities),
        super::canonical_hash::canonical_hash_into(&mut hasher, &snapshot.relations),
        super::canonical_hash::canonical_hash_into(&mut hasher, &snapshot.external_references),
        super::canonical_hash::canonical_hash_into(&mut hasher, &snapshot.resolved_tree),
    ] {
        result.map_err(invalid)?;
    }
    Ok(Hash256::from_bytes(hasher.finalize().into()))
}

pub(crate) fn bind_selected_graph(
    metadata: &PersistedRepositoryAuthority,
    workspace: kin_model::WorkspaceId,
    snapshot: &mut GraphSnapshot,
) -> Result<(), KinDbError> {
    snapshot.verified_binding_history = None;
    validate_metadata(metadata)?;
    let Some(witness) = metadata
        .binding_history
        .iter()
        .find(|w| w.scope.workspace_id == workspace)
    else {
        return Ok(());
    };
    if graph_digest(snapshot)? != witness.graph_digest {
        return Err(invalid("selected graph differs"));
    }
    snapshot.verified_binding_history = Some(VerifiedBindingHistory {
        witness: witness.clone(),
        selected_graph_digest: witness.graph_digest,
        runtime_lineage: witness.lineage_digest,
    });
    Ok(())
}

/// Runtime derivations carry the exact durable anchor plus a checked selected
/// graph. They cannot cross serialization or qualify an unknown predecessor.
pub fn is_checked_derivation_of(
    authority: &GraphSnapshot,
    observed: &GraphSnapshot,
) -> Result<bool, KinDbError> {
    let (Some(base), Some(derived)) = (
        &authority.verified_binding_history,
        &observed.verified_binding_history,
    ) else {
        return Ok(false);
    };
    base.validate_selected(authority)?;
    derived.validate_selected(observed)?;
    Ok(base.witness == derived.witness && authority.resolved_tree == observed.resolved_tree)
}

pub(crate) fn qualify_graph_derivation(
    before: &GraphSnapshot,
    after: &GraphSnapshot,
    verifier: &dyn BindingHistoryVerifier,
    load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
) -> Result<Option<VerifiedBindingHistory>, KinDbError> {
    let Some(prior) = &before.verified_binding_history else {
        return Ok(None);
    };
    prior.validate_selected(before)?;
    if !verifier.verify_graph_transition(before, after, load_body)? {
        return Ok(None);
    }
    let selected_graph_digest = graph_digest(after)?;
    let runtime_lineage = canonical_digest(
        b"kin.binding-history.runtime-transition.v1\0",
        &(
            prior.runtime_lineage,
            prior.selected_graph_digest,
            selected_graph_digest,
        ),
    )?;
    Ok(Some(VerifiedBindingHistory {
        witness: prior.witness.clone(),
        selected_graph_digest,
        runtime_lineage,
    }))
}
