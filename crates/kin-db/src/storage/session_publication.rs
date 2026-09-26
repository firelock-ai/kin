// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Local prepared session authority. Persisted evidence is admitted by the
//! manager, not a deserialized runtime capability. Privileged raw-storage
//! forgery remains outside the existing trusted local-storage boundary.

use super::{binding_history::BindingHistoryWitness, GraphSnapshot};
use crate::KinDbError;
use kin_model::{
    Entity, EntityId, ExternalReference, ExternalReferenceId, Hash256, OperationId, Relation,
    RelationId, RepositoryCommitReceipt, RepositoryTransaction, ResolutionRecord,
    ResolutionRecordId, ResolvedTree, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Explicit refusal limit, not an eviction policy. Completed records remain
/// necessary evidence; this first protocol does not compact their contents.
pub const MAX_SESSION_PUBLICATION_BYTES: u64 = 256 * 1024 * 1024;

/// Exact caller control identities. These bind inputs; they grant no authority
/// and make no claim that the caller has observed a real session control file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPublicationBinding {
    pub session_id: String,
    pub base_identity: Hash256,
    pub control_identity: Hash256,
}

impl SessionPublicationBinding {
    pub(super) fn validate(&self) -> Result<(), KinDbError> {
        if self.session_id.is_empty()
            || self.session_id.len() > 128
            || !self
                .session_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(invalid("invalid portable session identity"));
        }
        Ok(())
    }
}

/// Durable location information, separate from the portable binding identity.
/// This is a locator, not a filesystem or publication capability. Runtime
/// recovery must re-observe its no-follow directory identities and exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionPublicationLocator {
    RetainedUnixV1 { session_leaf: String },
}

impl SessionPublicationLocator {
    pub(super) fn validate(&self) -> Result<(), KinDbError> {
        let Self::RetainedUnixV1 { session_leaf } = self;
        // Unix leaves may contain spaces, non-ASCII text, and backslashes.
        // Do not reinterpret them as the portable session_id or a path.
        if !session_leaf.starts_with("session-")
            || session_leaf.len() == "session-".len()
            || session_leaf.len() > 4096
            || session_leaf.contains('/')
            || session_leaf.contains('\0')
        {
            return Err(invalid("invalid retained Unix session leaf"));
        }
        Ok(())
    }
}

/// Only a local manager can create this handle. It is never deserialized or
/// accepted from the disposable workspace. Commit revalidates its durable
/// acknowledgement and exact repository identity on every use.
#[derive(Debug, Clone)]
pub struct PreparedSessionPublication {
    pub(super) record: PreparedSessionRecord,
    pub(super) payload_sha256: String,
}

impl PreparedSessionPublication {
    pub fn operation_id(&self) -> OperationId {
        self.record.transaction.operation_id
    }
    pub fn transaction_hash(&self) -> Hash256 {
        self.record.receipt.transaction_hash
    }
    pub fn binding(&self) -> &SessionPublicationBinding {
        &self.record.binding
    }
    /// Legacy v1 handles have no runtime recovery location. Never interpret
    /// their arbitrary portable session_id as a filesystem name.
    pub fn recovery_locator(&self) -> Result<&SessionPublicationLocator, KinDbError> {
        self.record.recovery_locator.as_ref().ok_or_else(|| {
            invalid("unsupported runtime recovery identity: legacy v1 preparation has no locator")
        })
    }
    pub fn transaction(&self) -> &RepositoryTransaction {
        &self.record.transaction
    }
    pub fn expected_receipt(&self) -> &RepositoryCommitReceipt {
        &self.record.receipt
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapturedSessionGraph {
    entities: BTreeMap<EntityId, Entity>,
    relations: BTreeMap<RelationId, Relation>,
    external_references: BTreeMap<ExternalReferenceId, ExternalReference>,
    tree: ResolvedTree,
    /// Appended last and omitted when empty, so a captured graph without
    /// resolution records keeps the bytes it always had.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    resolution_records: BTreeMap<ResolutionRecordId, ResolutionRecord>,
}

impl CapturedSessionGraph {
    pub(super) fn capture(source: &GraphSnapshot) -> Self {
        Self {
            entities: source
                .entities
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            relations: source
                .relations
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            external_references: source
                .external_references
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            tree: source.resolved_tree.clone(),
            resolution_records: source
                .resolution_records
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        }
    }
    pub(super) fn graph(&self) -> GraphSnapshot {
        let mut graph = GraphSnapshot::empty();
        graph.entities = self.entities.iter().map(|(k, v)| (*k, v.clone())).collect();
        graph.relations = self
            .relations
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        graph.external_references = self
            .external_references
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        graph.resolved_tree = self.tree.clone();
        if !self.resolution_records.is_empty() {
            graph.resolution_records = self
                .resolution_records
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            graph.version = GraphSnapshot::graph_only_version(graph.resolution_records.values());
        }
        graph
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedSessionRecord {
    pub version: u32,
    pub binding: SessionPublicationBinding,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_locator"
    )]
    pub recovery_locator: Option<SessionPublicationLocator>,
    pub workspace: WorkspaceId,
    pub predecessor_authority: String,
    pub predecessor_backend_generation: u64,
    pub transaction: RepositoryTransaction,
    pub observed: CapturedSessionGraph,
    pub observed_digest: Hash256,
    pub successor_graph_digest: Hash256,
    pub successor_history: Vec<BindingHistoryWitness>,
    pub receipt: RepositoryCommitReceipt,
}

// A missing field is the legacy format. An explicitly present null is not:
// old readers rejected any such field, and v2 requires a real typed locator.
fn deserialize_present_locator<'de, D>(
    deserializer: D,
) -> Result<Option<SessionPublicationLocator>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SessionPublicationLocator::deserialize(deserializer).map(Some)
}

impl PreparedSessionRecord {
    fn validate_version(&self) -> Result<(), KinDbError> {
        match (self.version, &self.recovery_locator) {
            (1, None) => Ok(()),
            (2, Some(locator)) => locator.validate(),
            _ => Err(invalid("prepared record version/locator mismatch")),
        }
    }
    pub fn content_digest(&self) -> Result<Hash256, KinDbError> {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        self.validate_version()?;
        hash.update(match self.version {
            1 => b"kin.prepared-session.record.v1\0",
            2 => b"kin.prepared-session.record.v2\0",
            _ => unreachable!("validated record version"),
        });
        super::canonical_hash::canonical_hash_into(&mut hash, self).map_err(invalid)?;
        Ok(Hash256::from_bytes(hash.finalize().into()))
    }
    pub fn encode(&self) -> Result<Vec<u8>, KinDbError> {
        self.validate_version()?;
        let bytes = serde_json::to_vec(self).map_err(invalid)?;
        if bytes.len() as u64 > MAX_SESSION_PUBLICATION_BYTES {
            return Err(invalid(
                "prepared publication exceeds explicit 256 MiB limit",
            ));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, KinDbError> {
        if bytes.len() as u64 > MAX_SESSION_PUBLICATION_BYTES {
            return Err(invalid(
                "prepared publication exceeds explicit 256 MiB limit",
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        record.binding.validate()?;
        record.receipt.validate()?;
        record.validate_version()?;
        if record.transaction.transaction_hash()? != record.receipt.transaction_hash
            || record.transaction.operation_id != record.receipt.operation_id
            || record.transaction.repository_id != record.receipt.repository_id
            || record.transaction.expected_roots != record.receipt.roots_before
            || super::binding_history::graph_digest(&record.observed.graph())?
                != record.observed_digest
        {
            return Err(invalid("prepared publication identity mismatch"));
        }
        Ok(record)
    }
}

pub(super) fn invalid(reason: impl std::fmt::Display) -> KinDbError {
    KinDbError::StorageError(format!("prepared session publication: {reason}"))
}
