// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::types::*;

/// The serializable snapshot of the entire graph state.
///
/// This is the on-disk format. We use std::collections::HashMap here
/// (not hashbrown) for stable serde compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub version: u32,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub incoming: HashMap<EntityId, Vec<RelationId>>,
    pub changes: HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub branches: HashMap<BranchName, Branch>,
    #[serde(default)]
    pub work_items: HashMap<WorkId, WorkItem>,
    #[serde(default)]
    pub annotations: HashMap<AnnotationId, Annotation>,
    #[serde(default)]
    pub work_links: Vec<WorkLink>,
    #[serde(default)]
    pub test_cases: HashMap<TestId, TestCase>,
    #[serde(default)]
    pub assertions: HashMap<AssertionId, Assertion>,
    #[serde(default)]
    pub verification_runs: HashMap<VerificationRunId, VerificationRun>,
    #[serde(default)]
    pub test_covers_entity: Vec<(TestId, EntityId)>,
    #[serde(default)]
    pub test_covers_contract: Vec<(TestId, ContractId)>,
    #[serde(default)]
    pub test_verifies_work: Vec<(TestId, WorkId)>,
    #[serde(default)]
    pub run_proves_entity: Vec<(VerificationRunId, EntityId)>,
    #[serde(default)]
    pub run_proves_work: Vec<(VerificationRunId, WorkId)>,
    #[serde(default)]
    pub mock_hints: Vec<MockHint>,
    #[serde(default)]
    pub contracts: HashMap<ContractId, Contract>,
    #[serde(default)]
    pub actors: HashMap<ActorId, Actor>,
    #[serde(default)]
    pub delegations: Vec<Delegation>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub audit_events: Vec<AuditEvent>,
    #[serde(default)]
    pub shallow_files: Vec<ShallowTrackedFile>,
    #[serde(default)]
    pub file_hashes: HashMap<String, [u8; 32]>,
    #[serde(default)]
    pub sessions: HashMap<SessionId, AgentSession>,
    #[serde(default)]
    pub intents: HashMap<IntentId, Intent>,
    #[serde(default)]
    pub downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

impl GraphSnapshot {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 3;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Size of the SHA-256 checksum appended to v3+ snapshots.
    pub const CHECKSUM_LEN: usize = 32;

    pub fn empty() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            branches: HashMap::new(),
            work_items: HashMap::new(),
            annotations: HashMap::new(),
            work_links: Vec::new(),
            test_cases: HashMap::new(),
            assertions: HashMap::new(),
            verification_runs: HashMap::new(),
            test_covers_entity: Vec::new(),
            test_covers_contract: Vec::new(),
            test_verifies_work: Vec::new(),
            run_proves_entity: Vec::new(),
            run_proves_work: Vec::new(),
            mock_hints: Vec::new(),
            contracts: HashMap::new(),
            actors: HashMap::new(),
            delegations: Vec::new(),
            approvals: Vec::new(),
            audit_events: Vec::new(),
            shallow_files: Vec::new(),
            file_hashes: HashMap::new(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
        }
    }

    /// Serialize the snapshot to bytes with a header and SHA-256 checksum.
    ///
    /// Wire format (v3):
    ///   [4B magic] [4B version LE] [8B body_len LE] [body ...] [32B SHA-256]
    ///
    /// The SHA-256 is computed over the msgpack body only.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::CURRENT_VERSION.to_le_bytes());
        let mut snapshot = self.clone();
        snapshot.version = Self::CURRENT_VERSION;
        let body = rmp_serde::to_vec(&snapshot).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
        })?;
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        // Append SHA-256 checksum of the body
        let hash = Sha256::digest(&body);
        buf.extend_from_slice(&hash);

        Ok(buf)
    }

    /// Deserialize a snapshot from bytes (with header validation).
    ///
    /// - v1/v2: no checksum (loaded with a warning for v2)
    /// - v3+: SHA-256 checksum verified; returns error on mismatch
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
        if data.len() < 16 {
            return Err(crate::error::KinDbError::StorageError(
                "file too small for header".to_string(),
            ));
        }

        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(crate::error::KinDbError::StorageError(format!(
                "invalid magic bytes: expected KNDB, got {:?}",
                magic
            )));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "version bytes: expected 4-byte slice".to_string(),
            )
        })?);
        let body_len = u64::from_le_bytes(data[8..16].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "body_len bytes: expected 8-byte slice".to_string(),
            )
        })?) as usize;
        if data.len() < 16 + body_len {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot file truncated: body extends past end of data".to_string(),
            ));
        }
        let body = &data[16..16 + body_len];

        match version {
            1 => {
                let legacy: GraphSnapshotV1 = rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })?;
                Ok(legacy.into())
            }
            2 => {
                // v2 snapshots have no checksum — load normally
                rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })
            }
            3 => {
                // v3: verify SHA-256 checksum after body
                let checksum_start = 16 + body_len;
                if data.len() < checksum_start + Self::CHECKSUM_LEN {
                    return Err(crate::error::KinDbError::StorageError(
                        "v3 snapshot missing SHA-256 checksum".to_string(),
                    ));
                }
                let stored_hash = &data[checksum_start..checksum_start + Self::CHECKSUM_LEN];
                let computed_hash = Sha256::digest(body);

                if stored_hash != computed_hash.as_slice() {
                    return Err(crate::error::KinDbError::StorageError(
                        "snapshot checksum mismatch: file is corrupted".to_string(),
                    ));
                }

                rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })
            }
            _ => Err(crate::error::KinDbError::StorageError(format!(
                "unsupported format version: {version} (expected 1, 2, or {})",
                Self::CURRENT_VERSION
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GraphSnapshotV1 {
    version: u32,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    incoming: HashMap<EntityId, Vec<RelationId>>,
    changes: HashMap<SemanticChangeId, SemanticChange>,
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    branches: HashMap<BranchName, Branch>,
}

impl From<GraphSnapshotV1> for GraphSnapshot {
    fn from(value: GraphSnapshotV1) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = value.entities;
        snapshot.relations = value.relations;
        snapshot.outgoing = value.outgoing;
        snapshot.incoming = value.incoming;
        snapshot.changes = value.changes;
        snapshot.change_children = value.change_children;
        snapshot.branches = value.branches;
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_snapshot() {
        let snap = GraphSnapshot::empty();

        let bytes = snap.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn v3_checksum_is_appended() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Header: 4 magic + 4 version + 8 body_len = 16
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        // Total should be header + body + 32-byte SHA-256
        assert_eq!(bytes.len(), 16 + body_len + GraphSnapshot::CHECKSUM_LEN);

        // Version in header should be 3
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(version, 3);
    }

    #[test]
    fn v3_corrupted_body_detected() {
        let snap = GraphSnapshot::empty();
        let mut bytes = snap.to_bytes().unwrap();

        // Corrupt a byte in the body (after the 16-byte header)
        if bytes.len() > 20 {
            bytes[20] ^= 0xFF;
        }

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checksum mismatch") || msg.contains("corrupted"),
            "expected checksum error, got: {msg}"
        );
    }

    #[test]
    fn v3_truncated_checksum_detected() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Truncate the last 10 bytes (partial checksum)
        let truncated = &bytes[..bytes.len() - 10];

        let err = GraphSnapshot::from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing SHA-256 checksum"),
            "expected missing checksum error, got: {msg}"
        );
    }

    #[test]
    fn loads_v1_snapshot_with_new_fields_defaulted() {
        let legacy = GraphSnapshotV1 {
            version: 1,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            branches: HashMap::new(),
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let body = rmp_serde::to_vec(&legacy).unwrap();
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.work_items.is_empty());
        assert!(loaded.shallow_files.is_empty());
        assert!(loaded.sessions.is_empty());
    }

    #[test]
    fn loads_v2_snapshot_without_checksum() {
        // v2 snapshots have no checksum — must still load
        let snap = GraphSnapshot::empty();
        let mut snapshot = snap.clone();
        snapshot.version = 2;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(GraphSnapshot::from_bytes(&data).is_err());
    }
}
