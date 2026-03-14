use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::*;

/// The serializable snapshot of the entire graph state.
///
/// This is the on-disk format. We use std::collections::HashMap here
/// (not hashbrown) for stable serde compatibility.
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub version: u32,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub incoming: HashMap<EntityId, Vec<RelationId>>,
    pub changes: HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub branches: HashMap<BranchName, Branch>,
}

impl GraphSnapshot {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Serialize the snapshot to bytes with a header.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::CURRENT_VERSION.to_le_bytes());
        let body = serde_json::to_vec(self).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
        })?;
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(body);
        Ok(buf)
    }

    /// Deserialize a snapshot from bytes (with header validation).
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

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != Self::CURRENT_VERSION {
            return Err(crate::error::KinDbError::StorageError(format!(
                "unsupported format version: {version} (expected {})",
                Self::CURRENT_VERSION
            )));
        }

        let body_len = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
        let body = &data[16..16 + body_len];

        serde_json::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_snapshot() {
        let snap = GraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            branches: HashMap::new(),
        };

        let bytes = snap.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(GraphSnapshot::from_bytes(&data).is_err());
    }
}
