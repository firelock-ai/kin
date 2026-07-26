// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::ids::*;
use crate::review::RiskSummary;
use crate::timestamp::Timestamp;

/// Kin's native commit — the unit of semantic history.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SemanticChange {
    /// Content-addressed hash.
    pub id: SemanticChangeId,
    /// 0 = genesis, 1 = normal, 2 = merge.
    pub parents: Vec<SemanticChangeId>,
    pub timestamp: Timestamp,
    /// Human or assistant.
    pub author: AuthorId,
    pub message: String,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    /// Exact changes to the repository tree, including code, configuration,
    /// documentation, assets, and files in unsupported languages.
    pub tree_deltas: Vec<TreeDelta>,
    pub projected_files: Vec<FilePathId>,
    pub spec_link: Option<SpecId>,
    pub evidence: Vec<EvidenceId>,
    pub risk_summary: Option<RiskSummary>,
    /// Informational: branch name at creation time.
    pub authored_on: Option<BranchName>,
}

/// Delta for a single entity within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::large_enum_variant)]
pub enum EntityDelta {
    Added(Entity),
    Modified { old: Entity, new: Entity },
    Removed(EntityId),
}

/// Delta for a single relation within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum RelationDelta {
    Added(crate::relation::Relation),
    Removed(RelationId),
}

/// Delta for a batch of transactional graph changes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TransactionDelta {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    pub tree_deltas: Vec<TreeDelta>,
}

/// Exact Git-relevant kind of a repository tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeEntryKind {
    Regular { executable: bool },
    Symlink,
}

/// Content identity and exact mode for one repository tree entry.
///
/// Symlink entries store the link target bytes as the referenced blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TreeEntry {
    pub blob_hash: Hash256,
    pub kind: TreeEntryKind,
}

impl TreeEntry {
    pub const fn regular(blob_hash: Hash256, executable: bool) -> Self {
        Self {
            blob_hash,
            kind: TreeEntryKind::Regular { executable },
        }
    }

    pub const fn symlink(blob_hash: Hash256) -> Self {
        Self {
            blob_hash,
            kind: TreeEntryKind::Symlink,
        }
    }
}

/// Exact transition for one path in the repository tree.
///
/// Each variant carries every entry needed to describe the transition. This
/// makes mode-unknown entries, missing hashes, and `None -> None` deltas
/// unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeDelta {
    Added {
        file_id: FilePathId,
        new_entry: TreeEntry,
    },
    Modified {
        file_id: FilePathId,
        old_entry: TreeEntry,
        new_entry: TreeEntry,
    },
    Removed {
        file_id: FilePathId,
        old_entry: TreeEntry,
    },
}

impl TreeDelta {
    pub fn file_id(&self) -> &FilePathId {
        match self {
            Self::Added { file_id, .. }
            | Self::Modified { file_id, .. }
            | Self::Removed { file_id, .. } => file_id,
        }
    }

    pub const fn old_entry(&self) -> Option<TreeEntry> {
        match self {
            Self::Added { .. } => None,
            Self::Modified { old_entry, .. } | Self::Removed { old_entry, .. } => Some(*old_entry),
        }
    }

    pub const fn new_entry(&self) -> Option<TreeEntry> {
        match self {
            Self::Added { new_entry, .. } | Self::Modified { new_entry, .. } => Some(*new_entry),
            Self::Removed { .. } => None,
        }
    }

    pub const fn is_added(&self) -> bool {
        matches!(self, Self::Added { .. })
    }

    pub const fn is_modified(&self) -> bool {
        matches!(self, Self::Modified { .. })
    }

    pub const fn is_removed(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_entry_constructors_preserve_exact_kind() {
        let regular = TreeEntry::regular(Hash256::from_bytes([0x11; 32]), false);
        let executable = TreeEntry::regular(Hash256::from_bytes([0x22; 32]), true);
        let symlink = TreeEntry::symlink(Hash256::from_bytes([0x33; 32]));

        assert_eq!(regular.kind, TreeEntryKind::Regular { executable: false });
        assert_eq!(executable.kind, TreeEntryKind::Regular { executable: true });
        assert_eq!(symlink.kind, TreeEntryKind::Symlink);
    }

    #[test]
    fn tree_delta_roundtrip_preserves_complete_transition() {
        let old_entry = TreeEntry::regular(Hash256::from_bytes([0x44; 32]), false);
        let new_entry = TreeEntry::symlink(Hash256::from_bytes([0x55; 32]));
        let delta = TreeDelta::Modified {
            file_id: FilePathId::new("compose.yaml"),
            old_entry,
            new_entry,
        };

        let json = serde_json::to_string(&delta).unwrap();
        let parsed: TreeDelta = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, delta);
        assert_eq!(parsed.file_id(), &FilePathId::new("compose.yaml"));
        assert_eq!(parsed.old_entry(), Some(old_entry));
        assert_eq!(parsed.new_entry(), Some(new_entry));
        assert!(parsed.is_modified());
    }

    #[test]
    fn tree_delta_variants_expose_only_valid_sides() {
        let entry = TreeEntry::regular(Hash256::from_bytes([0x66; 32]), false);
        let added = TreeDelta::Added {
            file_id: FilePathId::new("Dockerfile"),
            new_entry: entry,
        };
        let removed = TreeDelta::Removed {
            file_id: FilePathId::new("Dockerfile"),
            old_entry: entry,
        };

        assert_eq!(added.old_entry(), None);
        assert_eq!(added.new_entry(), Some(entry));
        assert!(added.is_added());
        assert_eq!(removed.old_entry(), Some(entry));
        assert_eq!(removed.new_entry(), None);
        assert!(removed.is_removed());
    }

    #[test]
    fn incomplete_tree_delta_payloads_are_rejected() {
        let entry = serde_json::json!({
            "blob_hash": Hash256::from_bytes([0x77; 32]),
            "kind": { "type": "regular", "executable": false }
        });
        let missing_old_entry = serde_json::json!({
            "operation": "modified",
            "file_id": "compose.yaml",
            "new_entry": entry
        });
        let invalid_added_with_old_entry = serde_json::json!({
            "operation": "added",
            "file_id": "compose.yaml",
            "old_entry": entry,
            "new_entry": entry
        });

        assert!(serde_json::from_value::<TreeDelta>(missing_old_entry).is_err());
        assert!(serde_json::from_value::<TreeDelta>(invalid_added_with_old_entry).is_err());
    }

    #[test]
    fn transaction_delta_requires_tree_mutations_to_be_explicit() {
        let legacy_payload = serde_json::json!({
            "entity_deltas": [],
            "relation_deltas": []
        });
        assert!(serde_json::from_value::<TransactionDelta>(legacy_payload).is_err());

        let delta = TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                file_id: FilePathId::new("Makefile"),
                new_entry: TreeEntry::regular(Hash256::from_bytes([0x88; 32]), false),
            }],
        };
        let encoded = serde_json::to_vec(&delta).unwrap();
        let decoded: TransactionDelta = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.tree_deltas, delta.tree_deltas);
    }
}
