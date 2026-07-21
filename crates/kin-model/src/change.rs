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
    /// Non-entity file changes.
    pub artifact_deltas: Vec<ArtifactDelta>,
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
}

/// Delta for a non-entity file within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactDelta {
    pub file_id: FilePathId,
    pub kind: ArtifactDeltaKind,
    pub old_hash: Option<Hash256>,
    pub new_hash: Option<Hash256>,
}

/// Classification of an artifact delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ArtifactDeltaKind {
    /// Legacy added entry whose exact mode was not recorded.
    Added,
    /// Legacy modified entry whose resulting exact mode was not recorded.
    Modified,
    /// Removed entry of any prior source kind.
    Removed,
    /// Added regular file without an executable bit.
    AddedRegularFile,
    /// Modified content or mode whose resulting entry is a regular non-executable file.
    ModifiedRegularFile,
    /// Added regular file with at least one executable bit.
    AddedExecutableFile,
    /// Modified content or mode whose resulting entry is an executable file.
    ModifiedExecutableFile,
    /// Added symbolic link. `new_hash` names UTF-8 target bytes.
    AddedSymlink,
    /// Modified content or mode whose resulting entry is a symbolic link.
    ModifiedSymlink,
}

/// Exact source entry kind carried by graph artifact history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceEntryKind {
    File { executable: bool },
    Symlink,
}

impl ArtifactDeltaKind {
    /// Resulting exact-source entry kind, or `None` for a removal or a legacy
    /// delta that predates mode capture.
    pub const fn source_entry_kind(self) -> Option<SourceEntryKind> {
        match self {
            Self::AddedRegularFile | Self::ModifiedRegularFile => {
                Some(SourceEntryKind::File { executable: false })
            }
            Self::AddedExecutableFile | Self::ModifiedExecutableFile => {
                Some(SourceEntryKind::File { executable: true })
            }
            Self::AddedSymlink | Self::ModifiedSymlink => Some(SourceEntryKind::Symlink),
            Self::Added | Self::Modified | Self::Removed => None,
        }
    }

    pub const fn is_added(self) -> bool {
        matches!(
            self,
            Self::Added | Self::AddedRegularFile | Self::AddedExecutableFile | Self::AddedSymlink
        )
    }

    pub const fn is_modified(self) -> bool {
        matches!(
            self,
            Self::Modified
                | Self::ModifiedRegularFile
                | Self::ModifiedExecutableFile
                | Self::ModifiedSymlink
        )
    }

    pub const fn is_removed(self) -> bool {
        matches!(self, Self::Removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_delta_kind_roundtrip() {
        for kind in [
            ArtifactDeltaKind::Added,
            ArtifactDeltaKind::Modified,
            ArtifactDeltaKind::Removed,
            ArtifactDeltaKind::AddedRegularFile,
            ArtifactDeltaKind::ModifiedRegularFile,
            ArtifactDeltaKind::AddedExecutableFile,
            ArtifactDeltaKind::ModifiedExecutableFile,
            ArtifactDeltaKind::AddedSymlink,
            ArtifactDeltaKind::ModifiedSymlink,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: ArtifactDeltaKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn artifact_delta_kind_preserves_resulting_source_mode() {
        assert_eq!(
            ArtifactDeltaKind::AddedRegularFile.source_entry_kind(),
            Some(SourceEntryKind::File { executable: false })
        );
        assert_eq!(
            ArtifactDeltaKind::ModifiedExecutableFile.source_entry_kind(),
            Some(SourceEntryKind::File { executable: true })
        );
        assert_eq!(
            ArtifactDeltaKind::AddedSymlink.source_entry_kind(),
            Some(SourceEntryKind::Symlink)
        );
        assert_eq!(ArtifactDeltaKind::Removed.source_entry_kind(), None);
        assert!(ArtifactDeltaKind::AddedSymlink.is_added());
        assert!(ArtifactDeltaKind::ModifiedSymlink.is_modified());
        assert!(ArtifactDeltaKind::Removed.is_removed());
    }

    #[test]
    fn legacy_artifact_kind_remains_compatible_but_mode_unknown() {
        let parsed: ArtifactDeltaKind = serde_json::from_str("\"Added\"").unwrap();
        assert_eq!(parsed, ArtifactDeltaKind::Added);
        assert_eq!(parsed.source_entry_kind(), None);
        assert!(parsed.is_added());
    }
}
