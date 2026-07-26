// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared wire contract for one graph-owned workspace-tree projection.
//!
//! Both the Kin daemon producer and filesystem/VFS consumers use this exact
//! type. The strong HTTP ETag is [`WorkspaceTreeSnapshot::identity`], so a
//! consumer can independently bind transport metadata, projection metadata,
//! and the graph-owned tree to one canonical payload.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    compute_resolved_tree_hash, identity::canonical_json_bytes, ArtifactId, Hash256, ModelError,
    RepoPath, ResolvedArtifact, ResolvedTree, Result, TreeEntry, WorkspaceSnapshotBinding,
};

/// Current shared daemon/VFS workspace-tree wire schema.
///
/// Versions 1 and 2 were private `kin-vfs` contracts. Version 3 was the first
/// contract owned by `kin-model`; version 4 additionally binds the persisted
/// semantic workspace overlay.
pub const WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION: u32 = 4;

/// One leaf in a workspace-tree projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceTreeArtifact {
    pub artifact_id: ArtifactId,
    pub path: RepoPath,
    pub entry: TreeEntry,
    /// Exact byte length of the blob or symlink target. Gitlinks have no local
    /// body and must advertise zero.
    pub size: u64,
    /// Projection timestamp as Unix seconds. Git does not store file mtimes;
    /// this value is projection metadata and is integrity-bound by the
    /// snapshot identity rather than by the repository tree hash.
    pub mtime: u64,
}

impl WorkspaceTreeArtifact {
    pub fn resolved_artifact(&self) -> ResolvedArtifact {
        ResolvedArtifact::new(self.artifact_id, self.path.clone(), self.entry)
    }
}

/// One complete, authority-bound workspace tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceTreeSnapshot {
    pub schema: u32,
    pub binding: WorkspaceSnapshotBinding,
    /// Canonically ordered by stable artifact identity.
    pub artifacts: Vec<WorkspaceTreeArtifact>,
}

impl WorkspaceTreeSnapshot {
    /// Construct a canonical snapshot and validate its authority binding.
    pub fn new(
        binding: WorkspaceSnapshotBinding,
        mut artifacts: Vec<WorkspaceTreeArtifact>,
    ) -> Result<Self> {
        artifacts.sort_by_key(|artifact| artifact.artifact_id);
        let snapshot = Self {
            schema: WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION,
            binding,
            artifacts,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validate the complete wire document and return its exact resolved tree.
    pub fn validate(&self) -> Result<ResolvedTree> {
        if self.schema != WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported workspace tree snapshot version {}; expected {}",
                self.schema, WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION
            )));
        }
        self.binding.validate()?;

        for pair in self.artifacts.windows(2) {
            if pair[0].artifact_id >= pair[1].artifact_id {
                return Err(ModelError::InvalidOperation(
                    "workspace tree artifacts are not in canonical unique identity order"
                        .to_string(),
                ));
            }
        }
        for artifact in &self.artifacts {
            if matches!(artifact.entry, TreeEntry::Gitlink { .. }) && artifact.size != 0 {
                return Err(ModelError::InvalidOperation(format!(
                    "gitlink {} must advertise zero bytes, not {}",
                    artifact.path, artifact.size
                )));
            }
        }
        reject_file_directory_collisions(&self.artifacts)?;

        let tree = ResolvedTree::from_artifacts(
            self.artifacts
                .iter()
                .map(WorkspaceTreeArtifact::resolved_artifact),
        )
        .map_err(|error| {
            ModelError::InvalidOperation(format!("invalid workspace tree snapshot: {error}"))
        })?;
        let computed = compute_resolved_tree_hash(&tree)?;
        if computed != self.binding.workspace_tree_hash {
            return Err(ModelError::InvalidOperation(format!(
                "workspace tree hash {} recomputes to {}",
                self.binding.workspace_tree_hash, computed
            )));
        }
        Ok(tree)
    }

    /// Canonical strong identity for HTTP ETag and cache succession.
    pub fn identity(&self) -> Result<Hash256> {
        self.validate()?;
        let payload = canonical_json_bytes(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-workspace-tree-snapshot-v4\0");
        hasher.update(
            u64::try_from(payload.len())
                .map_err(|_| {
                    ModelError::InvalidOperation("workspace tree snapshot exceeds u64".to_string())
                })?
                .to_le_bytes(),
        );
        hasher.update(payload);
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(Hash256::from_bytes(bytes))
    }
}

fn reject_file_directory_collisions(artifacts: &[WorkspaceTreeArtifact]) -> Result<()> {
    let paths: BTreeSet<Vec<u8>> = artifacts
        .iter()
        .map(|artifact| artifact.path.as_bytes().to_vec())
        .collect();
    for path in &paths {
        for separator in path
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'/').then_some(index))
        {
            if paths.contains(&path[..separator]) {
                return Err(ModelError::InvalidOperation(format!(
                    "workspace tree contains a file/directory collision at {}",
                    RepoPath::from_bytes(path[..separator].to_vec())
                        .expect("a non-empty path prefix is canonical")
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdmissionPolicyStamp, AuthorityRoot, EffectiveAdmissionPolicyStamp, GitObjectId,
        LocalOverlayHash, LocalOverlayStamp, RefName, RefTarget, RepositoryId, RootBundle,
        SemanticChangeId, WorkspaceHead, WorkspaceId, REPOSITORY_ROOT_SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn root(byte: u8) -> AuthorityRoot {
        AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            Hash256::from_bytes([byte; 32]),
        )
    }

    fn binding(tree_hash: Hash256) -> WorkspaceSnapshotBinding {
        WorkspaceSnapshotBinding {
            repository_id: RepositoryId::new("snapshot-test").unwrap(),
            workspace_id: WorkspaceId::from_uuid(Uuid::from_u128(1)),
            workspace_head: WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap(),
            },
            base_target: Some(RefTarget::change(SemanticChangeId::from_hash(
                Hash256::from_bytes([0x10; 32]),
            ))),
            base_tree_hash: Some(tree_hash),
            workspace_tree_hash: tree_hash,
            workspace_semantic_overlay_hash: crate::WorkspaceSemanticOverlay::default()
                .identity_hash()
                .unwrap(),
            roots: RootBundle {
                version: REPOSITORY_ROOT_SCHEMA_VERSION,
                generation: 4,
                history: root(1),
                ref_state: root(2),
                ref_log: root(3),
                collaboration: root(4),
                replication: root(5),
                local_state: root(6),
            },
            workspace_generation: 2,
            admission_policy: EffectiveAdmissionPolicyStamp {
                shared: AdmissionPolicyStamp {
                    hash: crate::AdmissionPolicyHash(Hash256::from_bytes([0x20; 32])),
                    generation: 1,
                },
                local: LocalOverlayStamp {
                    hash: LocalOverlayHash(Hash256::from_bytes([0x21; 32])),
                    generation: 1,
                },
            },
        }
    }

    fn artifact(id: u128, path: &[u8], entry: TreeEntry, size: u64) -> WorkspaceTreeArtifact {
        WorkspaceTreeArtifact {
            artifact_id: ArtifactId(Uuid::from_u128(id)),
            path: RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry,
            size,
            mtime: 1_700_000_000 + id as u64,
        }
    }

    fn snapshot(artifacts: Vec<WorkspaceTreeArtifact>) -> WorkspaceTreeSnapshot {
        let tree = ResolvedTree::from_artifacts(
            artifacts
                .iter()
                .map(WorkspaceTreeArtifact::resolved_artifact),
        )
        .unwrap();
        WorkspaceTreeSnapshot::new(
            binding(compute_resolved_tree_hash(&tree).unwrap()),
            artifacts,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_binds_arbitrary_artifacts_and_metadata() {
        let snapshot = snapshot(vec![
            artifact(
                2,
                b"logs/raw-\xff.bin",
                TreeEntry::blob(Hash256::from_bytes([0x32; 32]), false),
                7,
            ),
            artifact(
                1,
                b"compose.yaml",
                TreeEntry::blob(Hash256::from_bytes([0x31; 32]), true),
                11,
            ),
        ]);

        assert_eq!(
            snapshot
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id)
                .collect::<Vec<_>>(),
            vec![
                ArtifactId(Uuid::from_u128(1)),
                ArtifactId(Uuid::from_u128(2))
            ]
        );
        assert_eq!(snapshot.validate().unwrap().len(), 2);

        let identity = snapshot.identity().unwrap();
        let mut changed_metadata = snapshot.clone();
        changed_metadata.artifacts[0].mtime += 1;
        assert_ne!(changed_metadata.identity().unwrap(), identity);

        let mut changed_binding = snapshot;
        changed_binding.binding.roots.generation += 1;
        assert_ne!(changed_binding.identity().unwrap(), identity);
    }

    #[test]
    fn malformed_tree_documents_fail_closed() {
        let mut wrong_hash = snapshot(vec![artifact(
            1,
            b"Dockerfile",
            TreeEntry::blob(Hash256::from_bytes([0x41; 32]), false),
            4,
        )]);
        wrong_hash.binding.workspace_tree_hash = Hash256::from_bytes([0xff; 32]);
        assert!(wrong_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("recomputes"));

        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                ArtifactId(Uuid::from_u128(1)),
                RepoPath::from_utf8("src").unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x42; 32]), false),
            ),
            ResolvedArtifact::new(
                ArtifactId(Uuid::from_u128(2)),
                RepoPath::from_utf8("src/main.rs").unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false),
            ),
        ])
        .unwrap();
        let collision = WorkspaceTreeSnapshot {
            schema: WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION,
            binding: binding(compute_resolved_tree_hash(&tree).unwrap()),
            artifacts: vec![
                artifact(
                    1,
                    b"src",
                    TreeEntry::blob(Hash256::from_bytes([0x42; 32]), false),
                    1,
                ),
                artifact(
                    2,
                    b"src/main.rs",
                    TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false),
                    1,
                ),
            ],
        };
        assert!(collision
            .validate()
            .unwrap_err()
            .to_string()
            .contains("file/directory collision"));

        let gitlink = snapshot(vec![artifact(
            1,
            b"vendor/submodule",
            TreeEntry::gitlink(GitObjectId::sha1([0x44; 20])),
            0,
        )]);
        let mut nonzero_gitlink = gitlink;
        nonzero_gitlink.artifacts[0].size = 1;
        assert!(nonzero_gitlink
            .validate()
            .unwrap_err()
            .to_string()
            .contains("zero bytes"));
    }

    #[test]
    fn canonical_order_and_unknown_fields_are_rejected() {
        let snapshot = snapshot(vec![
            artifact(
                1,
                b"a",
                TreeEntry::blob(Hash256::from_bytes([0x51; 32]), false),
                1,
            ),
            artifact(
                2,
                b"b",
                TreeEntry::blob(Hash256::from_bytes([0x52; 32]), false),
                1,
            ),
        ]);
        let mut reversed = snapshot.clone();
        reversed.artifacts.reverse();
        assert!(reversed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("canonical"));

        let mut legacy = snapshot.clone();
        legacy.schema = 3;
        assert!(legacy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("expected 4"));

        let mut encoded = serde_json::to_value(snapshot).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<WorkspaceTreeSnapshot>(encoded).is_err());
    }
}
