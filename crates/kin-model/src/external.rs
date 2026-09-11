// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact identities and payload descriptors for external VCS objects.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{
    GitObjectId, Hash256, ModelError, RepositoryId, Result, SemanticChange, SemanticChangeId,
};

/// The object type that participates in Git's object header and object ID.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExternalObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ExternalObjectKind {
    pub const fn git_header(self) -> &'static [u8] {
        match self {
            Self::Commit => b"commit",
            Self::Tree => b"tree",
            Self::Blob => b"blob",
            Self::Tag => b"tag",
        }
    }
}

/// Typed identity of one object in an external Git object database.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ExternalObjectId {
    pub kind: ExternalObjectKind,
    pub oid: GitObjectId,
}

impl ExternalObjectId {
    pub const fn new(kind: ExternalObjectKind, oid: GitObjectId) -> Self {
        Self { kind, oid }
    }
}

/// Exact raw-body descriptor for an external object.
///
/// `body_hash` addresses the body in Kin's blob CAS. `oid` is independently
/// verified over Git's `"<kind> <len>\0<body>"` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalObjectRecord {
    pub object: ExternalObjectId,
    pub body_hash: Hash256,
    pub body_len: u64,
}

impl ExternalObjectRecord {
    pub fn from_raw(kind: ExternalObjectKind, oid: GitObjectId, body: &[u8]) -> Result<Self> {
        let record = Self {
            object: ExternalObjectId::new(kind, oid),
            body_hash: sha256(body),
            body_len: u64::try_from(body.len()).map_err(|_| {
                ModelError::InvalidOperation("external object body exceeds u64".to_string())
            })?,
        };
        record.validate_raw(body)?;
        Ok(record)
    }

    pub fn validate_raw(&self, body: &[u8]) -> Result<()> {
        let actual_len = u64::try_from(body.len()).map_err(|_| {
            ModelError::InvalidOperation("external object body exceeds u64".to_string())
        })?;
        if actual_len != self.body_len {
            return Err(ModelError::InvalidOperation(format!(
                "external object {} declares length {} but has {} bytes",
                self.object.oid, self.body_len, actual_len
            )));
        }
        let actual_body_hash = sha256(body);
        if actual_body_hash != self.body_hash {
            return Err(ModelError::InvalidOperation(format!(
                "external object {} body hash mismatch",
                self.object.oid
            )));
        }
        let computed = compute_git_object_id(self.object.kind, &self.object.oid, body)?;
        if computed != self.object.oid {
            return Err(ModelError::InvalidOperation(format!(
                "external object {} recomputes to {}",
                self.object.oid, computed
            )));
        }
        Ok(())
    }
}

/// Repository-scoped mapping from an external commit OID to final Kin truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalChangeAlias {
    pub repository_id: RepositoryId,
    pub oid: GitObjectId,
    pub change_id: SemanticChangeId,
}

impl ExternalChangeAlias {
    pub fn new(repository_id: RepositoryId, oid: GitObjectId, change_id: SemanticChangeId) -> Self {
        Self {
            repository_id,
            oid,
            change_id,
        }
    }

    /// Check an attempted binding against the already-authoritative value.
    ///
    /// Replaying an identical binding is idempotent. Rebinding an OID to a
    /// different change is never allowed.
    pub fn validate_binding(&self, existing: Option<SemanticChangeId>) -> Result<()> {
        if let Some(existing) = existing {
            if existing != self.change_id {
                return Err(ModelError::Conflict(format!(
                    "external commit {} in repository {} is already bound to {}, not {}",
                    self.oid, self.repository_id, existing, self.change_id
                )));
            }
        }
        Ok(())
    }

    /// Validate this alias against a change included in the same transaction.
    pub fn validate_change(&self, change: &SemanticChange) -> Result<()> {
        if change.id != self.change_id {
            return Err(ModelError::InvalidOperation(format!(
                "external alias {} targets change {}, not supplied change {}",
                self.oid, self.change_id, change.id
            )));
        }
        match change.origin {
            crate::ChangeOrigin::GitCommit { oid } if oid == self.oid => {}
            crate::ChangeOrigin::GitCommit { oid } => {
                return Err(ModelError::InvalidOperation(format!(
                    "Git-origin change {} names {}, but its alias names {}",
                    change.id, oid, self.oid
                )));
            }
            crate::ChangeOrigin::Native => {
                return Err(ModelError::InvalidOperation(format!(
                    "external alias {} cannot target native change {}",
                    self.oid, change.id
                )));
            }
        }
        Ok(())
    }
}

fn sha256(body: &[u8]) -> Hash256 {
    let digest = Sha256::digest(body);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Hash256::from_bytes(bytes)
}

fn compute_git_object_id(
    kind: ExternalObjectKind,
    algorithm: &GitObjectId,
    body: &[u8],
) -> Result<GitObjectId> {
    let mut envelope = Vec::new();
    envelope.extend_from_slice(kind.git_header());
    envelope.push(b' ');
    envelope.extend_from_slice(body.len().to_string().as_bytes());
    envelope.push(0);
    envelope.extend_from_slice(body);

    Ok(match algorithm {
        GitObjectId::Sha1(_) => {
            let digest = Sha1::digest(&envelope);
            let mut bytes = [0_u8; 20];
            bytes.copy_from_slice(&digest);
            GitObjectId::sha1(bytes)
        }
        GitObjectId::Sha256(_) => {
            let digest = Sha256::digest(&envelope);
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(&digest);
            GitObjectId::sha256(bytes)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_git_object_validation_is_kind_and_body_exact() {
        // `echo -n test | git hash-object --stdin`
        let oid = GitObjectId::sha1(
            hex::decode("30d74d258442c7c65512eafab474568dd706c430")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let record =
            ExternalObjectRecord::from_raw(ExternalObjectKind::Blob, oid, b"test").unwrap();
        record.validate_raw(b"test").unwrap();
        assert!(record.validate_raw(b"Test").is_err());
        assert!(ExternalObjectRecord::from_raw(ExternalObjectKind::Tree, oid, b"test").is_err());
    }

    #[test]
    fn alias_binding_is_idempotent_but_never_rebinds() {
        let alias = ExternalChangeAlias::new(
            RepositoryId::new("repo").unwrap(),
            GitObjectId::sha1([0x11; 20]),
            SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32])),
        );
        alias.validate_binding(None).unwrap();
        alias.validate_binding(Some(alias.change_id)).unwrap();
        assert!(alias
            .validate_binding(Some(SemanticChangeId::from_hash(Hash256::from_bytes(
                [0x33; 32]
            ))))
            .is_err());
    }
}
