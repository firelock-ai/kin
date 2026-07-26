// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Byte-exact repository refs and local workspace-head state.

use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, fmt};

use crate::{ExternalObjectId, ModelError, RepositoryId, Result, SemanticChangeId};

/// A full, byte-exact Git-compatible reference name.
///
/// UTF-8 is a display convenience only. Repository refs use full names such as
/// `refs/heads/main` and `refs/tags/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefName(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefNameError {
    #[error("reference name must not be empty")]
    Empty,
    #[error("repository reference must begin with 'refs/'")]
    NotFullyQualified,
    #[error("reference name contains a forbidden byte")]
    ForbiddenByte,
    #[error("reference name contains an empty component")]
    EmptyComponent,
    #[error("reference name contains a forbidden component")]
    ForbiddenComponent,
    #[error("reference name contains a forbidden sequence")]
    ForbiddenSequence,
    #[error("reference name hex encoding is not canonical lowercase hex")]
    NonCanonicalHex,
    #[error("reference name hex encoding is invalid: {0}")]
    InvalidHex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RefNameWire {
    bytes_hex: String,
}

impl RefName {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> std::result::Result<Self, RefNameError> {
        let bytes = bytes.into();
        Self::validate(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_utf8(value: impl Into<String>) -> std::result::Result<Self, RefNameError> {
        Self::from_bytes(value.into().into_bytes())
    }

    pub fn branch(value: impl AsRef<[u8]>) -> std::result::Result<Self, RefNameError> {
        let mut bytes = b"refs/heads/".to_vec();
        bytes.extend_from_slice(value.as_ref());
        Self::from_bytes(bytes)
    }

    pub fn tag(value: impl AsRef<[u8]>) -> std::result::Result<Self, RefNameError> {
        let mut bytes = b"refs/tags/".to_vec();
        bytes.extend_from_slice(value.as_ref());
        Self::from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn is_branch(&self) -> bool {
        self.0.starts_with(b"refs/heads/")
    }

    pub fn is_tag(&self) -> bool {
        self.0.starts_with(b"refs/tags/")
    }

    fn validate(bytes: &[u8]) -> std::result::Result<(), RefNameError> {
        if bytes.is_empty() {
            return Err(RefNameError::Empty);
        }
        if !bytes.starts_with(b"refs/") || bytes.len() == b"refs/".len() {
            return Err(RefNameError::NotFullyQualified);
        }
        if bytes.iter().any(|byte| {
            *byte < 0x20
                || *byte == 0x7f
                || matches!(
                    *byte,
                    b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'
                )
        }) {
            return Err(RefNameError::ForbiddenByte);
        }
        if bytes.ends_with(b"/") || bytes.split(|byte| *byte == b'/').any(<[u8]>::is_empty) {
            return Err(RefNameError::EmptyComponent);
        }
        if bytes == b"@" || bytes.ends_with(b".") || bytes.windows(2).any(|pair| pair == b"..") {
            return Err(RefNameError::ForbiddenSequence);
        }
        if bytes.windows(2).any(|pair| pair == b"@{") {
            return Err(RefNameError::ForbiddenSequence);
        }
        if bytes
            .split(|byte| *byte == b'/')
            .any(|component| component.starts_with(b".") || component.ends_with(b".lock"))
        {
            return Err(RefNameError::ForbiddenComponent);
        }
        Ok(())
    }

    fn wire(&self) -> RefNameWire {
        RefNameWire {
            bytes_hex: hex::encode(&self.0),
        }
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = self.as_utf8() {
            return formatter.write_str(value);
        }
        for byte in &self.0 {
            match byte {
                b'\\' => formatter.write_str("\\\\")?,
                0x20..=0x7e => write!(formatter, "{}", char::from(*byte))?,
                _ => write!(formatter, "\\x{byte:02x}")?,
            }
        }
        Ok(())
    }
}

impl Serialize for RefName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RefName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RefNameWire::deserialize(deserializer)?;
        let bytes = hex::decode(&wire.bytes_hex)
            .map_err(|error| D::Error::custom(RefNameError::InvalidHex(error.to_string())))?;
        if hex::encode(&bytes) != wire.bytes_hex {
            return Err(D::Error::custom(RefNameError::NonCanonicalHex));
        }
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

impl JsonSchema for RefName {
    fn schema_name() -> String {
        "RefName".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RefNameWire::json_schema(generator)
    }
}

/// Exact target of a repository ref.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefTarget {
    Change { change_id: SemanticChangeId },
    ExternalObject { object: ExternalObjectId },
    Symbolic { target: RefName },
}

impl RefTarget {
    pub const fn change(change_id: SemanticChangeId) -> Self {
        Self::Change { change_id }
    }

    pub const fn external_object(object: ExternalObjectId) -> Self {
        Self::ExternalObject { object }
    }

    pub fn symbolic(target: RefName) -> Self {
        Self::Symbolic { target }
    }
}

/// One repository-scoped named ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRef {
    pub repository_id: RepositoryId,
    pub name: RefName,
    pub target: RefTarget,
}

/// Replicated ref state, including the repository's explicit default ref.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRefState {
    pub refs: Vec<RepositoryRef>,
    pub default_ref: Option<RefName>,
}

impl RepositoryRefState {
    pub fn validate(&self) -> Result<()> {
        let mut repository_id = None;
        let mut names = BTreeSet::new();
        for repository_ref in &self.refs {
            if let Some(expected) = &repository_id {
                if expected != &repository_ref.repository_id {
                    return Err(ModelError::InvalidOperation(
                        "repository ref state mixes repository identities".to_string(),
                    ));
                }
            } else {
                repository_id = Some(repository_ref.repository_id.clone());
            }
            if !names.insert(repository_ref.name.clone()) {
                return Err(ModelError::InvalidOperation(format!(
                    "repository ref state repeats {}",
                    repository_ref.name
                )));
            }
        }
        // The default ref is intentionally allowed to be unborn. Its byte
        // identity remains authoritative before the first target exists.
        Ok(())
    }
}

/// Local HEAD for one materialized workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceHead {
    Symbolic { target: RefName },
    Detached { target: RefTarget },
}

/// Exact compare-and-swap expectation for a ref mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefExpectation {
    MustNotExist,
    MustEqual { target: RefTarget },
}

/// Ancestry policy for a ref mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefUpdatePolicy {
    FastForwardOnly,
    ForceWithLease,
}

/// One exact create, update, or delete inside a multi-ref transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefMutation {
    pub name: RefName,
    pub expected: RefExpectation,
    /// `None` deletes the ref.
    pub new_target: Option<RefTarget>,
    pub policy: RefUpdatePolicy,
}

impl RefMutation {
    pub fn validate(&self) -> Result<()> {
        if self.new_target.is_none() && self.policy != RefUpdatePolicy::ForceWithLease {
            return Err(ModelError::InvalidOperation(format!(
                "deleting {} requires force-with-lease",
                self.name
            )));
        }
        if matches!(self.expected, RefExpectation::MustNotExist) && self.new_target.is_none() {
            return Err(ModelError::InvalidOperation(format!(
                "cannot delete absent ref {}",
                self.name
            )));
        }
        if let Some(RefTarget::Symbolic { target }) = &self.new_target {
            if target == &self.name {
                return Err(ModelError::InvalidOperation(format!(
                    "ref {} cannot target itself symbolically",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

/// CAS expectation for the repository's optional default ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DefaultRefExpectation {
    MustBeUnset,
    MustEqual { name: RefName },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefaultRefMutation {
    pub expected: DefaultRefExpectation,
    pub new_default: Option<RefName>,
}

impl DefaultRefMutation {
    pub fn validate(&self) -> Result<()> {
        match (&self.expected, &self.new_default) {
            (DefaultRefExpectation::MustBeUnset, None) => Err(ModelError::InvalidOperation(
                "clearing an already-unset default ref is a no-op".to_string(),
            )),
            (DefaultRefExpectation::MustEqual { name }, Some(new)) if name == new => Err(
                ModelError::InvalidOperation(format!("default ref update to {new} is a no-op")),
            ),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_utf8_ref_name_roundtrips_exactly() {
        let name = RefName::from_bytes([
            b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', 0xff,
        ])
        .unwrap();
        let encoded = serde_json::to_vec(&name).unwrap();
        let decoded: RefName = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), name.as_bytes());
        assert!(decoded.as_utf8().is_none());
    }

    #[test]
    fn ref_name_rejects_git_forbidden_forms() {
        for value in [
            b"main".as_slice(),
            b"refs/heads/a..b",
            b"refs/heads/.hidden",
            b"refs/heads/a.lock",
            b"refs/heads/a@{b",
            b"refs/heads/a b",
        ] {
            assert!(RefName::from_bytes(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn deletion_requires_exact_lease_policy() {
        let mutation = RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual {
                target: RefTarget::change(SemanticChangeId::from_hash(crate::Hash256::from_bytes(
                    [0x11; 32],
                ))),
            },
            new_target: None,
            policy: RefUpdatePolicy::FastForwardOnly,
        };
        assert!(mutation.validate().is_err());
    }

    #[test]
    fn default_ref_may_remain_unborn() {
        let state = RepositoryRefState {
            refs: Vec::new(),
            default_ref: Some(RefName::branch(b"main").unwrap()),
        };
        state.validate().unwrap();
    }
}
