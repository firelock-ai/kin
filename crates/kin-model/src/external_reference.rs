// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persisted graph authority for symbols resolved outside the local repository.
//!
//! An external reference is created only after a resolver has produced a
//! canonical authority coordinate. Parser spelling such as a relative import,
//! manifest alias, or workspace-local path remains relation evidence until a
//! resolver can bind it. The resolver namespace owns the meaning of
//! `canonical_source` and `symbol`; this model preserves those opaque selectors
//! exactly and never case-folds, normalizes Unicode, or rewrites separators.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Hash256, ModelError, Result};

pub const EXTERNAL_REFERENCE_SCHEMA_VERSION: u32 = 1;

/// UUID-v5 namespace for resolved external-reference identities.
///
/// This immutable namespace is itself UUID-v5 derived from
/// `https://kin.dev/namespaces/external-reference-id/v1`. Changing it would
/// change every persisted external-reference ID.
pub const EXTERNAL_REFERENCE_ID_NAMESPACE_V1: Uuid =
    Uuid::from_u128(0x408e263f_b82c_5ecb_8e97_c9ea8f6c8380);

const EXTERNAL_REFERENCE_ID_DOMAIN_V1: &[u8] = b"kin.external-reference.id.v1\0";
const EXTERNAL_REFERENCE_RECORD_DOMAIN_V1: &[u8] = b"kin-external-reference-record-v1\0";
const MAX_RESOLUTION_NAMESPACE_BYTES: usize = 128;
const MAX_EXTERNAL_SELECTOR_BYTES: usize = 4096;

/// Stable identity of one resolver-issued external symbol coordinate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ExternalReferenceId(pub Uuid);

impl ExternalReferenceId {
    /// Derive an ID from an already resolved authority coordinate.
    ///
    /// The preimage is explicitly domain-separated and each component is
    /// u64-little-endian length-prefixed. This avoids delimiter collisions and
    /// makes field boundaries independent of selector content.
    pub fn from_resolved(
        resolution_namespace: &str,
        canonical_source: &str,
        symbol: &str,
    ) -> Result<Self> {
        validate_coordinate(resolution_namespace, canonical_source, symbol)?;

        let mut preimage = Vec::with_capacity(
            EXTERNAL_REFERENCE_ID_DOMAIN_V1.len()
                + resolution_namespace.len()
                + canonical_source.len()
                + symbol.len()
                + 24,
        );
        preimage.extend_from_slice(EXTERNAL_REFERENCE_ID_DOMAIN_V1);
        append_len_prefixed(&mut preimage, resolution_namespace.as_bytes())?;
        append_len_prefixed(&mut preimage, canonical_source.as_bytes())?;
        append_len_prefixed(&mut preimage, symbol.as_bytes())?;
        Ok(Self(Uuid::new_v5(
            &EXTERNAL_REFERENCE_ID_NAMESPACE_V1,
            &preimage,
        )))
    }
}

impl fmt::Display for ExternalReferenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Immutable, resolved endpoint for a symbol owned outside the local graph.
///
/// `resolution_namespace` identifies both the resolver and its normalization
/// contract. It is versioned so a change to that contract cannot silently
/// reinterpret existing coordinates. `canonical_source` and `symbol` are
/// resolver-issued opaque selectors, preserved byte-for-byte after validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalReference {
    pub schema_version: u32,
    pub id: ExternalReferenceId,
    pub resolution_namespace: String,
    pub canonical_source: String,
    pub symbol: String,
    pub hash: Hash256,
}

impl ExternalReference {
    /// Create a persisted reference from a resolver-issued canonical
    /// coordinate. Unresolved parser spelling must not enter this constructor.
    pub fn new_resolved(
        resolution_namespace: impl Into<String>,
        canonical_source: impl Into<String>,
        symbol: impl Into<String>,
    ) -> Result<Self> {
        let resolution_namespace = resolution_namespace.into();
        let canonical_source = canonical_source.into();
        let symbol = symbol.into();
        let id =
            ExternalReferenceId::from_resolved(&resolution_namespace, &canonical_source, &symbol)?;
        let hash = compute_record_hash(
            EXTERNAL_REFERENCE_SCHEMA_VERSION,
            id,
            &resolution_namespace,
            &canonical_source,
            &symbol,
        )?;

        Ok(Self {
            schema_version: EXTERNAL_REFERENCE_SCHEMA_VERSION,
            id,
            resolution_namespace,
            canonical_source,
            symbol,
            hash,
        })
    }

    /// Validate schema, coordinate identity, and immutable record content.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != EXTERNAL_REFERENCE_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported external-reference schema version {}",
                self.schema_version
            )));
        }
        let expected_id = ExternalReferenceId::from_resolved(
            &self.resolution_namespace,
            &self.canonical_source,
            &self.symbol,
        )?;
        if self.id != expected_id {
            return Err(ModelError::InvalidOperation(format!(
                "external reference {} declares identity that recomputes to {expected_id}",
                self.id
            )));
        }
        let expected_hash = compute_record_hash(
            self.schema_version,
            self.id,
            &self.resolution_namespace,
            &self.canonical_source,
            &self.symbol,
        )?;
        if self.hash != expected_hash {
            return Err(ModelError::InvalidOperation(format!(
                "external reference {} declares content hash {} that recomputes to {expected_hash}",
                self.id, self.hash
            )));
        }
        Ok(())
    }
}

/// Exact, self-inverting transitions of persisted external endpoints.
///
/// External references are immutable. A resolver coordinate change is an
/// explicit removal plus addition (with any affected relation modified in the
/// same transaction), never an in-place modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalReferenceDelta {
    Added { new: ExternalReference },
    Removed { old: ExternalReference },
}

impl ExternalReferenceDelta {
    pub fn target_id(&self) -> ExternalReferenceId {
        match self {
            Self::Added { new } => new.id,
            Self::Removed { old } => old.id,
        }
    }

    pub fn old_state(&self) -> Option<&ExternalReference> {
        match self {
            Self::Added { .. } => None,
            Self::Removed { old } => Some(old),
        }
    }

    pub fn new_state(&self) -> Option<&ExternalReference> {
        match self {
            Self::Added { new } => Some(new),
            Self::Removed { .. } => None,
        }
    }

    pub fn inverse(&self) -> Self {
        match self {
            Self::Added { new } => Self::Removed { old: new.clone() },
            Self::Removed { old } => Self::Added { new: old.clone() },
        }
    }
}

fn validate_coordinate(
    resolution_namespace: &str,
    canonical_source: &str,
    symbol: &str,
) -> Result<()> {
    validate_resolution_namespace(resolution_namespace)?;
    validate_selector("canonical source", canonical_source)?;
    validate_selector("symbol", symbol)?;
    Ok(())
}

fn validate_resolution_namespace(value: &str) -> Result<()> {
    validate_exact_text(
        "external-reference resolution namespace",
        value,
        MAX_RESOLUTION_NAMESPACE_BYTES,
    )?;

    let Some((base, version)) = value.rsplit_once("-v") else {
        return Err(ModelError::InvalidOperation(
            "external-reference resolution namespace must end in -v followed by a positive version"
                .to_string(),
        ));
    };
    let valid_base = base.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'0'..=b'9' => true,
        b'.' | b'_' | b'-' => index > 0,
        _ => false,
    });
    let valid_version = matches!(version.as_bytes(), [b'1'..=b'9', rest @ ..]
        if rest.iter().all(u8::is_ascii_digit));
    if base.is_empty() || !valid_base || !valid_version {
        return Err(ModelError::InvalidOperation(
            "external-reference resolution namespace must match \
             [a-z0-9][a-z0-9._-]*-v[1-9][0-9]*"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_selector(label: &str, value: &str) -> Result<()> {
    validate_exact_text(label, value, MAX_EXTERNAL_SELECTOR_BYTES)
}

fn validate_exact_text(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > max_bytes {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not exceed {max_bytes} bytes"
        )));
    }
    if value.trim() != value {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must already be trimmed"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

fn compute_record_hash(
    schema_version: u32,
    id: ExternalReferenceId,
    resolution_namespace: &str,
    canonical_source: &str,
    symbol: &str,
) -> Result<Hash256> {
    let mut hasher = Sha256::new();
    hasher.update(EXTERNAL_REFERENCE_RECORD_DOMAIN_V1);
    hasher.update(schema_version.to_le_bytes());
    append_len_prefixed_hash_field(&mut hasher, id.0.as_bytes())?;
    append_len_prefixed_hash_field(&mut hasher, resolution_namespace.as_bytes())?;
    append_len_prefixed_hash_field(&mut hasher, canonical_source.as_bytes())?;
    append_len_prefixed_hash_field(&mut hasher, symbol.as_bytes())?;
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(Hash256::from_bytes(bytes))
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| {
                ModelError::InvalidOperation(
                    "external-reference identity field exceeds u64".to_string(),
                )
            })?
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn append_len_prefixed_hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| {
                ModelError::InvalidOperation(
                    "external-reference record field exceeds u64".to_string(),
                )
            })?
            .to_le_bytes(),
    );
    hasher.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_identity_is_namespace_scoped_and_tuple_unambiguous() {
        let python =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let npm = ExternalReference::new_resolved("npm-package-v1", "requests", "get").unwrap();
        assert_ne!(python.id, npm.id);
        assert_ne!(python.hash, npm.hash);

        let left = ExternalReference::new_resolved("resolver-v1", "ab", "c").unwrap();
        let right = ExternalReference::new_resolved("resolver-v1", "a", "bc").unwrap();
        assert_ne!(left.id, right.id);
        assert_ne!(left.hash, right.hash);
    }

    #[test]
    fn resolved_identity_and_record_wire_have_pinned_fixtures() {
        assert_eq!(
            EXTERNAL_REFERENCE_ID_NAMESPACE_V1,
            Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                b"https://kin.dev/namespaces/external-reference-id/v1",
            )
        );
        assert_eq!(
            EXTERNAL_REFERENCE_ID_NAMESPACE_V1.to_string(),
            "408e263f-b82c-5ecb-8e97-c9ea8f6c8380"
        );

        let reference = ExternalReference::new_resolved(
            "python-module-v1",
            "pypi://requests@2.32.4",
            "requests.api.get",
        )
        .unwrap();
        assert_eq!(
            reference.id.to_string(),
            "a2fad390-2e57-52a2-a6a3-288da4e01f1e"
        );
        assert_eq!(
            reference.hash.to_string(),
            "6cf053a83ef7c46d406cab7edd1eb5b56281358a022b558f3e482c9a43a4cdab"
        );
        assert_eq!(
            serde_json::to_string(&reference).unwrap(),
            "{\"schema_version\":1,\"id\":\"a2fad390-2e57-52a2-a6a3-288da4e01f1e\",\
             \"resolution_namespace\":\"python-module-v1\",\
             \"canonical_source\":\"pypi://requests@2.32.4\",\
             \"symbol\":\"requests.api.get\",\
             \"hash\":[108,240,83,168,62,247,196,109,64,108,171,126,221,30,181,181,\
             98,129,53,138,2,43,85,143,62,72,44,154,67,164,205,171]}"
        );
        let messagepack = rmp_serde::to_vec(&reference).unwrap();
        assert_eq!(
            hex::encode(&messagepack),
            "9601c410a2fad3902e5752a2a6a3288da4e01f1eb0707974686f6e2d6d6f64756c652d7631\
             b6707970693a2f2f726571756573747340322e33322e34b072657175657374732e6170692e676574\
             dc00206cccf053cca83eccf7ccc46d406cccab7eccdd1eccb5ccb562cc8135cc8a022b55cc8f\
             3e482ccc9a43cca4cccdccab"
        );
        assert_eq!(
            rmp_serde::from_slice::<ExternalReference>(&messagepack).unwrap(),
            reference
        );
    }

    #[test]
    fn selectors_are_exact_and_never_normalized() {
        let lowercase =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let uppercase =
            ExternalReference::new_resolved("python-module-v1", "Requests", "get").unwrap();
        let slash =
            ExternalReference::new_resolved("python-module-v1", "requests/", "get").unwrap();
        let composed = ExternalReference::new_resolved("python-module-v1", "café", "get").unwrap();
        let decomposed =
            ExternalReference::new_resolved("python-module-v1", "cafe\u{301}", "get").unwrap();

        assert_ne!(lowercase.id, uppercase.id);
        assert_ne!(lowercase.id, slash.id);
        assert_ne!(composed.id, decomposed.id);
        assert_eq!(slash.canonical_source, "requests/");
    }

    #[test]
    fn invalid_namespaces_and_non_exact_selectors_are_rejected() {
        for namespace in [
            "",
            "npm-package",
            "npm-package-v0",
            "npm-package-v01",
            "NPM-package-v1",
            "-npm-package-v1",
            "npm/package-v1",
            " npm-package-v1",
        ] {
            assert!(
                ExternalReference::new_resolved(namespace, "requests", "get").is_err(),
                "{namespace:?} must be rejected"
            );
        }

        for (source, symbol) in [
            ("", "get"),
            ("requests", ""),
            (" requests", "get"),
            ("requests ", "get"),
            ("requests", " get"),
            ("requests", "get "),
            ("requests\u{1f}", "get"),
            ("requests", "get\u{1f}"),
        ] {
            assert!(
                ExternalReference::new_resolved("python-module-v1", source, symbol).is_err(),
                "source={source:?}, symbol={symbol:?} must be rejected"
            );
        }

        let long_namespace = format!("{}-v1", "a".repeat(MAX_RESOLUTION_NAMESPACE_BYTES));
        assert!(ExternalReference::new_resolved(long_namespace, "requests", "get").is_err());
        assert!(ExternalReference::new_resolved(
            "python-module-v1",
            "a".repeat(MAX_EXTERNAL_SELECTOR_BYTES + 1),
            "get"
        )
        .is_err());
        assert!(ExternalReference::new_resolved(
            "python-module-v1",
            "requests",
            "a".repeat(MAX_EXTERNAL_SELECTOR_BYTES + 1)
        )
        .is_err());
    }

    #[test]
    fn record_validation_detects_identity_hash_and_schema_tampering() {
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        reference.validate().unwrap();
        let json = serde_json::to_vec(&reference).unwrap();
        let decoded_json: ExternalReference = serde_json::from_slice(&json).unwrap();
        decoded_json.validate().unwrap();
        assert_eq!(decoded_json, reference);
        let messagepack = rmp_serde::to_vec(&reference).unwrap();
        let decoded_messagepack: ExternalReference = rmp_serde::from_slice(&messagepack).unwrap();
        decoded_messagepack.validate().unwrap();
        assert_eq!(decoded_messagepack, reference);

        let mut identity_tampered = reference.clone();
        identity_tampered.id = ExternalReferenceId(Uuid::nil());
        assert!(identity_tampered.validate().is_err());

        let mut hash_tampered = reference.clone();
        hash_tampered.hash = Hash256::from_bytes([0xff; 32]);
        assert!(hash_tampered.validate().is_err());

        let mut schema_tampered = reference;
        schema_tampered.schema_version += 1;
        assert!(schema_tampered.validate().is_err());
    }

    #[test]
    fn deltas_are_exact_and_self_inverting() {
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let added = ExternalReferenceDelta::Added {
            new: reference.clone(),
        };
        assert_eq!(added.target_id(), reference.id);
        assert_eq!(added.old_state(), None);
        assert_eq!(added.new_state(), Some(&reference));
        assert_eq!(added.inverse().inverse(), added);
        let added_json = serde_json::to_value(&added).unwrap();
        assert_eq!(
            added_json,
            serde_json::json!({"operation": "added", "new": &reference})
        );

        let removed = added.inverse();
        assert_eq!(removed.old_state(), Some(&reference));
        assert_eq!(removed.new_state(), None);
        let removed_json = serde_json::to_value(&removed).unwrap();
        assert_eq!(
            removed_json,
            serde_json::json!({"operation": "removed", "old": &reference})
        );
    }
}
