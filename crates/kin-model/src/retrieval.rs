// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ids::{ArtifactRevisionId, EntityId, EntityRevisionId, FilePathId};

const ARTIFACT_NAMESPACE: Uuid = Uuid::from_u128(0x91c11f2ce3d14f8b8a9f0fb8b1972b3a);

/// Deterministic ID for retrievable non-entity graph objects.
///
/// Artifact IDs are derived from graph-owned file paths so the same tracked
/// artifact produces the same retrieval ID across re-index and re-init.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ArtifactId(pub Uuid);

impl ArtifactId {
    /// Create a new graph-assigned artifact ID.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Deterministically derive an artifact ID from a graph-owned file path.
    /// DEPRECATED: Use graph-assigned IDs via the artifact index lookup.
    #[deprecated(note = "use graph-assigned ArtifactId via artifact_index lookup")]
    pub fn from_path(path: &str) -> Self {
        Self(Uuid::new_v5(&ARTIFACT_NAMESPACE, path.as_bytes()))
    }

    #[deprecated(note = "use graph-assigned ArtifactId via artifact_index lookup")]
    pub fn from_file_id(file_id: &FilePathId) -> Self {
        Self::from_path(&file_id.0)
    }
}

/// Unified key for the retrieval spine.
///
/// Admission rule:
/// - `Entity` admits parsed semantic entities already stored as graph truth.
/// - `Artifact` admits graph-owned non-entity file objects that already exist in
///   graph state (`ShallowTrackedFile`, `StructuredArtifact`, `OpaqueArtifact`)
///   and can contribute lexical, semantic, or file-projection evidence.
/// - `EntityRevision` admits deterministic content-addressed revisions of semantic entities.
/// - `ArtifactRevision` admits deterministic content-addressed revisions of files/artifacts.
/// - Raw filesystem paths, projection outputs, and storage-only records are not
///   admitted. Retrieval remains graph-first and projection-second.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum RetrievalKey {
    Entity(EntityId),
    Artifact(ArtifactId),
    EntityRevision(EntityRevisionId),
    ArtifactRevision(ArtifactRevisionId),
}

impl From<EntityId> for RetrievalKey {
    fn from(value: EntityId) -> Self {
        Self::Entity(value)
    }
}

impl From<ArtifactId> for RetrievalKey {
    fn from(value: ArtifactId) -> Self {
        Self::Artifact(value)
    }
}

impl From<EntityRevisionId> for RetrievalKey {
    fn from(value: EntityRevisionId) -> Self {
        Self::EntityRevision(value)
    }
}

impl From<ArtifactRevisionId> for RetrievalKey {
    fn from(value: ArtifactRevisionId) -> Self {
        Self::ArtifactRevision(value)
    }
}

impl kin_vector::VectorId for RetrievalKey {}

/// Reverse-map contract for display surfaces that need a file anchor.
pub trait RetrievalKeyFileResolver {
    fn file_path_for_retrieval_key(&self, key: RetrievalKey) -> Option<FilePathId>;
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::{ArtifactId, RetrievalKey};

    #[test]
    fn artifact_id_is_deterministic_for_same_path() {
        let left = ArtifactId::from_path("src/lib.rs");
        let right = ArtifactId::from_path("src/lib.rs");
        let other = ArtifactId::from_path("src/main.rs");

        assert_eq!(left, right);
        assert_ne!(left, other);
    }

    #[test]
    fn retrieval_key_roundtrips_through_json() {
        let key = RetrievalKey::Artifact(ArtifactId::from_path("Makefile"));
        let json = serde_json::to_string(&key).unwrap();
        let parsed: RetrievalKey = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, key);
    }

    #[test]
    fn retrieval_key_satisfies_search_and_vector_bounds() {
        fn assert_search_bounds<T>()
        where
            T: Copy
                + Eq
                + std::hash::Hash
                + Send
                + Sync
                + std::fmt::Debug
                + serde::Serialize
                + serde::de::DeserializeOwned
                + 'static,
        {
        }

        fn assert_vector_id<T: kin_vector::VectorId>() {}

        assert_search_bounds::<ArtifactId>();
        assert_search_bounds::<RetrievalKey>();
        assert_vector_id::<RetrievalKey>();
    }
}
