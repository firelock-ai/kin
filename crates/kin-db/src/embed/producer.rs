// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Actual producer provenance for vector embeddings.
//!
//! A producer is the backend that returned the vector, not the backend a caller
//! requested or configured. The distinction matters because hybrid dispatch,
//! memory guards, and OOM recovery can all move a batch after configuration has
//! been read.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

/// Runtime that actually returned an embedding vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingProducer {
    Cpu,
    Metal,
    Cuda,
    Remote,
    /// A current caller inserted raw vector bytes without producer evidence.
    ///
    /// This is deliberately distinct from [`VectorProducerProvenance::UnknownLegacy`]:
    /// `Unspecified` is an explicit fact about a current write, while
    /// `UnknownLegacy` means the older persisted format carried no field at all.
    Unspecified,
}

impl EmbeddingProducer {
    #[cfg(feature = "embeddings")]
    pub(crate) const fn cache_tag(self) -> u8 {
        match self {
            Self::Cpu => 1,
            Self::Metal => 2,
            Self::Cuda => 3,
            Self::Remote => 4,
            Self::Unspecified => 5,
        }
    }

    #[cfg(feature = "embeddings")]
    pub(crate) const fn from_cache_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Cpu),
            2 => Some(Self::Metal),
            3 => Some(Self::Cuda),
            4 => Some(Self::Remote),
            5 => Some(Self::Unspecified),
            _ => None,
        }
    }
}

/// Canonically ordered union of every actual producer represented by a batch
/// or vector index.
///
/// `BTreeSet` makes JSON and cache serialization deterministic without relying
/// on insertion order. The set is conservative for an index: removal does not
/// erase a producer, so persistence can over-restrict reuse but can never hide a
/// numerical backend that contributed bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EmbeddingProducerSet(BTreeSet<EmbeddingProducer>);

impl<'de> Deserialize<'de> for EmbeddingProducerSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<EmbeddingProducer>::deserialize(deserializer)?;
        let mut producers = BTreeSet::new();
        let mut previous = None;
        for producer in values {
            if previous.is_some_and(|prior| prior >= producer) {
                return Err(D::Error::custom(
                    "embedding producer entries must be unique and strictly canonical",
                ));
            }
            producers.insert(producer);
            previous = Some(producer);
        }
        Ok(Self(producers))
    }
}

impl EmbeddingProducerSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn singleton(producer: EmbeddingProducer) -> Self {
        Self(BTreeSet::from([producer]))
    }

    pub fn insert(&mut self, producer: EmbeddingProducer) -> bool {
        self.0.insert(producer)
    }

    pub fn extend(&mut self, other: &Self) {
        self.0.extend(other.0.iter().copied());
    }

    pub fn contains(&self, producer: EmbeddingProducer) -> bool {
        self.0.contains(&producer)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = EmbeddingProducer> + '_ {
        self.0.iter().copied()
    }

    /// Whether every producer in this set carries attributable runtime
    /// evidence suitable for hosted reuse.
    pub fn is_fully_attributed(&self) -> bool {
        !self.is_empty() && !self.contains(EmbeddingProducer::Unspecified)
    }

    pub fn is_subset(&self, allowed: &Self) -> bool {
        self.0.is_subset(&allowed.0)
    }
}

impl From<EmbeddingProducer> for EmbeddingProducerSet {
    fn from(value: EmbeddingProducer) -> Self {
        Self::singleton(value)
    }
}

impl IntoIterator for EmbeddingProducerSet {
    type Item = EmbeddingProducer;
    type IntoIter = std::collections::btree_set::IntoIter<EmbeddingProducer>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Provenance decoded from persisted vector bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorProducerProvenance {
    /// Current evidence with a canonical actual-producer set.
    Known(EmbeddingProducerSet),
    /// A pre-contract artifact that carried no actual-producer evidence.
    UnknownLegacy { metadata_version: Option<u32> },
    /// Bytes claim current evidence but are malformed, tampered, truncated, or
    /// otherwise incompatible with the current bounded producer contract.
    Incompatible { reason: String },
}

/// Public document-batch result carrying the vectors and the union of the
/// runtime producers that actually returned them.
#[derive(Debug, Clone, PartialEq)]
pub struct ProducedEmbeddingBatch {
    /// Vectors in the same order as the input batch.
    pub vectors: Vec<Vec<f32>>,
    /// Conservative union of the runtimes that actually returned these exact
    /// vectors. For `embed_query_batch_with_producers` this is query-time
    /// producer evidence, not the lineage of the stored index being queried.
    pub producers: EmbeddingProducerSet,
}

impl ProducedEmbeddingBatch {
    pub fn empty() -> Self {
        Self {
            vectors: Vec::new(),
            producers: EmbeddingProducerSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_set_serializes_canonically() {
        let mut first = EmbeddingProducerSet::new();
        first.insert(EmbeddingProducer::Metal);
        first.insert(EmbeddingProducer::Cpu);
        let mut second = EmbeddingProducerSet::new();
        second.insert(EmbeddingProducer::Cpu);
        second.insert(EmbeddingProducer::Metal);

        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert_eq!(
            rmp_serde::to_vec(&first).unwrap(),
            rmp_serde::to_vec(&second).unwrap()
        );
        assert_eq!(
            serde_json::from_slice::<EmbeddingProducerSet>(&serde_json::to_vec(&first).unwrap())
                .unwrap(),
            first
        );
    }

    #[test]
    fn producer_set_rejects_duplicate_and_descending_encodings() {
        assert!(serde_json::from_str::<EmbeddingProducerSet>(r#"["cpu","cpu"]"#).is_err());
        assert!(serde_json::from_str::<EmbeddingProducerSet>(r#"["metal","cpu"]"#).is_err());
        assert!(rmp_serde::from_slice::<EmbeddingProducerSet>(
            &rmp_serde::to_vec(&vec![EmbeddingProducer::Cpu, EmbeddingProducer::Cpu]).unwrap()
        )
        .is_err());
        assert!(rmp_serde::from_slice::<EmbeddingProducerSet>(
            &rmp_serde::to_vec(&vec![EmbeddingProducer::Metal, EmbeddingProducer::Cpu]).unwrap()
        )
        .is_err());
    }

    #[test]
    fn unspecified_is_current_but_not_hosted_attributable() {
        let set = EmbeddingProducerSet::singleton(EmbeddingProducer::Unspecified);
        assert!(!set.is_fully_attributed());
        assert_ne!(
            VectorProducerProvenance::Known(set),
            VectorProducerProvenance::UnknownLegacy {
                metadata_version: Some(3)
            }
        );
    }
}
