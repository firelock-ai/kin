// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared codec for existing parser occurrence provenance certificates.
//! This validates their original evidence binding, never the current truth of a call.

use crate::{GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Persisted parser tiers. The indexer's resolution ladder is checked against
/// this exact set so moving the codec changes neither accepted proof nor bytes.
pub const PARSER_CONFIDENCES: &[f32] = &[1.0, 0.95, 0.85, 0.86, 0.9, 0.8, 0.7, 0.6, 0.3, 0.2];

pub const OCCURRENCE_RULE: &str = "parser_occurrence_resolution_v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub relation_id: RelationId,
    pub src: GraphNodeId,
    pub dst: GraphNodeId,
    pub kind: RelationKind,
    pub evidence_sha256: String,
    pub confidence: f32,
    pub origin: RelationOrigin,
}

pub fn reserved(record: &RelationEvidence) -> bool {
    record
        .parser_rule
        .as_deref()
        .is_some_and(|rule| rule.starts_with("parser_occurrence_resolution_"))
}

pub fn evidence_digest(record: &RelationEvidence) -> String {
    let mut record = record.clone();
    // Multiplicity is merged separately. Normalize exactly as the linker does.
    record.occurrence_count = 1;
    if let Some(shape) = &mut record.call_shape {
        shape.keywords.sort();
        shape.keywords.dedup();
    }
    hex::encode(Sha256::digest(
        serde_json::to_vec(&record).expect("evidence serializes"),
    ))
}

#[allow(clippy::result_unit_err)]
pub fn validated_proofs(relation: &Relation) -> Result<BTreeMap<String, Proof>, ()> {
    let originals: BTreeSet<_> = relation
        .evidence
        .iter()
        .filter(|record| record.source_span.is_some() && !reserved(record))
        .map(evidence_digest)
        .collect();
    let mut proofs = BTreeMap::new();
    for record in relation.evidence.iter().filter(|record| reserved(record)) {
        if record.parser_rule.as_deref() != Some(OCCURRENCE_RULE)
            || record.source_span.is_some()
            || record.source_path.is_some()
            || record.resolved_path.is_some()
            || record.call_shape.is_some()
            || record.occurrence_count != 0
        {
            return Err(());
        }
        let proof: Proof =
            serde_json::from_str(record.token.as_deref().ok_or(())?).map_err(|_| ())?;
        if relation.kind != RelationKind::Calls
            || !matches!(
                relation.origin,
                RelationOrigin::Parsed | RelationOrigin::Inferred
            )
            || proof.relation_id != relation.id
            || proof.src != relation.src
            || proof.dst != relation.dst
            || proof.kind != relation.kind
            || !proof.confidence.is_finite()
            || !(0.0..=1.0).contains(&proof.confidence)
            || !PARSER_CONFIDENCES
                .iter()
                .any(|tier| tier.to_bits() == proof.confidence.to_bits())
            || proof.origin
                != if proof.confidence >= 1.0 {
                    RelationOrigin::Parsed
                } else {
                    RelationOrigin::Inferred
                }
            || !originals.contains(&proof.evidence_sha256)
        {
            return Err(());
        }
        if let Some(previous) = proofs.insert(proof.evidence_sha256.clone(), proof.clone()) {
            if previous != proof {
                return Err(());
            }
        }
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_certificate_wire_bytes_remain_the_original_codec() {
        let uuid = uuid::Uuid::from_u128(1);
        let proof = Proof {
            relation_id: RelationId(uuid),
            src: GraphNodeId::Entity(crate::EntityId(uuid)),
            dst: GraphNodeId::Entity(crate::EntityId(uuid::Uuid::from_u128(2))),
            kind: RelationKind::Calls,
            evidence_sha256: "0123456789abcdef".into(),
            confidence: 0.3,
            origin: RelationOrigin::Inferred,
        };
        let encoded = r#"{"relation_id":"00000000-0000-0000-0000-000000000001","src":{"Entity":"00000000-0000-0000-0000-000000000001"},"dst":{"Entity":"00000000-0000-0000-0000-000000000002"},"kind":"Calls","evidence_sha256":"0123456789abcdef","confidence":0.3,"origin":"Inferred"}"#;
        assert_eq!(serde_json::to_string(&proof).unwrap(), encoded);
        assert_eq!(serde_json::from_str::<Proof>(encoded).unwrap(), proof);
    }
}
