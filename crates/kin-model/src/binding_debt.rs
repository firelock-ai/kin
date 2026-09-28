// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical JSON representation of source-owned local-binding obligations.
//!
//! The payload lives in a relation evidence token. These types are never
//! nested positionally in snapshot, delta or operation records.

use crate::{
    ArtifactId, FilePathId, GraphNodeId, Hash256, Relation, RelationEvidence, RelationId,
    RelationKind, RelationOrigin,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LOCAL_BINDING_DEBT_V1: &str = "local_binding_debt_v1";
pub const LOCAL_BINDING_DEBT_V2: &str = "local_binding_debt_v2";

/// Includes unknown versions so claimed binding evidence cannot silently become
/// an ordinary relation when its version is unsupported or malformed.
pub fn claims_local_binding_debt(relation: &Relation) -> bool {
    relation.evidence.iter().any(|e| {
        e.parser_rule
            .as_deref()
            .is_some_and(|rule| rule.starts_with("local_binding_debt_"))
    })
}
const MAX_DEBT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindingObligation {
    pub retired_relation: Relation,
    pub source_name: String,
    /// Immutable body whose real relation established this prior local binding.
    pub source_digest: Hash256,
    /// Original occurrence location. V1 omits this because its current and
    /// original locations coincide; every V2 obligation carries it explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_source_file: Option<FilePathId>,
    pub target_artifact: ArtifactId,
    pub target_file: FilePathId,
    pub target_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindingDebt {
    pub source_file: FilePathId,
    /// Latest complete source observation that explicitly retained these debts.
    pub observed_source_digest: Hash256,
    pub obligations: Vec<LocalBindingObligation>,
}

pub fn local_binding_debt_id(artifact: ArtifactId) -> RelationId {
    let mut digest = Sha256::new();
    digest.update(b"kin-local-binding-debt-v1:");
    digest.update(artifact.0.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    RelationId::from_bytes(bytes)
}

pub fn build_local_binding_debt(
    artifact: ArtifactId,
    mut debt: LocalBindingDebt,
) -> Result<Relation, String> {
    if debt.source_file.0.is_empty() || debt.obligations.is_empty() {
        return Err("binding debt requires a source and at least one obligation".into());
    }
    let explicit_prior_locations = debt
        .obligations
        .iter()
        .any(|o| o.prior_source_file.is_some());
    if explicit_prior_locations {
        for obligation in &mut debt.obligations {
            obligation
                .prior_source_file
                .get_or_insert_with(|| debt.source_file.clone());
        }
    }
    debt.obligations
        .sort_by_key(|obligation| obligation.retired_relation.id);
    let mut previous = None;
    for obligation in &debt.obligations {
        let relation = &obligation.retired_relation;
        let prior_file = obligation
            .prior_source_file
            .as_ref()
            .unwrap_or(&debt.source_file);
        if prior_file.0.is_empty()
            || previous == Some(relation.id)
            || relation.src.as_entity().is_none()
            || relation.dst.as_entity().is_none()
            || relation.src == relation.dst
            || obligation.source_name.is_empty()
            || obligation.target_name.is_empty()
            || obligation.target_file.0.is_empty()
            || obligation.target_file == *prior_file
            || obligation.target_artifact == artifact
            || relation
                .evidence
                .iter()
                .filter_map(|e| e.source_span.as_ref())
                .any(|span| span.file != *prior_file || span.start_byte >= span.end_byte)
        {
            return Err(
                "binding debt contains an invalid or duplicated prior local binding".into(),
            );
        }
        previous = Some(relation.id);
    }
    let token = serde_json::to_string(&debt).map_err(|error| error.to_string())?;
    if token.len() > MAX_DEBT_BYTES {
        return Err("binding debt exceeds its bounded representation".into());
    }
    let node = GraphNodeId::Artifact(artifact);
    Ok(Relation {
        id: local_binding_debt_id(artifact),
        kind: RelationKind::DependsOn,
        src: node,
        dst: node,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: vec![RelationEvidence {
            parser_rule: Some(
                if explicit_prior_locations {
                    LOCAL_BINDING_DEBT_V2
                } else {
                    LOCAL_BINDING_DEBT_V1
                }
                .into(),
            ),
            source_path: Some(debt.source_file.0),
            token: Some(token),
            occurrence_count: 1,
            ..RelationEvidence::default()
        }],
    })
}

/// Decode only the exact owned representation; its reserved ID cannot hide a
/// missing marker, and a marker cannot enroll a different ID or endpoint.
pub fn decode_local_binding_debt(
    file: &FilePathId,
    artifact: ArtifactId,
    relation: &Relation,
) -> Result<Option<LocalBindingDebt>, String> {
    let claims = claims_local_binding_debt(relation);
    if !claims && relation.id != local_binding_debt_id(artifact) {
        return Ok(None);
    }
    let [evidence] = relation.evidence.as_slice() else {
        return Err("malformed binding debt evidence".into());
    };
    let version = evidence.parser_rule.as_deref();
    if !matches!(version, Some(LOCAL_BINDING_DEBT_V1 | LOCAL_BINDING_DEBT_V2)) {
        return Err("unsupported binding debt version".into());
    }
    let token = evidence
        .token
        .as_deref()
        .filter(|token| token.len() <= MAX_DEBT_BYTES)
        .ok_or("missing or oversized binding debt payload")?;
    let debt: LocalBindingDebt =
        serde_json::from_str(token).map_err(|error| format!("malformed binding debt: {error}"))?;
    if debt
        .obligations
        .iter()
        .any(|o| o.prior_source_file.is_some() != (version == Some(LOCAL_BINDING_DEBT_V2)))
    {
        return Err("binding debt version and prior source locations disagree".into());
    }
    if &debt.source_file != file {
        return Err("binding debt source path mismatch".into());
    }
    let mut expected = build_local_binding_debt(artifact, debt.clone())?;
    expected.created_in = relation.created_in;
    if expected != *relation {
        return Err("binding debt is not the canonical owned payload".into());
    }
    Ok(Some(debt))
}
