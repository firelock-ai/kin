// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Definition evidence is independent of an entity's project/file role.

use serde::{Deserialize, Serialize};

use crate::{Entity, SourceSpan};

pub const ENTITY_DERIVATION_KEY: &str = "kin_entity_derivation";
pub const MEMBER_COVERAGE_KEY: &str = "kin_computed_member_coverage";
pub const DERIVED_MEMBER_CANDIDATE_RULE: &str = "derived_member_candidate_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationSchema {
    #[serde(rename = "kin.entity.derivation.v1")]
    V1,
}

/// A candidate member's real generating syntax, never its independent body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityDerivation {
    pub schema: DerivationSchema,
    pub generator: SourceSpan,
    pub assignment: SourceSpan,
    pub source_blob_hash: String,
    pub owner: String,
    pub member_key: String,
    pub rule: String,
    pub conditions: Vec<String>,
}

impl EntityDerivation {
    pub fn validate(&self) -> Result<(), String> {
        if self.source_blob_hash.len() != 64
            || !self
                .source_blob_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("derived member has no valid source-blob basis".into());
        }
        if self.generator.start_byte >= self.generator.end_byte
            || self.assignment.start_byte >= self.assignment.end_byte
            || self.assignment.file != self.generator.file
            || self.assignment.start_byte < self.generator.start_byte
            || self.assignment.end_byte > self.generator.end_byte
            || self.owner.is_empty()
            || self.member_key.is_empty()
            || self.conditions.is_empty()
        {
            return Err("derived member has invalid generator evidence".into());
        }
        Ok(())
    }
}

/// The only decoder for entity derivation authority. Errors remain untrusted.
pub fn entity_derivation(entity: &Entity) -> Result<Option<EntityDerivation>, String> {
    let Some(value) = entity.metadata.extra.get(ENTITY_DERIVATION_KEY) else {
        if entity.doc_summary.as_deref().is_some_and(|note| {
            note.starts_with("Derived from a loop over `") && note.contains("no literal `")
        }) {
            return Err("legacy derived member needs re-admission; its stored span is not an independent implementation".into());
        }
        return Ok(None);
    };
    let derivation: EntityDerivation = serde_json::from_value(value.clone())
        .map_err(|error| format!("unrecognized entity derivation: {error}"))?;
    derivation.validate()?;
    if entity.span.is_some() || entity.file_origin.as_ref() != Some(&derivation.generator.file) {
        return Err(
            "derived member must be spanless and associated with its generator file".into(),
        );
    }
    Ok(Some(derivation))
}

/// Validate the complete generator edge against the admitted artifact and bytes.
pub fn generator_relation_matches(
    entity: &Entity,
    relation: &crate::Relation,
    artifact: crate::ArtifactId,
    source_hash: &str,
) -> bool {
    let Ok(Some(derivation)) = entity_derivation(entity) else {
        return false;
    };
    relation.kind == crate::RelationKind::DerivedFrom
        && relation.src == crate::GraphNodeId::Entity(entity.id)
        && relation.dst == crate::GraphNodeId::Artifact(artifact)
        && derivation.source_blob_hash == source_hash
        && relation.evidence.iter().any(|e| {
            e.parser_rule.as_deref() == Some("derived_member_generator_v1")
                && e.source_span.as_ref() == Some(&derivation.generator)
                && e.token.as_deref() == Some(source_hash)
        })
}

/// Unknown/malformed/legacy derivations cannot regain declaration authority.
pub fn is_derived_member(entity: &Entity) -> bool {
    !matches!(entity_derivation(entity), Ok(None))
}

pub fn require_independent_source(entity: &Entity) -> Result<(), String> {
    match entity_derivation(entity) {
        Ok(None) => Ok(()),
        Ok(Some(derivation)) => Err(format!(
            "{} is a derived member candidate, not an independently editable declaration; inspect and edit its generator in {} at line {} (this may affect sibling members)",
            entity.name, derivation.generator.file, derivation.generator.start_line + 1
        )),
        Err(reason) => Err(format!("{} has no independent source authority: {reason}", entity.name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_member_schema_refuses_unknown_versions_and_invalid_spans() {
        let mut value = serde_json::json!({
            "schema":"kin.entity.derivation.v2", "generator":{}, "assignment":{},
            "source_blob_hash":"", "owner":"app", "member_key":"get", "rule":"literal", "conditions":[]
        });
        assert!(serde_json::from_value::<EntityDerivation>(value.clone()).is_err());
        value["schema"] = serde_json::json!("kin.entity.derivation.v1");
        assert!(serde_json::from_value::<EntityDerivation>(value).is_err());
    }
}
