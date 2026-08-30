// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Semantic-version impact derived from repository-v6 entity change classes.
//!
//! The API surface, the change classes, and the resulting bump all come from
//! two immutable graph states resolved at explicit endpoints. No branch naming
//! convention, commit-message convention, or working-copy scan participates:
//! the answer is a function of the entities repository authority owns at the
//! two endpoints and nothing else.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use kin_model::{Entity, EntityDelta, EntityId, EntityKind, EntityRole, Visibility};
use serde::{Deserialize, Serialize};

use super::diff::{DiffEndpoint, DIFF_SCHEMA};

pub const SEMVER_SCHEMA: &str = "kin.semver-impact.v1";

/// The exact change class one entity contributes to API impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiChangeClass {
    /// A published entity disappeared from the API surface.
    Removed,
    /// A published entity's declaration shape changed.
    SignatureChanged,
    /// A published entity stopped being published.
    Unpublished,
    /// A new entity appeared on the API surface.
    Added,
    /// An existing entity became published.
    Published,
    /// A published entity's behavior changed behind an unchanged declaration.
    BehaviorChanged,
}

impl ApiChangeClass {
    pub const fn impact(self) -> SemverImpact {
        match self {
            Self::Removed | Self::SignatureChanged | Self::Unpublished => SemverImpact::Major,
            Self::Added | Self::Published => SemverImpact::Minor,
            Self::BehaviorChanged => SemverImpact::Patch,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::SignatureChanged => "signature_changed",
            Self::Unpublished => "unpublished",
            Self::Added => "added",
            Self::Published => "published",
            Self::BehaviorChanged => "behavior_changed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemverImpact {
    None,
    Patch,
    Minor,
    Major,
}

impl SemverImpact {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiChange {
    pub class: String,
    pub impact: String,
    pub entity_id: EntityId,
    pub name: String,
    pub kind: EntityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemverSummary {
    pub major: usize,
    pub minor: usize,
    pub patch: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemverReport {
    pub schema: String,
    pub authority: String,
    pub authority_generation: u64,
    pub base: DiffEndpoint,
    pub head: DiffEndpoint,
    /// Entities on the published API surface at each endpoint.
    pub base_api_entities: usize,
    pub head_api_entities: usize,
    pub impact: String,
    pub summary: SemverSummary,
    pub changes: Vec<ApiChange>,
}

/// Entities that participate in the published API surface.
///
/// Tests, docs, generated, vendored, and external entities are excluded because
/// changing them cannot break a consumer of this repository. Non-public
/// visibility is excluded for the same reason, and File and DocumentNode
/// entities are containers rather than callable surface.
fn is_api_surface(entity: &Entity) -> bool {
    if entity.visibility != Visibility::Public {
        return false;
    }
    if entity.role != EntityRole::Source {
        return false;
    }
    !matches!(
        entity.kind,
        EntityKind::File | EntityKind::DocumentNode | EntityKind::Test
    )
}

/// How much published API surface an endpoint carries.
///
/// This counts the same surface [`is_api_surface`] classifies changes over, so
/// the reported endpoint sizes and the reported impact answer for one
/// population. The endpoint's total entity count is a different number and is
/// reported separately by diff.
fn api_surface_count(entities: &HashMap<EntityId, Entity>) -> usize {
    entities
        .values()
        .filter(|entity| is_api_surface(entity))
        .count()
}

fn classify(delta: &EntityDelta) -> Option<(ApiChangeClass, ApiChange)> {
    let (class, old, new) = match delta {
        EntityDelta::Added { new } => {
            if !is_api_surface(new) {
                return None;
            }
            (ApiChangeClass::Added, None, Some(new))
        }
        EntityDelta::Removed { old } => {
            if !is_api_surface(old) {
                return None;
            }
            (ApiChangeClass::Removed, Some(old), None)
        }
        EntityDelta::Modified { old, new } => match (is_api_surface(old), is_api_surface(new)) {
            (false, false) => return None,
            (false, true) => (ApiChangeClass::Published, Some(old), Some(new)),
            (true, false) => (ApiChangeClass::Unpublished, Some(old), Some(new)),
            (true, true) => {
                if old.fingerprint.signature_hash != new.fingerprint.signature_hash
                    || old.signature != new.signature
                    || old.name != new.name
                {
                    (ApiChangeClass::SignatureChanged, Some(old), Some(new))
                } else if old.fingerprint.behavior_hash != new.fingerprint.behavior_hash {
                    (ApiChangeClass::BehaviorChanged, Some(old), Some(new))
                } else {
                    return None;
                }
            }
        },
    };
    let anchor = new.or(old).expect("a classified delta has an endpoint");
    Some((
        class,
        ApiChange {
            class: class.as_str().to_string(),
            impact: class.impact().as_str().to_string(),
            entity_id: anchor.id,
            name: anchor.name.clone(),
            kind: anchor.kind,
            previous_signature: old.map(|entity| entity.signature.clone()),
            signature: new.map(|entity| entity.signature.clone()),
        },
    ))
}

pub fn inspect(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: &str,
    head: &str,
) -> Result<SemverReport> {
    let (diff, endpoints) =
        super::diff::inspect_with_endpoint_entities(binding, Some(base), Some(head), None)?;
    if diff.schema != DIFF_SCHEMA {
        return Err(anyhow!(
            "repository diff returned schema '{}' instead of '{DIFF_SCHEMA}'",
            diff.schema
        ));
    }
    let mut summary = SemverSummary::default();
    let mut impact = SemverImpact::None;
    let mut changes = Vec::new();
    for delta in &diff.entity_deltas {
        let Some((class, change)) = classify(delta) else {
            continue;
        };
        match class.impact() {
            SemverImpact::Major => summary.major += 1,
            SemverImpact::Minor => summary.minor += 1,
            SemverImpact::Patch => summary.patch += 1,
            SemverImpact::None => {}
        }
        impact = impact.max(class.impact());
        changes.push(change);
    }
    changes.sort_by(|left, right| {
        left.entity_id
            .to_string()
            .cmp(&right.entity_id.to_string())
            .then_with(|| left.class.cmp(&right.class))
    });

    Ok(SemverReport {
        schema: SEMVER_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        authority_generation: diff.authority_generation,
        base_api_entities: api_surface_count(&endpoints.base),
        head_api_entities: api_surface_count(&endpoints.head),
        base: diff.base,
        head: diff.head,
        impact: impact.as_str().to_string(),
        summary,
        changes,
    })
}

pub fn run(base: String, head: String, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let report = inspect(&binding, &base, &head)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}

pub fn render_lines(report: &SemverReport) -> Vec<String> {
    let mut lines = vec![
        "Kin repository-v6 semver impact".to_string(),
        format!("Authority generation: {}", report.authority_generation),
        format!("Impact: {}", report.impact),
        format!(
            "API changes: {} major, {} minor, {} patch",
            report.summary.major, report.summary.minor, report.summary.patch
        ),
    ];
    for change in &report.changes {
        lines.push(format!(
            "{:>8}  {}  {}",
            change.impact, change.class, change.name
        ));
    }
    if report.changes.is_empty() {
        lines.push("No published API surface changed between these endpoints.".to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint};

    fn fingerprint(signature: u8, behavior: u8) -> SemanticFingerprint {
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([signature; 32]),
            behavior_hash: Hash256::from_bytes([behavior; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    fn entity(name: &str, visibility: Visibility, signature: u8, behavior: u8) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: fingerprint(signature, behavior),
            file_origin: None,
            span: None,
            signature: format!("fn {name}(v{signature})"),
            visibility,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: Default::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn only_published_source_surface_drives_impact() {
        let private = entity("hidden", Visibility::Private, 1, 1);
        let mut private_changed = private.clone();
        private_changed.fingerprint = fingerprint(2, 2);
        private_changed.signature = "fn hidden(v2)".to_string();
        assert!(
            classify(&EntityDelta::Modified {
                old: private,
                new: private_changed,
            })
            .is_none(),
            "a private entity must not produce API impact"
        );

        let mut test_entity = entity("proves", Visibility::Public, 1, 1);
        test_entity.role = EntityRole::Test;
        assert!(
            classify(&EntityDelta::Added { new: test_entity }).is_none(),
            "test entities are not published API surface"
        );
    }

    #[test]
    fn endpoint_counts_are_the_published_surface_not_every_entity() {
        let published = entity("api", Visibility::Public, 1, 1);
        let private = entity("hidden", Visibility::Private, 1, 1);
        let mut proving = entity("proves", Visibility::Public, 1, 1);
        proving.role = EntityRole::Test;
        let mut container = entity("src/lib.rs", Visibility::Public, 1, 1);
        container.kind = EntityKind::File;

        let endpoint: HashMap<EntityId, Entity> = [published, private, proving, container]
            .into_iter()
            .map(|entity| (entity.id, entity))
            .collect();

        assert_eq!(
            api_surface_count(&endpoint),
            1,
            "the reported endpoint size must count the same surface the impact is classified over"
        );
    }

    #[test]
    fn change_classes_map_to_the_expected_bump() {
        let public = entity("api", Visibility::Public, 1, 1);

        let (class, _) = classify(&EntityDelta::Removed {
            old: public.clone(),
        })
        .expect("removing published surface is API impact");
        assert_eq!(class, ApiChangeClass::Removed);
        assert_eq!(class.impact(), SemverImpact::Major);

        let (class, _) = classify(&EntityDelta::Added {
            new: public.clone(),
        })
        .expect("adding published surface is API impact");
        assert_eq!(class, ApiChangeClass::Added);
        assert_eq!(class.impact(), SemverImpact::Minor);

        let mut resigned = public.clone();
        resigned.fingerprint = fingerprint(2, 2);
        resigned.signature = "fn api(v2)".to_string();
        let (class, change) = classify(&EntityDelta::Modified {
            old: public.clone(),
            new: resigned,
        })
        .expect("a changed declaration is API impact");
        assert_eq!(class, ApiChangeClass::SignatureChanged);
        assert_eq!(class.impact(), SemverImpact::Major);
        assert_eq!(change.previous_signature.as_deref(), Some("fn api(v1)"));

        let mut rebodied = public.clone();
        rebodied.fingerprint = fingerprint(1, 9);
        let (class, _) = classify(&EntityDelta::Modified {
            old: public.clone(),
            new: rebodied,
        })
        .expect("a changed body behind a stable declaration is API impact");
        assert_eq!(class, ApiChangeClass::BehaviorChanged);
        assert_eq!(class.impact(), SemverImpact::Patch);

        let mut hidden = public.clone();
        hidden.visibility = Visibility::Private;
        let (class, _) = classify(&EntityDelta::Modified {
            old: public.clone(),
            new: hidden.clone(),
        })
        .expect("unpublishing is API impact");
        assert_eq!(class, ApiChangeClass::Unpublished);
        assert_eq!(class.impact(), SemverImpact::Major);

        let (class, _) = classify(&EntityDelta::Modified {
            old: hidden,
            new: public.clone(),
        })
        .expect("publishing is API impact");
        assert_eq!(class, ApiChangeClass::Published);
        assert_eq!(class.impact(), SemverImpact::Minor);

        assert!(
            classify(&EntityDelta::Modified {
                old: public.clone(),
                new: public,
            })
            .is_none(),
            "an unchanged entity must not produce API impact"
        );
    }
}
