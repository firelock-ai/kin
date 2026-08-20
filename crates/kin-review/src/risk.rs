// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;

use crate::diff::{EntityChangeKind, RelationChangeKind, SemanticDiff};
use crate::impact::{EntityImpact, ImpactReport};
use kin_model::entity::{Entity, EntityKind, EntityRole, Visibility};
use kin_model::ids::EntityId;
use kin_model::relation::GraphNodeId;
use kin_model::review::{RiskLevel, RiskSummary};

/// This entity's own inbound attribution, or an all-zero record when the report
/// carries none for it.
///
/// FIR-2485. Every condition in [`assess_risk`]'s per-change loop used to read a
/// DIFF-GLOBAL bucket off the report and attribute it to whichever change was in
/// hand, so a finding about one entity fired on another entity's evidence. The
/// principle is `shadow.rs`'s and is stated there: another entity's consumers do
/// not make this entity's surface change risky, the per-entity inbound
/// attribution decides.
///
/// It fails in BOTH directions, which is why one pass fixes six sites rather
/// than five. The consumer conditions fire when their bucket is non-empty, so
/// diff-global INVENTED findings. The coverage conditions fire when their bucket
/// is empty, so diff-global SUPPRESSED them: a modified entity with no tests of
/// its own read as covered because a different entity in the diff had one. The
/// suppressing half hides risk rather than inventing it, and nothing in the
/// output said so.
///
/// The all-zero fallback is conservative in both directions at once, which is
/// what lets one accessor serve every condition: zero consumers does not raise a
/// finding on absent evidence, and zero covering tests does report the gap on
/// absent evidence. `analyze_impact` records every changed entity, so the
/// fallback is reached only where a report was built without computing impact,
/// and those paths already carry their own blocking evidence gap.
fn per_entity(impact: &ImpactReport, entity_id: &EntityId) -> EntityImpact {
    impact
        .entity_impact(entity_id)
        .cloned()
        .unwrap_or_else(|| EntityImpact {
            entity_id: *entity_id,
            consumer_count: 0,
            strong_consumer_count: 0,
            proven_consumer_count: 0,
            contract_consumer_count: 0,
            consumer_files: Vec::new(),
            covering_tests: 0,
            consumers_migrated_in_diff: 0,
            call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
        })
}

/// `name (Kind) at file:line` for a removed entity, so a finding reads as code.
fn describe_entity(entity: &Entity) -> String {
    let kind = format!("{:?}", entity.kind);
    match entity.span.as_ref() {
        Some(span) => format!(
            "`{}` ({}) at {}:{}",
            entity.name,
            kind,
            span.file,
            crate::format::presentation_line(span.start_line)
        ),
        None => match entity.file_origin.as_ref() {
            Some(origin) => format!("`{}` ({}) in {}", entity.name, kind, origin),
            None => format!("`{}` ({})", entity.name, kind),
        },
    }
}

/// Names for every entity this diff and impact report can see, keyed by id.
///
/// A relation note carries two node ids. Both are usually entities the same
/// review already describes, so this index turns them back into names. An id
/// with no entry stays an id: a note must not invent a name it cannot support.
fn known_entity_names(diff: &SemanticDiff, impact: &ImpactReport) -> BTreeMap<EntityId, String> {
    let mut names = BTreeMap::new();
    for entity in impact
        .affected_callers
        .iter()
        .chain(impact.affected_dependents.iter())
        .chain(impact.affected_contract_consumers.iter())
        .chain(impact.affected_tests.iter())
    {
        names
            .entry(entity.id)
            .or_insert_with(|| entity.name.clone());
    }
    for change in &diff.entity_changes {
        let named = match &change.kind {
            EntityChangeKind::Added(entity) => Some(entity),
            EntityChangeKind::Modified { new, .. } => Some(new),
            EntityChangeKind::Removed { old } => old.as_ref(),
        };
        if let Some(entity) = named {
            names
                .entry(change.entity_id)
                .or_insert_with(|| entity.name.clone());
        }
    }
    names
}

/// One endpoint of a relation, named where the review can name it.
fn describe_node(node: &GraphNodeId, names: &BTreeMap<EntityId, String>) -> String {
    match node.as_entity().and_then(|id| names.get(&id)) {
        Some(name) => format!("`{name}`"),
        None => node.to_string(),
    }
}

/// How many dependents a removal finding names before summarising the rest. A
/// deleted helper can have dozens of callers; naming the first few and counting
/// the remainder keeps the finding readable without hiding the size.
const MAX_LISTED_DEPENDENTS: usize = 5;

/// Dependents of a removed entity, named and carrying the edge kind that joined
/// them to it.
///
/// The edge kinds come from the relations this diff removed alongside the
/// entity: a relation whose `dst` was the removed entity names its consumer in
/// `src`. Names come from the impact report's entity lists, which hold whole
/// entities. Both inputs are already in hand, so no graph lookup is needed and
/// this is safe to call from a pure formatting path.
///
/// Returns the rendered dependents and the total found, which may exceed the
/// rendered count. Production consumers sort ahead of tests so a cap never
/// drops the callers that decide whether the deletion is safe.
fn removed_entity_dependents(
    diff: &SemanticDiff,
    impact: &ImpactReport,
    removed_id: &EntityId,
) -> (Vec<String>, usize) {
    let mut edge_kinds: BTreeMap<EntityId, String> = BTreeMap::new();
    for relation_change in &diff.relation_changes {
        let RelationChangeKind::Removed { old } = &relation_change.kind else {
            continue;
        };
        if old.dst != GraphNodeId::Entity(*removed_id) {
            continue;
        }
        if let Some(src) = old.src.as_entity() {
            // A pair can carry more than one edge kind; keep the first in the
            // relation set's stable order rather than picking arbitrarily.
            edge_kinds
                .entry(src)
                .or_insert_with(|| format!("{:?}", old.kind));
        }
    }
    if edge_kinds.is_empty() {
        return (Vec::new(), 0);
    }

    // A test consumer is real blast radius but it is not what decides whether a
    // deletion is safe, so it sorts after production consumers and yields the
    // listed slots to them.
    let mut described: BTreeMap<EntityId, (bool, String)> = BTreeMap::new();
    let candidates = impact
        .affected_callers
        .iter()
        .chain(impact.affected_dependents.iter())
        .chain(impact.affected_contract_consumers.iter())
        .chain(impact.affected_tests.iter());
    for entity in candidates {
        if let Some(edge_kind) = edge_kinds.get(&entity.id) {
            described.entry(entity.id).or_insert_with(|| {
                (
                    entity.role == EntityRole::Test,
                    format!("{} via {}", describe_entity(entity), edge_kind),
                )
            });
        }
    }

    let mut ordered: Vec<(bool, String)> = described.into_values().collect();
    ordered.sort();
    let total = ordered.len();
    let listed = ordered
        .into_iter()
        .take(MAX_LISTED_DEPENDENTS)
        .map(|(_, description)| description)
        .collect();
    (listed, total)
}

/// Assess risk given a diff and its impact report.
///
/// Returns a `RiskSummary` (from kin-model) with:
/// - breaking changes (contract/signature changes with consumers)
/// - test coverage gaps (modified entities with no test coverage)
/// - contract violations
/// - overall risk level
pub fn assess_risk(diff: &SemanticDiff, impact: &ImpactReport) -> RiskSummary {
    let mut breaking_changes = Vec::new();
    let mut test_coverage_gaps = Vec::new();
    let mut contract_violations = Vec::new();
    let mut notes = Vec::new();

    // Check for signature changes on entities with consumers/callers
    for change in &diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Modified { old, new } => {
                // Signature changed?
                if old.signature != new.signature {
                    let entity = per_entity(impact, &change.entity_id);
                    if entity.consumer_count > 0 || entity.contract_consumer_count > 0 {
                        breaking_changes.push(format!(
                            "Signature change on `{}`: `{}` -> `{}`",
                            new.name, old.signature, new.signature,
                        ));
                    }

                    // Public visibility change is notable
                    if old.visibility == Visibility::Public && new.visibility != Visibility::Public
                    {
                        breaking_changes
                            .push(format!("Visibility reduced on `{}` from public", new.name,));
                    }
                }

                // Contract entity modified with consumers
                let contract_consumers =
                    per_entity(impact, &change.entity_id).contract_consumer_count;
                if matches!(
                    new.kind,
                    EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
                ) && contract_consumers > 0
                {
                    contract_violations.push(format!(
                        "Contract `{}` ({:?}) modified with {} consumer(s)",
                        new.name, new.kind, contract_consumers,
                    ));
                }

                // Check test coverage gap
                if new.role != EntityRole::Test {
                    if per_entity(impact, &change.entity_id).covering_tests == 0 {
                        test_coverage_gaps.push(format!(
                            "Modified entity `{}` has no test coverage",
                            new.name,
                        ));
                    }
                }
            }
            EntityChangeKind::Removed { old } => {
                // Two per-entity sources, unioned, because a removal has two
                // and neither alone covers the path the other serves.
                //
                // `removed_entity_dependents` reads the relations THIS diff
                // removed, which are exactly the edges that pointed at this
                // entity. It also feeds the message below, so gating on it makes
                // it impossible for the gate and the message to disagree: the
                // pre-fix code could assert dependents and then name none, which
                // is what the defect looked like on a report.
                //
                // The recorded per-entity count covers what that cannot see.
                // `analyze_impact` walks the LIVE graph, where a removed entity
                // is already gone, so its inbound edges may reach this function
                // only through `shadow.rs`'s base-side overlay. Gating on the
                // relation walk alone would silence a removal whose dependents
                // were recovered that way, including the unresolvable-record
                // case, which is the one a reviewer can least afford to lose.
                //
                // Neither source is the diff-global bucket, which is the point:
                // both answer for THIS entity.
                let (dependents, total) =
                    removed_entity_dependents(diff, impact, &change.entity_id);
                let recorded_consumers = per_entity(impact, &change.entity_id).consumer_count;
                if total > 0 || recorded_consumers > 0 {
                    let subject = match old {
                        Some(entity) => describe_entity(entity),
                        // An unrecoverable base-side record is reported as one.
                        // An id rendered bare would read as a name.
                        None => format!(
                            "<unresolved removal> id {} (no base-side record)",
                            change.entity_id
                        ),
                    };
                    {
                        // The overflow is counted rather than dropped: a reader
                        // must be able to tell five of five from five of forty.
                        let more = total
                            .checked_sub(dependents.len())
                            .filter(|remaining| *remaining > 0)
                            .map(|remaining| format!(", and {remaining} more"))
                            .unwrap_or_default();
                        breaking_changes.push(format!(
                            "Removed entity {subject} still has {total} dependent(s): {}{more}",
                            dependents.join(", ")
                        ));
                    }
                }
            }
            EntityChangeKind::Added(entity) => {
                // New public API without tests
                if entity.visibility == Visibility::Public && entity.role != EntityRole::Test {
                    if per_entity(impact, &change.entity_id).covering_tests == 0 {
                        notes.push(format!(
                            "New public entity `{}` has no test coverage",
                            entity.name,
                        ));
                    }
                }
            }
        }
    }

    // Removed relations that break contracts
    let relation_note_names = known_entity_names(diff, impact);
    for rel_change in &diff.relation_changes {
        if let RelationChangeKind::Removed { old } = &rel_change.kind {
            notes.push(format!(
                "Relation removed: {:?} {} -> {}",
                old.kind,
                describe_node(&old.src, &relation_note_names),
                describe_node(&old.dst, &relation_note_names)
            ));
        }
    }

    // Unreviewed agent changes increase risk.
    if !impact.unreviewed_agent_changes.is_empty() {
        let total = diff.entity_changes.len().max(1);
        let agent_count = impact.unreviewed_agent_changes.len();
        let ratio = agent_count as f64 / total as f64;
        if ratio > 0.5 {
            notes.push(format!(
                "{} of {} changed entities are unreviewed agent changes (>{:.0}%)",
                agent_count,
                total,
                ratio * 100.0,
            ));
        } else {
            notes.push(format!(
                "{} unreviewed agent change(s) among {} changed entities",
                agent_count, total,
            ));
        }
    }

    // Work item risks: flag in-progress work affected by changes.
    let mut work_risks = Vec::new();
    for item in &impact.affected_work_items {
        work_risks.push(format!(
            "Changes affect {} work item `{}` ({})",
            item.status, item.title, item.kind,
        ));
    }
    for ann in &impact.affected_annotations {
        if ann.staleness == kin_model::work::StalenessState::Fresh {
            work_risks.push(format!(
                "Fresh {} annotation may become stale: \"{}\"",
                ann.kind,
                if ann.body.len() > 60 {
                    format!("{}...", &ann.body[..60])
                } else {
                    ann.body.clone()
                },
            ));
        }
    }

    let overall_risk = compute_risk_level(
        &breaking_changes,
        &test_coverage_gaps,
        &contract_violations,
        &work_risks,
        impact,
    );

    RiskSummary {
        overall_risk,
        breaking_changes,
        test_coverage_gaps,
        contract_violations,
        work_risks,
        notes,
    }
}

fn compute_risk_level(
    breaking_changes: &[String],
    test_coverage_gaps: &[String],
    contract_violations: &[String],
    work_risks: &[String],
    impact: &ImpactReport,
) -> RiskLevel {
    if !contract_violations.is_empty() {
        return RiskLevel::Critical;
    }

    if !breaking_changes.is_empty() {
        return RiskLevel::High;
    }

    if !test_coverage_gaps.is_empty() && impact.total_affected() > 5 {
        return RiskLevel::High;
    }

    if !test_coverage_gaps.is_empty() || impact.total_affected() > 3 {
        return RiskLevel::Medium;
    }

    // In-progress work items on changed code is at least Medium risk.
    if !work_risks.is_empty() {
        return RiskLevel::Medium;
    }

    // Unreviewed agent changes bump risk to at least Medium.
    if !impact.unreviewed_agent_changes.is_empty() {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
    use crate::impact::ImpactReport;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// `test_entity` with a real span, so a rendered finding can be checked for
    /// the file and line a reviewer needs.
    fn placed_entity(name: &str, file: &str, start_line: u32) -> Entity {
        let mut entity = test_entity(name);
        entity.span = Some(kin_model::entity::SourceSpan {
            file: kin_model::ids::FilePathId::new(file),
            start_byte: 0,
            end_byte: 1,
            // `placed_entity` takes the 1-based line a reader would see, so the
            // graph row stored here is one less.
            start_line: start_line.saturating_sub(1),
            start_col: 0,
            end_line: start_line,
            end_col: 0,
        });
        entity
    }

    /// A per-entity impact record with the three counts these cases turn on.
    ///
    /// Written out rather than reached through `Default`, which `EntityImpact`
    /// deliberately does not derive: every field is a measured count, and a
    /// field added later should force a decision here rather than silently
    /// arriving as zero in tests that are about which entity a count belongs to.
    fn entity_impact_counts(
        entity_id: EntityId,
        consumer_count: usize,
        contract_consumer_count: usize,
        covering_tests: usize,
    ) -> crate::impact::EntityImpact {
        crate::impact::EntityImpact {
            entity_id,
            consumer_count,
            strong_consumer_count: consumer_count,
            proven_consumer_count: consumer_count,
            contract_consumer_count,
            consumer_files: Vec::new(),
            covering_tests,
            consumers_migrated_in_diff: 0,
            call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
        }
    }

    fn calls_relation(src: &Entity, dst: &Entity) -> kin_model::relation::Relation {
        kin_model::relation::Relation {
            id: kin_model::ids::RelationId::new(),
            kind: kin_model::relation::RelationKind::Calls,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// Deleting a consumed helper is the canonical review catch. The finding has
    /// to say what was deleted and who still calls it, in words a reviewer can
    /// act on. This mirrors the `utils.super_len` case from the reviewprobe
    /// assessment, where the finding named a bare id and nothing else.
    #[test]
    fn removed_entity_finding_names_the_entity_and_its_dependents() {
        use crate::diff::{RelationChange, RelationChangeKind};

        let removed = placed_entity("super_len", "src/requests/utils.py", 160);
        let caller_a = placed_entity(
            "PreparedRequest.prepare_body",
            "src/requests/models.py",
            576,
        );
        let caller_b = placed_entity(
            "PreparedRequest.prepare_content_length",
            "src/requests/models.py",
            654,
        );

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: removed.id,
                kind: EntityChangeKind::Removed {
                    old: Some(removed.clone()),
                },
            }],
            relation_changes: vec![
                RelationChange {
                    kind: RelationChangeKind::Removed {
                        old: calls_relation(&caller_a, &removed),
                    },
                },
                RelationChange {
                    kind: RelationChangeKind::Removed {
                        old: calls_relation(&caller_b, &removed),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller_a.clone(), caller_b.clone()],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        let finding = summary
            .breaking_changes
            .iter()
            .find(|f| f.contains("still has") && f.contains("dependent"))
            .expect("a removal with dependents is a breaking change");

        assert!(
            finding.contains("super_len"),
            "names the deleted entity: {finding}"
        );
        assert!(
            finding.contains("src/requests/utils.py:160"),
            "names where it lived: {finding}"
        );
        assert!(
            finding.contains("PreparedRequest.prepare_body")
                && finding.contains("src/requests/models.py:576"),
            "names the first dependent and its location: {finding}"
        );
        assert!(
            finding.contains("PreparedRequest.prepare_content_length")
                && finding.contains("src/requests/models.py:654"),
            "names the second dependent and its location: {finding}"
        );
        assert!(finding.contains("Calls"), "names the edge kind: {finding}");
        assert!(
            !contains_uuid(finding),
            "a reviewer cannot act on an opaque id: {finding}"
        );
    }

    /// A widely-called helper has more dependents than a finding should print.
    /// The cap must count what it omits, and must spend its slots on production
    /// callers rather than tests.
    #[test]
    fn dependent_list_is_capped_but_counts_the_remainder_and_prefers_production() {
        use crate::diff::{RelationChange, RelationChangeKind};

        let removed = placed_entity("super_len", "src/requests/utils.py", 160);
        let production = placed_entity(
            "PreparedRequest.prepare_body",
            "src/requests/models.py",
            576,
        );
        let mut tests: Vec<Entity> = (0..12)
            .map(|i| {
                let mut test = placed_entity(
                    &format!("TestSuperLen.test_case_{i:02}"),
                    "tests/test_utils.py",
                    60 + i,
                );
                test.role = EntityRole::Test;
                test
            })
            .collect();
        let mut consumers = vec![production.clone()];
        consumers.append(&mut tests);

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: removed.id,
                kind: EntityChangeKind::Removed {
                    old: Some(removed.clone()),
                },
            }],
            relation_changes: consumers
                .iter()
                .map(|consumer| RelationChange {
                    kind: RelationChangeKind::Removed {
                        old: calls_relation(consumer, &removed),
                    },
                })
                .collect(),
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: consumers.clone(),
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        let finding = summary
            .breaking_changes
            .iter()
            .find(|f| f.contains("still has") && f.contains("dependent"))
            .expect("a removal with dependents is a breaking change");

        assert!(
            finding.contains("still has 13 dependent(s)"),
            "the total is stated, not just the listed few: {finding}"
        );
        assert!(
            finding.contains("and 8 more"),
            "the omitted remainder is counted, never silently dropped: {finding}"
        );
        assert!(
            finding.contains("PreparedRequest.prepare_body"),
            "a production caller must not be crowded out by tests: {finding}"
        );
        assert!(
            !contains_uuid(finding),
            "a reviewer cannot act on an opaque id: {finding}"
        );
    }

    /// A removal whose base-side record is unrecoverable must say so. Printing
    /// the id alone would read as a name and hide the gap.
    #[test]
    fn unresolvable_removal_is_reported_as_unresolved_not_as_a_name() {
        let dependent = placed_entity("caller", "src/lib.rs", 10);
        let removed_id = EntityId::new();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: removed_id,
                kind: EntityChangeKind::Removed { old: None },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![dependent],
            // FIR-2485. See the note on the sibling fixtures: the per-entity row
            // is what a real report carries, and it is what makes this removal's
            // dependents ITS dependents. An unrecoverable base-side record does
            // not imply unrecoverable impact, which is the whole reason this
            // case can still be reported as unresolved rather than dropped.
            entity_impacts: vec![entity_impact_counts(removed_id, 1, 0, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        let finding = summary
            .breaking_changes
            .iter()
            .find(|f| f.contains("still has") && f.contains("dependent"))
            .expect("a removal with dependents is a breaking change");
        assert!(
            finding.contains("unresolved removal"),
            "an unrecoverable record is named as one: {finding}"
        );
    }

    /// A 36-character hyphenated hex id. Used to assert a rendered finding does
    /// not fall back to one where a name is required.
    fn contains_uuid(text: &str) -> bool {
        text.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .any(|token| {
                let parts: Vec<&str> = token.split('-').collect();
                parts.len() == 5
                    && [8, 4, 4, 4, 12]
                        .iter()
                        .zip(&parts)
                        .all(|(want, part)| part.len() == *want)
            })
    }

    #[test]
    fn uuid_detector_catches_the_shape_it_is_guarding_against() {
        // The guard above is only evidence if it can fail, so pin both ways.
        assert!(contains_uuid(
            "Removed entity `1c5c4764-ef10-4cb7-b2b3-e1512d0b578d` still has dependents"
        ));
        assert!(!contains_uuid(
            "Removed entity `super_len` (Function) at src/requests/utils.py:160"
        ));
    }

    /// FIR-2485. Every condition in `assess_risk`'s per-change loop reads a
    /// DIFF-GLOBAL bucket off the impact report and attributes it to whichever
    /// change is in hand, so a finding about entity A fires on entity B's
    /// evidence.
    ///
    /// The reported direction: a removal finding on an entity nothing depends
    /// on, because a DIFFERENT entity in the same diff has dependents.
    ///
    /// Every case in this set is a TWO-entity diff on purpose. A one-entity
    /// diff cannot tell diff-global attribution from per-entity attribution,
    /// which is exactly why the older tests here pass under both readings.
    #[test]
    fn a_removal_does_not_inherit_another_entitys_dependents() {
        let removed = placed_entity("orphan_helper", "src/orphan.rs", 10);
        let modified_old = placed_entity("busy_function", "src/busy.rs", 20);
        let mut modified_new = modified_old.clone();
        modified_new.signature = "fn busy_function(x: i32)".to_string();
        let caller = placed_entity("caller_of_busy", "src/callers.rs", 30);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: removed.id,
                    kind: EntityChangeKind::Removed {
                        old: Some(removed.clone()),
                    },
                },
                EntityChange {
                    entity_id: modified_new.id,
                    kind: EntityChangeKind::Modified {
                        old: modified_old.clone(),
                        new: modified_new.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        // The caller belongs to `busy_function`. No relation reaching the
        // removed entity was removed, because nothing reached it.
        let impact = ImpactReport {
            affected_callers: vec![caller.clone()],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(
            !summary
                .breaking_changes
                .iter()
                .any(|f| f.contains("orphan_helper")),
            "nothing depends on the removed entity, so no removal finding may name it: {:?}",
            summary.breaking_changes
        );
    }

    /// The control that keeps the case above from being satisfied by a finding
    /// that never fires. A removal whose OWN dependents are in the diff must
    /// still be reported, or "no more false positives" and "the check is dead"
    /// are the same patch.
    #[test]
    fn a_removal_with_its_own_dependents_still_reports() {
        use crate::diff::{RelationChange, RelationChangeKind};

        let removed = placed_entity("consumed_helper", "src/helper.rs", 10);
        let caller = placed_entity("real_caller", "src/callers.rs", 30);
        let unrelated_old = placed_entity("unrelated", "src/other.rs", 40);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: removed.id,
                    kind: EntityChangeKind::Removed {
                        old: Some(removed.clone()),
                    },
                },
                EntityChange {
                    entity_id: unrelated_old.id,
                    kind: EntityChangeKind::Modified {
                        old: unrelated_old.clone(),
                        new: unrelated_old.clone(),
                    },
                },
            ],
            relation_changes: vec![RelationChange {
                kind: RelationChangeKind::Removed {
                    old: calls_relation(&caller, &removed),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller.clone()],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        let finding = summary
            .breaking_changes
            .iter()
            .find(|f| f.contains("consumed_helper"))
            .unwrap_or_else(|| {
                panic!(
                    "a removal with its own dependents is still a breaking change: {:?}",
                    summary.breaking_changes
                )
            });
        assert!(
            finding.contains("real_caller"),
            "and it names the dependent that makes it one: {finding}"
        );
    }

    /// The other direction, which the ticket does not name and which is the
    /// more dangerous half: the empty-bucket conditions SUPPRESS a finding.
    ///
    /// A modified entity with no tests of its own is reported as covered
    /// because a DIFFERENT entity in the same diff has a test. Risk is hidden
    /// rather than invented, so nothing in the output says anything is wrong.
    #[test]
    fn a_coverage_gap_is_not_hidden_by_another_entitys_tests() {
        let untested_old = placed_entity("untested", "src/untested.rs", 10);
        let mut untested_new = untested_old.clone();
        untested_new.signature = "fn untested(x: i32)".to_string();

        let tested_old = placed_entity("tested", "src/tested.rs", 20);
        let mut tested_new = tested_old.clone();
        tested_new.signature = "fn tested(y: i32)".to_string();

        let mut covering_test = placed_entity("tests_tested", "tests/tested.rs", 5);
        covering_test.role = EntityRole::Test;

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: untested_new.id,
                    kind: EntityChangeKind::Modified {
                        old: untested_old.clone(),
                        new: untested_new.clone(),
                    },
                },
                EntityChange {
                    entity_id: tested_new.id,
                    kind: EntityChangeKind::Modified {
                        old: tested_old.clone(),
                        new: tested_new.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        // The test covers `tested`, and only `tested`.
        let impact = ImpactReport {
            affected_tests: vec![covering_test.clone()],
            entity_impacts: vec![entity_impact_counts(tested_new.id, 0, 0, 1)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(
            summary
                .test_coverage_gaps
                .iter()
                .any(|gap| gap.contains("untested")),
            "an entity with no tests of its own has a coverage gap whatever its \
             neighbours have: {:?}",
            summary.test_coverage_gaps
        );
    }

    /// The control for the case above. An entity with its own covering tests
    /// must stay silent, or the fix reports a gap for everything and says
    /// nothing.
    #[test]
    fn a_covered_entity_reports_no_coverage_gap() {
        let tested_old = placed_entity("tested", "src/tested.rs", 20);
        let mut tested_new = tested_old.clone();
        tested_new.signature = "fn tested(y: i32)".to_string();
        let mut covering_test = placed_entity("tests_tested", "tests/tested.rs", 5);
        covering_test.role = EntityRole::Test;

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: tested_new.id,
                kind: EntityChangeKind::Modified {
                    old: tested_old.clone(),
                    new: tested_new.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_tests: vec![covering_test.clone()],
            entity_impacts: vec![entity_impact_counts(tested_new.id, 0, 0, 1)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(
            summary.test_coverage_gaps.is_empty(),
            "an entity its own tests cover has no gap: {:?}",
            summary.test_coverage_gaps
        );
    }

    /// Conditions 1 and 2: a signature change becomes a breaking change when
    /// THAT entity has consumers. Another entity's callers are not this
    /// entity's blast radius.
    #[test]
    fn a_signature_change_does_not_inherit_another_entitys_callers() {
        let quiet_old = placed_entity("quiet", "src/quiet.rs", 10);
        let mut quiet_new = quiet_old.clone();
        quiet_new.signature = "fn quiet(x: i32)".to_string();

        let busy_old = placed_entity("busy", "src/busy.rs", 20);
        let mut busy_new = busy_old.clone();
        busy_new.signature = "fn busy(y: i32)".to_string();

        let caller = placed_entity("caller_of_busy", "src/callers.rs", 30);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: quiet_new.id,
                    kind: EntityChangeKind::Modified {
                        old: quiet_old.clone(),
                        new: quiet_new.clone(),
                    },
                },
                EntityChange {
                    entity_id: busy_new.id,
                    kind: EntityChangeKind::Modified {
                        old: busy_old.clone(),
                        new: busy_new.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller.clone()],
            entity_impacts: vec![entity_impact_counts(busy_new.id, 1, 0, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(
            !summary
                .breaking_changes
                .iter()
                .any(|f| f.contains("`quiet`")),
            "a signature change on a consumer-free entity is not a breaking change: {:?}",
            summary.breaking_changes
        );
        assert!(
            summary
                .breaking_changes
                .iter()
                .any(|f| f.contains("`busy`")),
            "control: the entity that DOES have a consumer must still report: {:?}",
            summary.breaking_changes
        );
    }

    /// Condition 3, and condition 6's added-entity coverage, in one two-entity
    /// diff. A contract entity is violated by ITS OWN consumers, and a new
    /// public entity's coverage note is about its own tests.
    #[test]
    fn a_contract_and_a_new_entity_are_judged_on_their_own_evidence() {
        let mut contract_old = placed_entity("QuietSchema", "src/schema.rs", 10);
        contract_old.kind = EntityKind::Schema;
        let mut contract_new = contract_old.clone();
        contract_new.signature = "schema QuietSchema { v2 }".to_string();

        let added = placed_entity("brand_new", "src/new.rs", 40);

        let busy_old = placed_entity("busy", "src/busy.rs", 20);
        let mut busy_new = busy_old.clone();
        busy_new.signature = "fn busy(y: i32)".to_string();
        let consumer = placed_entity("consumer_of_busy", "src/consumers.rs", 30);
        let mut busy_test = placed_entity("tests_busy", "tests/busy.rs", 5);
        busy_test.role = EntityRole::Test;

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: contract_new.id,
                    kind: EntityChangeKind::Modified {
                        old: contract_old.clone(),
                        new: contract_new.clone(),
                    },
                },
                EntityChange {
                    entity_id: added.id,
                    kind: EntityChangeKind::Added(added.clone()),
                },
                EntityChange {
                    entity_id: busy_new.id,
                    kind: EntityChangeKind::Modified {
                        old: busy_old.clone(),
                        new: busy_new.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        // Every consumer and test in this report belongs to `busy`.
        let impact = ImpactReport {
            affected_contract_consumers: vec![consumer.clone()],
            affected_tests: vec![busy_test.clone()],
            entity_impacts: vec![entity_impact_counts(busy_new.id, 1, 1, 1)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(
            !summary
                .contract_violations
                .iter()
                .any(|v| v.contains("QuietSchema")),
            "a contract with no consumers of its own is not violated: {:?}",
            summary.contract_violations
        );
        assert!(
            summary
                .notes
                .iter()
                .any(|n| n.contains("brand_new") && n.contains("no test coverage")),
            "a new public entity with no tests of its own is noted whatever its \
             neighbours have: {:?}",
            summary.notes
        );
    }

    #[test]
    fn low_risk_for_empty_diff() {
        let diff = SemanticDiff::default();
        let impact = ImpactReport::default();
        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Low);
        assert!(summary.breaking_changes.is_empty());
    }

    #[test]
    fn medium_risk_for_uncovered_modification() {
        let old = test_entity("process");
        let mut new = old.clone();
        new.signature = "fn process(x: i32)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        // No callers, no tests
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // signature changed but no callers => no breaking change
        // but no test coverage => gap
        assert!(!summary.test_coverage_gaps.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn high_risk_for_breaking_signature_change() {
        let old = test_entity("api_handler");
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let caller = test_entity("caller_fn");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_callers: vec![caller],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 1, 0, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    #[test]
    fn critical_risk_for_contract_violation() {
        let mut old = test_entity("user_schema");
        old.kind = EntityKind::Schema;
        let mut new = old.clone();
        new.signature = "schema User { id: UUID, name: String, email: String }".to_string();

        let consumer = test_entity("user_service");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_contract_consumers: vec![consumer],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 1, 1, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.contract_violations.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Critical);
    }

    // ── Empty diff tests ────────────────────────────────────────────────

    #[test]
    fn empty_diff_empty_impact_is_low() {
        let summary = assess_risk(&SemanticDiff::default(), &ImpactReport::default());
        assert_eq!(summary.overall_risk, RiskLevel::Low);
        assert!(summary.breaking_changes.is_empty());
        assert!(summary.test_coverage_gaps.is_empty());
        assert!(summary.contract_violations.is_empty());
        assert!(summary.notes.is_empty());
    }

    // ── Only additions tests ────────────────────────────────────────────

    #[test]
    fn addition_only_low_risk_with_test_coverage() {
        let entity = test_entity("new_helper");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let test_entity_val = test_entity("test_new_helper");
        let impact = ImpactReport {
            affected_tests: vec![test_entity_val],
            changed_ids: vec![entity.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(entity.id, 0, 0, 1)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // Added public entity with test coverage should not flag
        assert!(summary.notes.is_empty() || !summary.notes.iter().any(|n| n.contains("no test")));
    }

    #[test]
    fn public_addition_without_tests_gets_note() {
        let entity = test_entity("public_api");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            changed_ids: vec![entity.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.notes.iter().any(|n| n.contains("no test coverage")));
    }

    // ── Only deletions tests ────────────────────────────────────────────

    #[test]
    fn removal_with_dependents_is_high_risk() {
        let entity_id = EntityId::new();
        let dependent = test_entity("consumer");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id,
                kind: EntityChangeKind::Removed { old: None },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_dependents: vec![dependent],
            changed_ids: vec![entity_id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(entity_id, 1, 0, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    #[test]
    fn removal_without_dependents_is_low_risk() {
        let entity_id = EntityId::new();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id,
                kind: EntityChangeKind::Removed { old: None },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            changed_ids: vec![entity_id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Low);
    }

    // ── Impact with no downstream tests ─────────────────────────────────

    #[test]
    fn modification_with_no_downstream_and_tests_is_low() {
        let old = test_entity("helper");
        let mut new = old.clone();
        new.signature = "fn helper(x: u32)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let test_ent = test_entity("test_helper");
        let impact = ImpactReport {
            affected_tests: vec![test_ent],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 0, 0, 1)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // No callers => no breaking change, has test coverage
        assert!(summary.breaking_changes.is_empty());
        assert!(summary.test_coverage_gaps.is_empty());
    }

    // ── Visibility reduction tests ──────────────────────────────────────

    #[test]
    fn visibility_reduction_with_callers_is_breaking() {
        let old = test_entity("public_fn");
        let mut new = old.clone();
        new.signature = "fn public_fn(x: i32)".to_string();
        new.visibility = Visibility::Private;

        let caller = test_entity("caller");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_callers: vec![caller],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 1, 0, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary
            .breaking_changes
            .iter()
            .any(|b| b.contains("Visibility reduced")));
    }

    // ── High risk for many affected entities ────────────────────────────

    #[test]
    fn high_risk_when_many_affected_and_no_tests() {
        let old = test_entity("core_fn");
        let mut new = old.clone();
        new.signature = "fn core_fn(a: i32, b: i32)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        // > 5 affected entities + no test coverage => High
        let dependents: Vec<Entity> = (0..6).map(|i| test_entity(&format!("dep_{i}"))).collect();

        let impact = ImpactReport {
            affected_dependents: dependents,
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    // ── Medium risk for moderate affected entities ──────────────────────

    #[test]
    fn medium_risk_when_moderate_affected() {
        let diff = SemanticDiff::default();

        let dependents: Vec<Entity> = (0..4).map(|i| test_entity(&format!("dep_{i}"))).collect();

        let impact = ImpactReport {
            affected_dependents: dependents,
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    // ── Unreviewed agent changes tests ──────────────────────────────────

    #[test]
    fn unreviewed_agent_changes_bump_risk_to_medium() {
        let entity_id = EntityId::new();
        let diff = SemanticDiff::default();

        let impact = ImpactReport {
            unreviewed_agent_changes: vec![entity_id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn agent_changes_over_half_generate_note() {
        let id1 = EntityId::new();
        let entity = test_entity("auto_fn");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            unreviewed_agent_changes: vec![id1],
            changed_ids: vec![entity.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.notes.iter().any(|n| n.contains("unreviewed agent")));
    }

    // ── Work item risk tests ────────────────────────────────────────────

    #[test]
    fn work_items_on_changed_entities_add_risk() {
        use kin_model::{IdentityRef, Priority, WorkId, WorkItem, WorkKind, WorkScope, WorkStatus};

        let diff = SemanticDiff::default();
        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "New login flow".to_string(),
            description: String::new(),
            status: WorkStatus::InProgress,
            priority: Priority::None,
            scopes: vec![WorkScope::Entity(EntityId::new())],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("dev"),
            created_at: kin_model::timestamp::Timestamp::now(),
        };

        let impact = ImpactReport {
            affected_work_items: vec![work],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
        assert!(!summary.work_risks.is_empty());
    }

    // ── Relation removal tests ──────────────────────────────────────────

    #[test]
    fn removed_relation_generates_note() {
        use crate::diff::{RelationChange, RelationChangeKind};

        let src = test_entity("caller");
        let dst = test_entity("callee");
        let diff = SemanticDiff {
            relation_changes: vec![RelationChange {
                kind: RelationChangeKind::Removed {
                    old: calls_relation(&src, &dst),
                },
            }],
            ..Default::default()
        };

        // The endpoints are entities the review can see, so the note must name
        // them rather than printing node ids.
        let impact = ImpactReport {
            affected_callers: vec![src.clone()],
            affected_dependents: vec![dst.clone()],
            ..Default::default()
        };
        let summary = assess_risk(&diff, &impact);
        let note = summary
            .notes
            .iter()
            .find(|n| n.contains("Relation removed"))
            .expect("removed relation emits a note");
        assert!(
            note.contains("Calls"),
            "note should name the edge kind: {note}"
        );
        assert!(
            note.contains("`caller`") && note.contains("`callee`"),
            "note should name both endpoints: {note}"
        );
        assert!(
            !contains_uuid(note),
            "a named endpoint must not fall back to a node id: {note}"
        );
    }

    /// An endpoint the review cannot name keeps its id. Inventing a name would
    /// be worse than showing the id, so the fallback is pinned.
    #[test]
    fn unknown_relation_endpoint_keeps_its_id() {
        use crate::diff::{RelationChange, RelationChangeKind};

        let src = test_entity("stranger");
        let dst = test_entity("also_stranger");
        let diff = SemanticDiff {
            relation_changes: vec![RelationChange {
                kind: RelationChangeKind::Removed {
                    old: calls_relation(&src, &dst),
                },
            }],
            ..Default::default()
        };
        let summary = assess_risk(&diff, &ImpactReport::default());
        let note = summary
            .notes
            .iter()
            .find(|n| n.contains("Relation removed"))
            .expect("removed relation emits a note");
        assert!(
            contains_uuid(note),
            "an unnameable endpoint shows its id rather than a guess: {note}"
        );
    }

    // ── API endpoint contract tests ─────────────────────────────────────

    #[test]
    fn api_endpoint_modification_with_consumers_is_critical() {
        let mut old = test_entity("get_users");
        old.kind = EntityKind::ApiEndpoint;
        let mut new = old.clone();
        new.signature = "GET /api/v2/users".to_string();

        let consumer = test_entity("frontend_client");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_contract_consumers: vec![consumer],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 1, 1, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Critical);
    }

    #[test]
    fn event_contract_modification_with_consumers_is_critical() {
        let mut old = test_entity("user_created_event");
        old.kind = EntityKind::EventContract;
        let mut new = old.clone();
        new.signature = "event UserCreated { id, name, email }".to_string();

        let consumer = test_entity("notification_handler");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_contract_consumers: vec![consumer],
            changed_ids: vec![new.id],
            // FIR-2485. The per-entity row a real report always carries for
            // this change. `analyze_impact` records one for every changed
            // entity, so a fixture naming a consumer in a diff-global bucket
            // with no per-entity trace is not a smaller report, it is a shape
            // the analyzer cannot produce. Every assertion below is unchanged:
            // the test was always about this entity's own evidence, and only
            // the fixture was written in the form that let another entity's
            // evidence answer for it.
            entity_impacts: vec![entity_impact_counts(new.id, 1, 1, 0)],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.contract_violations.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Critical);
    }

    // ── Test entity modification tests ──────────────────────────────────

    #[test]
    fn test_entity_modification_no_coverage_gap() {
        let mut old = test_entity("test_login");
        old.role = EntityRole::Test;
        let mut new = old.clone();
        new.signature = "fn test_login_v2()".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // Test entities should not generate coverage gaps
        assert!(summary.test_coverage_gaps.is_empty());
    }

    // ── Annotation staleness tests ──────────────────────────────────────

    #[test]
    fn fresh_annotation_on_changed_entity_generates_risk() {
        use kin_model::{
            Annotation, AnnotationId, AnnotationKind, EntityId as EId, IdentityRef, StalenessState,
            WorkScope,
        };

        let diff = SemanticDiff::default();
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            scopes: vec![WorkScope::Entity(EId::new())],
            kind: AnnotationKind::Warning,
            body: "Watch for race conditions here".to_string(),
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("dev"),
            created_at: kin_model::timestamp::Timestamp::now(),
            staleness: StalenessState::Fresh,
        };

        let impact = ImpactReport {
            affected_annotations: vec![ann],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.work_risks.iter().any(|r| r.contains("annotation")));
    }
}
