// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;

use kin_model::entity::{Entity, EntityKind, EntityRole, Visibility};
use kin_model::ids::EntityId;
use serde::{Deserialize, Serialize};

use crate::diff::{EntityChangeKind, SemanticDiff};
use crate::impact::ImpactReport;

const COMMAND_EFFECT_CONTRACT_KEY: &str = "command_effect_contract";

/// A review comment anchored to a specific source location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineComment {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub kind: InlineCommentKind,
    pub message: String,
}

/// Classification of an inline review comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InlineCommentKind {
    Breaking,
    CoverageGap,
    ContractViolation,
    CommandEffectContract,
    SignatureChange,
    VisibilityChange,
    ConsumerFanout,
    Added,
    Removed,
    Renamed,
    AgentUnreviewed,
}

impl InlineCommentKind {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Breaking => "!!",
            Self::ContractViolation => "!!",
            Self::CommandEffectContract => "~",
            Self::CoverageGap => "?",
            Self::SignatureChange => "~",
            Self::VisibilityChange => "~",
            Self::ConsumerFanout => "~",
            Self::Added => "+",
            Self::Removed => "-",
            Self::Renamed => "~",
            Self::AgentUnreviewed => "@",
        }
    }
}

/// Distinct non-test consumer ENTITIES at or above which a body-only
/// modification (signature and visibility unchanged) emits a consumer-fanout
/// attention comment. The decision is graph-native — it counts consuming
/// entities (typed inbound edges), not the files they happen to live in; a body
/// change reaching a single consumer is ordinary local iteration. The signature
/// channels own contract-surface changes.
pub const CONSUMER_FANOUT_THRESHOLD: usize = 2;

/// Qualifiers whose ADDITION strengthens a declaration without invalidating
/// any existing caller. Removal of one is a real surface change.
const STRENGTHENING_QUALIFIERS: &[&str] = &["constexpr", "inline", "[[nodiscard]]"];

/// True when `old` → `new` differs ONLY by adding strengthening qualifiers:
/// the qualifier-stripped declarations are identical and `new` carries more
/// strengthening qualifiers than `old`.
pub fn signature_strengthened_only(old: &str, new: &str) -> bool {
    if old == new {
        return false;
    }
    fn strip(sig: &str) -> (String, usize) {
        let mut removed = 0usize;
        let kept: Vec<&str> = sig
            .split_whitespace()
            .filter(|tok| {
                if STRENGTHENING_QUALIFIERS.contains(tok) {
                    removed += 1;
                    false
                } else {
                    true
                }
            })
            .collect();
        (kept.join(" "), removed)
    }
    let (old_core, old_quals) = strip(old);
    let (new_core, new_quals) = strip(new);
    old_core == new_core && new_quals > old_quals
}

/// Collect line-level inline comments from a review's diff and impact data.
///
/// Each comment is anchored to a file + line range derived from the entity's
/// `SourceSpan`. Entities without a span are skipped (they have no file location
/// to anchor to).
pub fn collect_inline_comments(diff: &SemanticDiff, impact: &ImpactReport) -> Vec<InlineComment> {
    let mut comments = Vec::new();

    for change in &diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Added(entity) => {
                collect_added_comments(entity, impact, &mut comments);
            }
            EntityChangeKind::Modified { old, new } => {
                collect_modified_comments(old, new, impact, &mut comments);
            }
            EntityChangeKind::Removed(_) => {
                // Removed entities have no span data — nothing to anchor.
            }
        }
    }

    // Sort by file, then by start_line for stable output.
    comments.sort_by(|a, b| a.file.cmp(&b.file).then(a.start_line.cmp(&b.start_line)));

    comments
}

/// Graph-known tests covering one changed entity.
fn covering_tests(impact: &ImpactReport, entity_id: &EntityId) -> usize {
    impact
        .entity_impact(entity_id)
        .map_or(0, |entry| entry.covering_tests)
}

fn collect_added_comments(
    entity: &Entity,
    impact: &ImpactReport,
    comments: &mut Vec<InlineComment>,
) {
    let span = match &entity.span {
        Some(s) => s,
        None => return,
    };

    comments.push(InlineComment {
        file: span.file.to_string(),
        start_line: span.start_line,
        end_line: span.end_line,
        kind: InlineCommentKind::Added,
        message: format!(
            "New {:?} `{}` — {}",
            entity.kind, entity.name, entity.signature,
        ),
    });

    // Public entity without test coverage. Keyed on THIS entity's covering
    // tests, not the diff-global test bucket, and suppressed when the diff
    // has no impact signal at all — an empty channel cannot distinguish
    // "uncovered" from "relations never ingested", and the report already
    // carries that deficit as an `impact_signal_absent` evidence gap.
    if entity.visibility == Visibility::Public
        && entity.role != EntityRole::Test
        && !impact.is_empty()
        && covering_tests(impact, &entity.id) == 0
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!("New public entity `{}` has no test coverage", entity.name,),
        });
    }

    // Unreviewed agent change
    if impact.unreviewed_agent_changes.contains(&entity.id) {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::AgentUnreviewed,
            message: format!(
                "Entity `{}` was added by an agent and has not been reviewed",
                entity.name,
            ),
        });
    }
}

fn collect_modified_comments(
    old: &Entity,
    new: &Entity,
    impact: &ImpactReport,
    comments: &mut Vec<InlineComment>,
) {
    // Anchor to the new entity's span (where the change landed).
    let span = match &new.span {
        Some(s) => s,
        None => return,
    };

    // All gate-relevant rules key on THIS entity's inbound edges. Another
    // entity's consumers are that entity's risk, not this one's.
    let per_entity = impact.entity_impact(&new.id);
    let consumer_count = per_entity.map_or(0, |e| e.consumer_count);
    let strong_consumer_count = per_entity.map_or(0, |e| e.strong_consumer_count);
    let contract_consumer_count = per_entity.map_or(0, |e| e.contract_consumer_count);
    let consumer_file_count = per_entity.map_or(0, |e| e.consumer_files.len());
    let entity_covering_tests = per_entity.map_or(0, |e| e.covering_tests);
    let fanout_gate_consumer_count = if entity_covering_tests > 0 {
        strong_consumer_count
    } else {
        consumer_count
    };

    // Signature change. A difference that only ADDS strengthening qualifiers
    // (constexpr/inline/[[nodiscard]]) cannot invalidate existing callers and
    // is not a contract-surface change; anything else — including removing
    // such qualifiers — remains one.
    if old.signature != new.signature
        && !signature_strengthened_only(&old.signature, &new.signature)
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::SignatureChange,
            message: format!(
                "Signature changed: `{}` → `{}`",
                old.signature, new.signature,
            ),
        });

        // Breaking only when THIS entity has non-test consumers to break.
        // Test-only consumers are the covering evidence for the change, not
        // a contract it is breaking.
        if consumer_count > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: signature modification affects {} downstream entity(ies)",
                    consumer_count,
                ),
            });
        }
    }

    // Visibility reduction
    if old.visibility == Visibility::Public && new.visibility != Visibility::Public {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::VisibilityChange,
            message: format!(
                "Visibility reduced: {:?} → {:?} on `{}`",
                old.visibility, new.visibility, new.name,
            ),
        });

        if consumer_count > 0 {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: visibility reduced with {} consumer(s)",
                    consumer_count,
                ),
            });
        }
    }

    // Renamed
    if old.name != new.name {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::Renamed,
            message: format!("Renamed: `{}` → `{}`", old.name, new.name),
        });
    }

    // Contract entity whose own consumers are exposed to this modification.
    if matches!(
        new.kind,
        EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
    ) && contract_consumer_count > 0
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::ContractViolation,
            message: format!(
                "Contract {:?} `{}` modified with {} consumer(s)",
                new.kind, new.name, contract_consumer_count,
            ),
        });
    }

    // Fire only when BOTH sides carry a contract: persist paths differ in
    // whether they attach the key, so one-sided presence is path-coverage
    // skew, not a behavior change.
    if let (Some(old_contract), Some(new_contract)) = (
        old.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY),
        new.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY),
    ) {
        if old_contract != new_contract {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::CommandEffectContract,
                message: format!(
                    "Command-effect contract for `{}` changed; external command behavior needs review",
                    new.name,
                ),
            });
        }
    }

    // Body-only modification with wide consumer fanout. The contract surface
    // is unchanged, so the breaking channels stay silent, but a behavior
    // change reaching many distinct non-test consumer entities deserves
    // attention. Graph-known covering tests can absorb weak/ambiguous fanout,
    // so covered body-only changes gate on strong consumers only. Uncovered
    // body-only changes gate on all graph-native consumer entities: weak
    // fanout plus no tests is still a review risk. The file list is reported
    // only as human-readable context.
    if old.signature == new.signature
        && old.visibility == new.visibility
        && fanout_gate_consumer_count >= CONSUMER_FANOUT_THRESHOLD
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::ConsumerFanout,
            message: format!(
                "Behavior of `{}` changed with {} distinct non-test consumer(s) across {} file(s)",
                new.name, fanout_gate_consumer_count, consumer_file_count,
            ),
        });
    }

    // No test coverage. Keyed on THIS entity's covering tests and suppressed
    // when the diff-wide impact signal is absent — that deficit is already
    // reported as an `impact_signal_absent` evidence gap.
    if new.role != EntityRole::Test && !impact.is_empty() && entity_covering_tests == 0 {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!("Modified entity `{}` has no test coverage", new.name,),
        });
    }

    // Unreviewed agent change
    if impact.unreviewed_agent_changes.contains(&new.id) {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::AgentUnreviewed,
            message: format!(
                "Entity `{}` was modified by an agent and has not been reviewed",
                new.name,
            ),
        });
    }
}

/// Group inline comments by file path, with comments sorted by line within
/// each file. Returns entries in file-path-sorted order.
pub fn group_by_file(comments: &[InlineComment]) -> BTreeMap<&str, Vec<&InlineComment>> {
    let mut grouped: BTreeMap<&str, Vec<&InlineComment>> = BTreeMap::new();
    for comment in comments {
        grouped.entry(&comment.file).or_default().push(comment);
    }
    // Each group is already sorted because collect_inline_comments sorts globally.
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
    use crate::impact::{EntityImpact, ImpactReport};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::ids::*;

    fn test_entity_with_span(name: &str, file: &str, start_line: u32, end_line: u32) -> Entity {
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
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 100,
                start_line,
                start_col: 0,
                end_line,
                end_col: 0,
            }),
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

    fn test_entity_no_span(name: &str) -> Entity {
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

    #[test]
    fn added_entity_with_span_produces_comment() {
        let entity = test_entity_with_span("handle_request", "src/api.rs", 10, 25);
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments.is_empty());
        assert_eq!(comments[0].file, "src/api.rs");
        assert_eq!(comments[0].start_line, 10);
        assert_eq!(comments[0].end_line, 25);
        assert_eq!(comments[0].kind, InlineCommentKind::Added);
    }

    #[test]
    fn entity_without_span_produces_no_comment() {
        let entity = test_entity_no_span("orphan");
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments.is_empty());
    }

    #[test]
    fn modified_entity_signature_change_produces_comments() {
        let old = test_entity_with_span("process", "src/core.rs", 5, 20);
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
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::SignatureChange));
    }

    #[test]
    fn breaking_change_when_callers_exist() {
        let old = test_entity_with_span("api_handler", "src/api.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let caller = test_entity_with_span("caller_fn", "src/client.rs", 1, 5);

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
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 1,
                strong_consumer_count: 1,
                contract_consumer_count: 0,
                consumer_files: vec!["src/client.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Breaking));
    }

    #[test]
    fn breaking_requires_this_entitys_consumers_not_the_diffs() {
        // Entity A changes signature but nothing consumes A; the diff-global
        // caller belongs to entity B. A must NOT be reported as breaking.
        let old_a = test_entity_with_span("isolated_fn", "src/a.rs", 1, 10);
        let mut new_a = old_a.clone();
        new_a.signature = "fn isolated_fn(x: i32)".to_string();
        let b = test_entity_with_span("popular_fn", "src/b.rs", 1, 10);
        let caller_of_b = test_entity_with_span("caller_fn", "src/client.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: new_a.id,
                    kind: EntityChangeKind::Modified {
                        old: old_a.clone(),
                        new: new_a.clone(),
                    },
                },
                EntityChange {
                    entity_id: b.id,
                    kind: EntityChangeKind::Modified {
                        old: b.clone(),
                        new: b.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller_of_b],
            changed_ids: vec![new_a.id, b.id],
            entity_impacts: vec![
                EntityImpact {
                    entity_id: new_a.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 0,
                },
                EntityImpact {
                    entity_id: b.id,
                    consumer_count: 1,
                    strong_consumer_count: 1,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/client.rs".to_string()],
                    covering_tests: 0,
                },
            ],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "another entity's consumers must not make this signature change breaking"
        );
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::SignatureChange));
    }

    #[test]
    fn breaking_suppressed_when_only_tests_consume() {
        // Signature change whose only inbound edges are tests: the tests are
        // the covering evidence, not a broken contract. Not breaking.
        let old = test_entity_with_span("tested_fn", "src/core.rs", 1, 10);
        let mut new = old.clone();
        new.signature = "fn tested_fn(flag: bool)".to_string();
        let test_entity = test_entity_with_span("test_tested_fn", "tests/core.rs", 1, 5);

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
            affected_tests: vec![test_entity],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 0,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec![],
                covering_tests: 1,
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::Breaking),
            "test-only consumers must not produce a breaking finding"
        );
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CoverageGap),
            "a tested entity has no coverage gap"
        );
    }

    #[test]
    fn coverage_gap_keys_on_the_entity_not_the_diff() {
        // Covered entity + uncovered entity in one diff: exactly the
        // uncovered one carries the gap. Under the old diff-global rule the
        // covered entity's test silenced both.
        let covered = test_entity_with_span("covered_fn", "src/covered.rs", 1, 10);
        let uncovered = test_entity_with_span("uncovered_fn", "src/uncovered.rs", 1, 10);
        let test_entity = test_entity_with_span("test_covered_fn", "tests/covered.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: covered.id,
                    kind: EntityChangeKind::Modified {
                        old: covered.clone(),
                        new: covered.clone(),
                    },
                },
                EntityChange {
                    entity_id: uncovered.id,
                    kind: EntityChangeKind::Modified {
                        old: uncovered.clone(),
                        new: uncovered.clone(),
                    },
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_tests: vec![test_entity],
            changed_ids: vec![covered.id, uncovered.id],
            entity_impacts: vec![
                EntityImpact {
                    entity_id: covered.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 1,
                },
                EntityImpact {
                    entity_id: uncovered.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 0,
                },
            ],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        let gaps: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::CoverageGap)
            .collect();
        assert_eq!(gaps.len(), 1, "exactly the uncovered entity carries a gap");
        assert_eq!(gaps[0].file, "src/uncovered.rs");
    }

    #[test]
    fn coverage_gap_suppressed_when_impact_signal_absent() {
        // The graph connects nothing to this diff: an empty channel cannot
        // prove a coverage gap, and the shadow report already carries the
        // deficit as an impact_signal_absent evidence gap.
        let old = test_entity_with_span("quiet_fn", "src/quiet.rs", 1, 10);
        let new = old.clone();

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

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CoverageGap),
            "no coverage gap may be claimed from an absent impact signal"
        );
    }

    #[test]
    fn command_contract_delta_emits_inline_finding() {
        let mut old = test_entity_with_span("prCheckout", "command/pr_checkout.go", 14, 102);
        old.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "schema_version": 1,
                "effects": [{
                    "kind": "queued_git_argv",
                    "expr": "append(cmdQueue, []string{\"git\", \"checkout\", newBranchName})",
                    "bindings": { "newBranchName": "pr.HeadRefName" }
                }]
            }),
        );
        let mut new = old.clone();
        new.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "schema_version": 1,
                "effects": [{
                    "kind": "queued_git_argv",
                    "expr": "append(cmdQueue, []string{\"git\", \"checkout\", newBranchName})",
                    "bindings": { "newBranchName": "fmt.Sprintf(\"pr/%d/%s\", pr.Number, pr.HeadRefName)" }
                }]
            }),
        );

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
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 0,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec![],
                covering_tests: 1,
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            comments
                .iter()
                .any(|comment| comment.kind == InlineCommentKind::CommandEffectContract),
            "command contract metadata delta should emit an attention finding: {comments:?}"
        );
    }

    #[test]
    fn consumer_fanout_fires_on_body_change_at_threshold() {
        // Body-only modification (signature and visibility unchanged) reaching
        // two distinct non-test consumer entities -> attention comment.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();

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
        let consumer_a = test_entity_with_span("use_a", "src/a.rs", 1, 5);
        let consumer_b = test_entity_with_span("use_b", "src/b.rs", 1, 5);
        let impact = ImpactReport {
            affected_callers: vec![consumer_a, consumer_b],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
            }],
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(fanout.len(), 1);
        assert!(fanout[0].message.contains("2 distinct non-test consumer"));
    }

    #[test]
    fn consumer_fanout_uses_weak_consumers_only_when_uncovered() {
        // Ambiguous-dispatch fan-out links every possible implementor at low
        // confidence. Covered body-only changes need strong consumers to gate;
        // uncovered body-only changes still gate on weak fanout, because the
        // graph has no test evidence to absorb that possible blast radius.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();
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
        let covered_weak_only = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &covered_weak_only);
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::ConsumerFanout),
            "covered weak-only consumers must not fire the fanout gate"
        );

        let uncovered_weak_only = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 0,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &uncovered_weak_only);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(
            fanout.len(),
            1,
            "uncovered weak fanout must still fire the review gate"
        );
        assert!(
            fanout[0].message.contains("4 distinct non-test consumer"),
            "uncovered fanout reports the full graph-native consumer count"
        );

        let mixed = ImpactReport {
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 4,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 1,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &mixed);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(fanout.len(), 1, "strong consumers at threshold must fire");
        assert!(fanout[0].message.contains("2 distinct non-test consumer"));
    }

    #[test]
    fn strengthened_only_signature_is_not_a_signature_change() {
        assert!(signature_strengthened_only(
            "TestRunInfo(StringRef _name)",
            "constexpr TestRunInfo(StringRef _name)"
        ));
        assert!(!signature_strengthened_only(
            "constexpr TestRunInfo(StringRef _name)",
            "TestRunInfo(StringRef _name)"
        ));
        assert!(!signature_strengthened_only(
            "TestRunInfo(StringRef _name)",
            "TestRunInfo(StringRef _name, int mode)"
        ));
        assert!(!signature_strengthened_only(
            "inline int f()",
            "constexpr int f()"
        ));
        assert!(!signature_strengthened_only("int f()", "int f()"));
    }

    #[test]
    fn strengthened_only_change_emits_no_signature_or_breaking_comment() {
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let mut new = old.clone();
        new.signature = format!("constexpr {}", old.signature);
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
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 3,
                strong_consumer_count: 3,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(
            !comments.iter().any(|c| matches!(
                c.kind,
                InlineCommentKind::SignatureChange | InlineCommentKind::Breaking
            )),
            "qualifier strengthening must not read as signature change or breaking"
        );
    }

    #[test]
    fn command_contract_absent_on_one_side_is_no_signal() {
        let old = test_entity_with_span("runner", "cmd/run.go", 1, 20);
        let mut new = old.clone();
        new.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.to_string(),
            serde_json::json!({"schema_version": 1, "effects": []}),
        );
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
        let comments = collect_inline_comments(&diff, &ImpactReport::default());
        assert!(
            !comments
                .iter()
                .any(|c| c.kind == InlineCommentKind::CommandEffectContract),
            "key present on only one side is persist-path coverage skew, not a change"
        );
    }

    #[test]
    fn consumer_fanout_decides_on_entity_count_not_file_count() {
        // Two distinct consumer entities that live in the SAME file: one file,
        // two entities. The fanout decision is graph-native — it keys on the
        // consumer ENTITY count (2 >= threshold), so it fires even though the
        // consumers project onto a single file. A file-count decision would
        // have stayed silent here; that is exactly the file-first behavior this
        // rule must not have.
        let old = test_entity_with_span("hot_path", "src/hot.rs", 1, 20);
        let new = old.clone();
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
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                // Both consumers in one file: file count (1) is below threshold,
                // entity count (2) is at it.
                consumer_files: vec!["src/shared.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        let fanout: Vec<&InlineComment> = comments
            .iter()
            .filter(|c| c.kind == InlineCommentKind::ConsumerFanout)
            .collect();
        assert_eq!(
            fanout.len(),
            1,
            "fanout fires on 2 consumer entities even though they share one file"
        );
        assert!(fanout[0]
            .message
            .contains("2 distinct non-test consumer(s) across 1 file(s)"));
    }

    #[test]
    fn consumer_fanout_silent_below_threshold_and_on_surface_changes() {
        let old = test_entity_with_span("narrow_fn", "src/narrow.rs", 1, 20);
        let new = old.clone();
        let consumer = test_entity_with_span("only_use", "src/only.rs", 1, 5);

        // One consumer file: below threshold, silent.
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
            affected_callers: vec![consumer.clone()],
            changed_ids: vec![new.id],
            entity_impacts: vec![EntityImpact {
                entity_id: new.id,
                consumer_count: 1,
                strong_consumer_count: 1,
                contract_consumer_count: 0,
                consumer_files: vec!["src/only.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::ConsumerFanout));

        // Signature change with wide fanout: the breaking/signature channels
        // own it; fanout stays silent.
        let mut resigned = old.clone();
        resigned.signature = "fn narrow_fn(extra: u8)".to_string();
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: resigned.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: resigned.clone(),
                },
            }],
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![consumer],
            changed_ids: vec![resigned.id],
            entity_impacts: vec![EntityImpact {
                entity_id: resigned.id,
                consumer_count: 2,
                strong_consumer_count: 2,
                contract_consumer_count: 0,
                consumer_files: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                covering_tests: 0,
            }],
            ..Default::default()
        };
        let comments = collect_inline_comments(&diff, &impact);
        assert!(!comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::ConsumerFanout));
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Breaking));
    }

    #[test]
    fn visibility_reduction_produces_comment() {
        let old = test_entity_with_span("public_fn", "src/lib.rs", 10, 20);
        let mut new = old.clone();
        new.visibility = Visibility::Private;

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
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::VisibilityChange));
    }

    #[test]
    fn rename_produces_comment() {
        let old = test_entity_with_span("old_name", "src/lib.rs", 1, 5);
        let mut new = old.clone();
        new.name = "new_name".to_string();

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
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments
            .iter()
            .any(|c| c.kind == InlineCommentKind::Renamed));
    }

    #[test]
    fn comments_sorted_by_file_then_line() {
        let e1 = test_entity_with_span("fn_b", "src/b.rs", 10, 20);
        let e2 = test_entity_with_span("fn_a", "src/a.rs", 5, 15);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: e1.id,
                    kind: EntityChangeKind::Added(e1.clone()),
                },
                EntityChange {
                    entity_id: e2.id,
                    kind: EntityChangeKind::Added(e2.clone()),
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        // src/a.rs should come before src/b.rs
        let files: Vec<&str> = comments.iter().map(|c| c.file.as_str()).collect();
        let a_pos = files.iter().position(|f| *f == "src/a.rs").unwrap();
        let b_pos = files.iter().position(|f| *f == "src/b.rs").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn group_by_file_groups_correctly() {
        let e1 = test_entity_with_span("fn_a", "src/a.rs", 1, 5);
        let e2 = test_entity_with_span("fn_b", "src/a.rs", 10, 20);
        let e3 = test_entity_with_span("fn_c", "src/b.rs", 1, 5);

        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: e1.id,
                    kind: EntityChangeKind::Added(e1.clone()),
                },
                EntityChange {
                    entity_id: e2.id,
                    kind: EntityChangeKind::Added(e2.clone()),
                },
                EntityChange {
                    entity_id: e3.id,
                    kind: EntityChangeKind::Added(e3.clone()),
                },
            ],
            ..Default::default()
        };
        let impact = ImpactReport::default();

        let comments = collect_inline_comments(&diff, &impact);
        let grouped = group_by_file(&comments);
        assert_eq!(grouped.len(), 2);
        // src/a.rs has two entities so at least 2 comments (could have coverage gap comments too)
        assert!(grouped["src/a.rs"].len() >= 2);
        assert!(grouped["src/b.rs"].len() >= 1);
    }
}
