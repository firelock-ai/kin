// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;

use kin_model::entity::{Entity, EntityKind, SourceSpan, Visibility};
use serde::{Deserialize, Serialize};

use crate::diff::{EntityChangeKind, SemanticDiff};
use crate::impact::ImpactReport;

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
    SignatureChange,
    VisibilityChange,
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
            Self::CoverageGap => "?",
            Self::SignatureChange => "~",
            Self::VisibilityChange => "~",
            Self::Added => "+",
            Self::Removed => "-",
            Self::Renamed => "~",
            Self::AgentUnreviewed => "@",
        }
    }
}

/// Collect line-level inline comments from a review's diff and impact data.
///
/// Each comment is anchored to a file + line range derived from the entity's
/// `SourceSpan`. Entities without a span are skipped (they have no file location
/// to anchor to).
pub fn collect_inline_comments(
    diff: &SemanticDiff,
    impact: &ImpactReport,
) -> Vec<InlineComment> {
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

    // Public entity without test coverage
    if entity.visibility == Visibility::Public
        && !matches!(entity.kind, EntityKind::Test)
        && impact.affected_tests.is_empty()
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!(
                "New public entity `{}` has no test coverage",
                entity.name,
            ),
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

    let has_callers = !impact.affected_callers.is_empty();
    let has_consumers = !impact.affected_contract_consumers.is_empty();

    // Signature change
    if old.signature != new.signature {
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

        // Breaking if callers or consumers exist
        if has_callers || has_consumers {
            let affected = impact.affected_callers.len() + impact.affected_contract_consumers.len();
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: signature modification affects {} downstream entity(ies)",
                    affected,
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

        if has_callers {
            comments.push(InlineComment {
                file: span.file.to_string(),
                start_line: span.start_line,
                end_line: span.end_line,
                kind: InlineCommentKind::Breaking,
                message: format!(
                    "Breaking change: visibility reduced with {} caller(s)",
                    impact.affected_callers.len(),
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

    // Contract entity with consumers
    if matches!(
        new.kind,
        EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
    ) && has_consumers
    {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::ContractViolation,
            message: format!(
                "Contract {:?} `{}` modified with {} consumer(s)",
                new.kind,
                new.name,
                impact.affected_contract_consumers.len(),
            ),
        });
    }

    // No test coverage
    if !matches!(new.kind, EntityKind::Test) && impact.affected_tests.is_empty() {
        comments.push(InlineComment {
            file: span.file.to_string(),
            start_line: span.start_line,
            end_line: span.end_line,
            kind: InlineCommentKind::CoverageGap,
            message: format!(
                "Modified entity `{}` has no test coverage",
                new.name,
            ),
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
    use crate::impact::ImpactReport;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
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
        assert!(comments.iter().any(|c| c.kind == InlineCommentKind::SignatureChange));
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
            ..Default::default()
        };

        let comments = collect_inline_comments(&diff, &impact);
        assert!(comments.iter().any(|c| c.kind == InlineCommentKind::Breaking));
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
        assert!(comments.iter().any(|c| c.kind == InlineCommentKind::VisibilityChange));
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
        assert!(comments.iter().any(|c| c.kind == InlineCommentKind::Renamed));
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
