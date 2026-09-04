// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Immutable repository-v6 history reads.
//!
//! Log resolves the active workspace base through one repository authority
//! lease, then walks the graph-owned semantic change DAG. It never asks Git,
//! legacy branch state, a daemon-owned graph, or checkout files for history.

use std::collections::{BTreeSet, VecDeque};

use anyhow::{Context, Result};
use kin_model::{
    AuthorId, ChangeOrigin, RefTarget, RepositoryId, RootBundle, SemanticChangeId, Timestamp,
    WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

pub const LOG_SCHEMA: &str = "kin.log.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRequest {
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<LogReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub change_id: SemanticChangeId,
    pub depth: usize,
    pub origin: ChangeOrigin,
    /// Exact parent order from the immutable semantic change.
    pub parents: Vec<SemanticChangeId>,
    pub timestamp: Timestamp,
    pub author: AuthorId,
    pub message: String,
    /// Entity deltas whose entity's own content moved.
    ///
    /// Not `entity_deltas.len()`. A change that edits one function mints a
    /// revision for every entity in that file, because `reconciler` stamps the
    /// whole FILE's blob hash into every entity's `metadata.extra` and editing
    /// one function moves the byte span of every entity below it. Those
    /// revisions are real and are what the file did; counting them here
    /// answered a two-function commit with `entities=12`.
    pub entity_delta_count: usize,
    /// The entity deltas the count above leaves out, named rather than dropped.
    ///
    /// `#[serde(default)]` because this crosses the daemon wire and an older
    /// peer sends none.
    #[serde(default)]
    pub entity_deltas_unchanged: usize,
    pub relation_delta_count: usize,
    pub tree_delta_count: usize,
    pub admission_policy_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub workspace_generation: u64,
    pub workspace_head: WorkspaceHead,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_target: Option<RefTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_change: Option<SemanticChangeId>,
    pub requested_count: usize,
    pub truncated: bool,
    pub entries: Vec<LogEntry>,
}

pub fn inspect(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    count: usize,
) -> Result<LogReport> {
    let authority = ActiveRepositoryAuthority::open(binding)?;
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let snapshot = lease.snapshot();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in its authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    workspace
        .validate()
        .context("active repository-v6 workspace is invalid")?;

    let start_target = workspace.base_target.clone();
    let start_change = start_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target))
        .transpose()
        .context("resolve active repository-v6 workspace history")?;

    let mut entries = Vec::with_capacity(count.min(snapshot.changes.len()));
    let mut scheduled = BTreeSet::new();
    let mut pending = VecDeque::new();
    if let Some(change_id) = start_change {
        scheduled.insert(change_id);
        pending.push_back((change_id, 0_usize));
    }

    while entries.len() < count {
        let Some((change_id, depth)) = pending.pop_front() else {
            break;
        };
        let change = snapshot.changes.get(&change_id).ok_or_else(|| {
            anyhow::anyhow!(
                "repository-v6 history target {} is absent from the immutable change DAG",
                change_id
            )
        })?;
        if change.id != change_id {
            anyhow::bail!(
                "repository-v6 history key {} contains mismatched change {}",
                change_id,
                change.id
            );
        }
        for parent in &change.parents {
            if !snapshot.changes.contains_key(parent) {
                anyhow::bail!(
                    "repository-v6 change {} names absent parent {}",
                    change_id,
                    parent
                );
            }
            if scheduled.insert(*parent) {
                pending.push_back((*parent, depth + 1));
            }
        }
        let entity_deltas_unchanged = unchanged_entity_deltas(change);
        entries.push(LogEntry {
            change_id,
            depth,
            origin: change.origin,
            parents: change.parents.clone(),
            timestamp: change.timestamp.clone(),
            author: change.author.clone(),
            message: change.message.clone(),
            entity_delta_count: change.entity_deltas.len() - entity_deltas_unchanged,
            entity_deltas_unchanged,
            relation_delta_count: change.relation_deltas.len(),
            tree_delta_count: change.tree_deltas.len(),
            admission_policy_changed: change.admission_policy_delta.is_some(),
        });
    }

    Ok(LogReport {
        schema: LOG_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        roots: lease.roots().clone(),
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_head: workspace.head.clone(),
        start_target,
        start_change,
        requested_count: count,
        truncated: !pending.is_empty(),
        entries,
    })
}

pub fn run(count: usize, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let report = inspect(&binding, count)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}

pub fn build_log_response(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    _graph: &kin_db::InMemoryGraph,
    request: &LogRequest,
) -> Result<LogResponse> {
    let report = inspect(binding, request.count)?;
    Ok(LogResponse {
        lines: render_lines(&report),
        report: Some(report),
    })
}

/// How many of a change's entity deltas moved no entity's own content.
///
/// Asked through [`kin_core::workspace_semantics::entity_content_agrees`],
/// which is the ONE answer `kin conflicts`, `kin diff`, `kin blame` and
/// `kin history` ask too. Only a `Modified` delta can be one of these: an
/// addition and a removal are content events by construction.
fn unchanged_entity_deltas(change: &kin_model::SemanticChange) -> usize {
    change
        .entity_deltas
        .iter()
        .filter(|delta| match delta {
            kin_model::EntityDelta::Modified { old, new } => {
                kin_core::workspace_semantics::entity_content_agrees(old, new)
            }
            kin_model::EntityDelta::Added { .. } | kin_model::EntityDelta::Removed { .. } => false,
        })
        .count()
}

/// Name what the entity count leaves out, so a reader can see it exists.
///
/// Half of `kin blame`'s contract: blame names its withheld count AND takes
/// `--all-revisions` to list them, while `kin log` names the count and has no
/// flag that shows them yet. The flag is the follow-up.
fn unchanged_suffix(unchanged: usize) -> String {
    if unchanged == 0 {
        return String::new();
    }
    let plural = if unchanged == 1 { "y" } else { "ies" };
    format!(" ({unchanged} unchanged entit{plural} moved with their artifact)")
}

fn render_lines(report: &LogReport) -> Vec<String> {
    if report.entries.is_empty() {
        return vec!["(no changes)".to_string()];
    }
    let mut lines = Vec::new();
    for (position, entry) in report.entries.iter().enumerate() {
        if position > 0 {
            lines.push(String::new());
        }
        lines.push(format!("change {}", entry.change_id));
        lines.push(format!("Author: {}", entry.author));
        lines.push(format!("Date:   {}", entry.timestamp));
        lines.push(format!("Origin: {}", render_origin(entry.origin)));
        if !entry.parents.is_empty() {
            lines.push(format!(
                "Parents: {}",
                entry
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        lines.push(format!(
            "Deltas: entities={} relations={} tree={} policy={}{}",
            entry.entity_delta_count,
            entry.relation_delta_count,
            entry.tree_delta_count,
            entry.admission_policy_changed,
            unchanged_suffix(entry.entity_deltas_unchanged)
        ));
        lines.push(format!("    {}", entry.message.replace('\n', "\n    ")));
    }
    lines
}

fn render_origin(origin: ChangeOrigin) -> String {
    match origin {
        ChangeOrigin::Native => "native".to_string(),
        ChangeOrigin::GitCommit { oid } => format!("git commit {oid}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        Entity, EntityDelta, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticChange, SemanticFingerprint, SourceSpan,
        Visibility,
    };

    /// One version of one entity, plus the file-level noise a real reconcile
    /// stamps on every entity in a touched file whether or not it moved: the
    /// whole FILE's blob hash in `metadata.extra`, and the byte span everything
    /// below an edit shifts to.
    fn entity(id: EntityId, name: &str, body: u8, stamp: u8) -> Entity {
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "artifact_blob".to_string(),
            serde_json::Value::String(format!("{stamp:02x}")),
        );
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([body; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([body; 32]),
                equivalence_hash: Hash256::from_bytes([body; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("ledger/reporting.py")),
            span: Some(SourceSpan {
                file: FilePathId::new("ledger/reporting.py"),
                start_byte: usize::from(stamp) * 100,
                end_byte: usize::from(stamp) * 100 + 40,
                start_line: u32::from(stamp),
                start_col: 0,
                end_line: u32::from(stamp) + 3,
                end_col: 0,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata { extra },
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn change_with(deltas: Vec<EntityDelta>) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "Right-align report amounts".to_string(),
            entity_deltas: deltas,
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        }
    }

    /// The vcs stranger run's `kin log` finding, rebuilt.
    ///
    /// A commit that edited two function bodies read `Deltas: entities=12`,
    /// because a file-level edit mints a revision for every entity in that
    /// file. Twelve deltas, one addition, one real body change, ten that moved
    /// only with their file.
    ///
    /// Breaking it: return 0 from `unchanged_entity_deltas` and this reports
    /// twelve.
    #[test]
    fn a_two_function_commit_counts_the_functions_it_changed() {
        let mut deltas = vec![EntityDelta::Added {
            new: entity(EntityId::new(), "format_currency", 9, 0x30),
        }];
        let edited = EntityId::new();
        deltas.push(EntityDelta::Modified {
            old: entity(edited, "format_totals", 1, 0x10),
            new: entity(edited, "format_totals", 2, 0x30),
        });
        for index in 0..10 {
            let id = EntityId::new();
            let name = format!("untouched_{index}");
            deltas.push(EntityDelta::Modified {
                old: entity(id, &name, 1, 0x10),
                new: entity(id, &name, 1, 0x30),
            });
        }
        let change = change_with(deltas);
        assert_eq!(change.entity_deltas.len(), 12, "the fixture is the case");

        let unchanged = unchanged_entity_deltas(&change);
        assert_eq!(unchanged, 10);
        assert_eq!(
            change.entity_deltas.len() - unchanged,
            2,
            "one addition and one changed body"
        );

        // Counted is not enough. A reader has to be able to see they exist.
        let suffix = unchanged_suffix(unchanged);
        assert!(suffix.contains("10"), "{suffix}");
    }

    /// The control. A change that withholds nothing must say nothing about
    /// withholding, or every line reads as trimmed. An addition and a removal
    /// are content events and are never withheld.
    #[test]
    fn a_change_that_withholds_nothing_says_nothing_about_withholding() {
        let id = EntityId::new();
        let change = change_with(vec![
            EntityDelta::Added {
                new: entity(EntityId::new(), "format_currency", 9, 0x30),
            },
            EntityDelta::Removed {
                old: entity(EntityId::new(), "legacy_totals", 5, 0x10),
            },
            EntityDelta::Modified {
                old: entity(id, "format_totals", 1, 0x10),
                new: entity(id, "format_totals", 2, 0x30),
            },
        ]);
        assert_eq!(unchanged_entity_deltas(&change), 0);
        assert!(unchanged_suffix(0).is_empty());
    }
}
