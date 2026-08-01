// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned repository-v6 rollback.
//!
//! Rollback moves history forward, never backward: it constructs a new change
//! whose content is exactly the target change's content, so the branch keeps
//! its complete immutable history and the repository ends up at a tree that
//! already existed. Every artifact identity in the result is the identity the
//! target already had, so no source is rewritten and no CAS entry is created.

use anyhow::Result;
use kin_model::{AuthorId, OperationId, RefName, RepositoryId, SemanticChangeId};
use serde::{Deserialize, Serialize};

pub const ROLLBACK_SCHEMA: &str = "kin.rollback.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    /// Canonical lowercase hexadecimal change to restore.
    pub change_id: String,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub branch: RefName,
    /// The change whose content is restored.
    pub target_change_id: String,
    /// The change the branch pointed at before this rollback.
    pub previous_change_id: String,
    /// The new change this rollback published.
    pub inverse_change_id: String,
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub entity_deltas: usize,
    pub relation_deltas: usize,
    pub tree_deltas: usize,
    pub projected_entries: usize,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<RollbackReport>,
}

/// How far back to read the change line when resolving a work item. A work
/// item's changes are the recent tip of a branch in every case this serves, and
/// an exhausted window refuses rather than guessing.
const WORK_ITEM_HISTORY_WINDOW: usize = 4096;

/// The change a work-item rollback resolves to: the state immediately before
/// the work item's earliest recorded change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItemRollbackPlan {
    pub target: SemanticChangeId,
    pub reverted: Vec<SemanticChangeId>,
}

/// Why a work item cannot be rolled back as a unit. Each case names something
/// the caller can act on rather than reporting a bare failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkItemRollbackRefusal {
    /// The work item records no change scopes at all.
    NoRecordedChanges,
    /// Recorded changes that are not on this branch line.
    NotOnBranchLine(Vec<SemanticChangeId>),
    /// Changes published after the work item's earliest change that the work
    /// item does not claim. Rolling back would silently discard them.
    InterveningChanges(Vec<SemanticChangeId>),
    /// The earliest recorded change is the first change on the line, so there
    /// is no earlier state to restore.
    ReachesRepositoryRoot,
    /// The read window ended before the earliest recorded change.
    HistoryWindowExhausted,
}

impl std::fmt::Display for WorkItemRollbackRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRecordedChanges => write!(
                f,
                "this work item records no changes, so there is nothing to roll back; link one \
                 with `kin work link <work-id> change:<change-id>`, or roll back to an explicit \
                 change with `kin rollback <change-id>`"
            ),
            Self::NotOnBranchLine(changes) => write!(
                f,
                "these recorded changes are not on the current branch line: {}; switch to the \
                 branch that carries them, or roll back to an explicit change",
                render_change_list(changes)
            ),
            Self::InterveningChanges(changes) => write!(
                f,
                "rolling this work item back would also discard {}, which it does not claim; roll \
                 back to an explicit change if that is what you intend",
                render_change_list(changes)
            ),
            Self::ReachesRepositoryRoot => write!(
                f,
                "the earliest change this work item records is the first change on this line, so \
                 there is no earlier state to restore"
            ),
            Self::HistoryWindowExhausted => write!(
                f,
                "the earliest change this work item records is further back than the {} changes \
                 read; roll back to an explicit change instead",
                WORK_ITEM_HISTORY_WINDOW
            ),
        }
    }
}

fn render_change_list(changes: &[SemanticChangeId]) -> String {
    changes
        .iter()
        .map(|change| change.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve a work item's recorded changes against a branch line.
///
/// `line` is the first-parent ancestry with the head first. Rollback restores
/// the content of one earlier change, so a work item can only be rolled back as
/// a unit when its changes are exactly the newest run of that line; anything
/// else would discard work the item never claimed.
pub fn plan_work_item_rollback(
    line: &[SemanticChangeId],
    line_truncated: bool,
    recorded: &[SemanticChangeId],
) -> Result<WorkItemRollbackPlan, WorkItemRollbackRefusal> {
    if recorded.is_empty() {
        return Err(WorkItemRollbackRefusal::NoRecordedChanges);
    }

    let mut positions = Vec::new();
    let mut absent = Vec::new();
    for change in recorded {
        match line.iter().position(|candidate| candidate == change) {
            Some(index) => positions.push(index),
            None if absent.contains(change) => {}
            None => absent.push(*change),
        }
    }
    if !absent.is_empty() {
        if line_truncated {
            return Err(WorkItemRollbackRefusal::HistoryWindowExhausted);
        }
        return Err(WorkItemRollbackRefusal::NotOnBranchLine(absent));
    }

    positions.sort_unstable();
    positions.dedup();
    let newest_run = positions.len();
    let intervening: Vec<SemanticChangeId> = (0..=positions[positions.len() - 1])
        .filter(|index| !positions.contains(index))
        .map(|index| line[index])
        .collect();
    if !intervening.is_empty() {
        return Err(WorkItemRollbackRefusal::InterveningChanges(intervening));
    }

    match line.get(newest_run) {
        Some(target) => Ok(WorkItemRollbackPlan {
            target: *target,
            reverted: positions.iter().map(|index| line[*index]).collect(),
        }),
        None if line_truncated => Err(WorkItemRollbackRefusal::HistoryWindowExhausted),
        None => Err(WorkItemRollbackRefusal::ReachesRepositoryRoot),
    }
}

/// The first-parent ancestry of a log report, head first.
///
/// History is a DAG and the log walk is breadth first, so position in the
/// entry list is not the branch order. The first-parent chain is the line the
/// branch actually advanced along, which is the only order a rollback target
/// can be read off.
pub fn first_parent_line(report: &crate::commands::log::LogReport) -> Vec<SemanticChangeId> {
    let mut by_id = std::collections::HashMap::new();
    for entry in &report.entries {
        by_id.insert(entry.change_id, entry);
    }
    let mut line = Vec::new();
    let mut cursor = report.start_change;
    let mut seen = std::collections::HashSet::new();
    while let Some(change_id) = cursor {
        if !seen.insert(change_id) {
            break;
        }
        line.push(change_id);
        cursor = by_id
            .get(&change_id)
            .and_then(|entry| entry.parents.first().copied());
    }
    line
}

async fn resolve_work_item_changes(work_id: &str) -> Result<Vec<SemanticChangeId>> {
    let response = crate::commands::work::request_work_scopes(work_id).await?;
    let report = response.scopes.ok_or_else(|| {
        anyhow::anyhow!("work item read returned no scopes for {work_id}; the daemon and this CLI disagree on the work protocol")
    })?;
    Ok(report
        .scopes
        .iter()
        .filter_map(|scope| match scope {
            kin_model::WorkScope::Change(change_id) => Some(*change_id),
            _ => None,
        })
        .collect())
}

async fn resolve_feature_target(work_id: &str) -> Result<String> {
    let recorded = resolve_work_item_changes(work_id).await?;
    let layout = crate::commands::require_repository_layout()?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let report = crate::commands::log::inspect(&binding, WORK_ITEM_HISTORY_WINDOW)?;
    let line = first_parent_line(&report);
    match plan_work_item_rollback(&line, report.truncated, &recorded) {
        Ok(plan) => {
            println!(
                "Work item {} records {} change(s) at the tip of this line.",
                work_id,
                plan.reverted.len()
            );
            println!("Restoring the content of change {}.", plan.target);
            Ok(plan.target.to_string())
        }
        Err(refusal) => anyhow::bail!("cannot roll back work item {work_id}: {refusal}"),
    }
}

pub async fn run(change_id: Option<String>, feature: Option<String>) -> Result<()> {
    let change_id = match (change_id, feature) {
        (Some(_), Some(_)) => anyhow::bail!(
            "name a change to roll back to, or a work item with --feature, not both"
        ),
        (None, None) => anyhow::bail!(
            "name the change to roll back to, or the work item whose changes to roll back with \
             --feature <work-id>; `kin log` lists the changes on this line"
        ),
        (Some(change_id), None) => change_id,
        (None, Some(work_id)) => resolve_feature_target(&work_id).await?,
    };
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Kin daemon is required for rollback but no daemon endpoint is available"
            )
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon
        .rollback(&RollbackRequest {
            change_id,
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        })
        .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn render_lines(report: &RollbackReport) -> Vec<String> {
    vec![
        format!(
            "Rolled {} back to change {}{}",
            report.branch,
            report.target_change_id,
            if report.idempotent {
                " (idempotent replay)"
            } else {
                ""
            }
        ),
        format!(
            "Published change {} over {}",
            report.inverse_change_id, report.previous_change_id
        ),
        format!(
            "Restored {} artifact(s), {} entity change(s), {} relation change(s); {} entries \
             projected",
            report.tree_deltas,
            report.entity_deltas,
            report.relation_deltas,
            report.projected_entries
        ),
        format!(
            "Authority generation {} (workspace generation {})",
            report.authority_generation, report.workspace_generation
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(seed: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([seed; 32]))
    }

    /// The newest run of the line is the only shape rollback can restore as a
    /// unit, and it resolves to the change just before that run.
    #[test]
    fn tip_run_resolves_to_the_change_before_it() {
        let line = vec![change(4), change(3), change(2), change(1)];
        let plan = plan_work_item_rollback(&line, false, &[change(3), change(4)]).unwrap();
        assert_eq!(plan.target, change(2));
        assert_eq!(plan.reverted, vec![change(4), change(3)]);
    }

    /// A work item that recorded nothing must not be answered with a guess.
    #[test]
    fn no_recorded_changes_refuses() {
        let line = vec![change(2), change(1)];
        assert_eq!(
            plan_work_item_rollback(&line, false, &[]),
            Err(WorkItemRollbackRefusal::NoRecordedChanges)
        );
    }

    /// Someone else's change published after the work item's earliest change
    /// would be discarded by the restore, so the refusal names it.
    #[test]
    fn intervening_change_is_named_rather_than_discarded() {
        let line = vec![change(9), change(3), change(2), change(1)];
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(3), change(2)]),
            Err(WorkItemRollbackRefusal::InterveningChanges(vec![change(9)]))
        );
    }

    /// A recorded change on another branch is not silently ignored.
    #[test]
    fn change_off_this_line_is_named() {
        let line = vec![change(2), change(1)];
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(7)]),
            Err(WorkItemRollbackRefusal::NotOnBranchLine(vec![change(7)]))
        );
    }

    /// Restoring the state before the first change on the line has no target.
    #[test]
    fn reaching_the_first_change_refuses() {
        let line = vec![change(2), change(1)];
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(2), change(1)]),
            Err(WorkItemRollbackRefusal::ReachesRepositoryRoot)
        );
    }

    /// A truncated read cannot tell the first change from an unread one, so it
    /// reports the window rather than claiming a root.
    #[test]
    fn truncated_window_is_reported_as_a_window() {
        let line = vec![change(2), change(1)];
        assert_eq!(
            plan_work_item_rollback(&line, true, &[change(2), change(1)]),
            Err(WorkItemRollbackRefusal::HistoryWindowExhausted)
        );
        assert_eq!(
            plan_work_item_rollback(&line, true, &[change(7)]),
            Err(WorkItemRollbackRefusal::HistoryWindowExhausted)
        );
    }

    /// Duplicate scope entries describe one change, not two.
    #[test]
    fn repeated_scope_entries_count_once() {
        let line = vec![change(3), change(2), change(1)];
        let plan =
            plan_work_item_rollback(&line, false, &[change(3), change(3), change(3)]).unwrap();
        assert_eq!(plan.target, change(2));
        assert_eq!(plan.reverted, vec![change(3)]);
    }

    /// Every refusal has to name something the caller can do next; a bare
    /// statement of the condition is the first-touch failure this avoids.
    #[test]
    fn every_refusal_names_a_remedy_or_a_change() {
        let refusals = [
            WorkItemRollbackRefusal::NoRecordedChanges,
            WorkItemRollbackRefusal::NotOnBranchLine(vec![change(1)]),
            WorkItemRollbackRefusal::InterveningChanges(vec![change(1)]),
            WorkItemRollbackRefusal::ReachesRepositoryRoot,
            WorkItemRollbackRefusal::HistoryWindowExhausted,
        ];
        for refusal in refusals {
            let rendered = refusal.to_string();
            assert!(
                rendered.contains("kin ") || rendered.contains("change"),
                "refusal must point somewhere: {rendered}"
            );
        }
    }
}
