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

/// One change on the branch line, carrying the parent list its immutable
/// change published rather than only the first-parent link.
///
/// A merge publishes `[ours, theirs]` and only `ours` continues the line, so a
/// plan given the bare line could not tell a merge from an ordinary change and
/// would discard everything the merge brought in without ever naming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineChange {
    pub change: SemanticChangeId,
    pub parents: Vec<SemanticChangeId>,
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
    /// A claimed change is a merge that brought in ancestry the work item does
    /// not claim. That ancestry is reachable but absent from the line, so a
    /// restore would discard it without the line ever showing it.
    MergedWorkNotClaimed {
        merge: SemanticChangeId,
        unclaimed_parents: Vec<SemanticChangeId>,
    },
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
                "these recorded changes are not on the first-parent line of the current branch: \
                 {}; a change merged in from elsewhere stays reachable without sitting on this \
                 line, so `kin log` shows where it sits and `kin rollback <change-id>` restores an \
                 explicit change",
                render_change_list(changes)
            ),
            Self::InterveningChanges(changes) => write!(
                f,
                "rolling this work item back would also discard {}, which it does not claim; \
                 restore an explicit change with `kin rollback <change-id>` if that is what you \
                 intend",
                render_change_list(changes)
            ),
            Self::MergedWorkNotClaimed {
                merge,
                unclaimed_parents,
            } => write!(
                f,
                "change {merge} merged {} into this line, and this work item does not claim that \
                 side of the merge, so restoring an earlier state would discard everything it \
                 brought in; `kin log` shows what the merge carries, and `kin rollback \
                 <change-id>` restores an explicit change if that is what you intend",
                render_change_list(unclaimed_parents)
            ),
            Self::ReachesRepositoryRoot => write!(
                f,
                "the earliest change this work item records is the first change on this line, so \
                 there is no earlier state to restore; `kin log` shows the whole line, and `kin \
                 rollback <change-id>` restores any change on it"
            ),
            Self::HistoryWindowExhausted => write!(
                f,
                "not every change this work item records was found within the {} changes read, so \
                 the branch line cannot be decided; restore an explicit change with `kin rollback \
                 <change-id>` instead",
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
///
/// The line alone is not enough to decide that. The daemon accepts a target on
/// full-DAG reachability and computes the correction from the whole current
/// state, so a merge inside the claimed run also discards its second-parent
/// ancestry, which no position on the line reveals. Each line entry therefore
/// carries its full parent list and a merge that brought in unclaimed work is
/// refused.
pub fn plan_work_item_rollback(
    line: &[LineChange],
    line_truncated: bool,
    recorded: &[SemanticChangeId],
) -> Result<WorkItemRollbackPlan, WorkItemRollbackRefusal> {
    if recorded.is_empty() {
        return Err(WorkItemRollbackRefusal::NoRecordedChanges);
    }

    let mut positions = Vec::new();
    let mut absent = Vec::new();
    for change in recorded {
        match line
            .iter()
            .position(|candidate| &candidate.change == change)
        {
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
        .map(|index| line[index].change)
        .collect();
    if !intervening.is_empty() {
        return Err(WorkItemRollbackRefusal::InterveningChanges(intervening));
    }

    // Every position above the oldest claimed one is claimed by here, so the
    // claimed run is exactly what a restore drops from this line. What it also
    // drops is whatever a merge in that run brought in from another line, and
    // that is invisible in the line itself.
    for entry in positions.iter().map(|index| &line[*index]) {
        let unclaimed: Vec<SemanticChangeId> = entry
            .parents
            .iter()
            .skip(1)
            .filter(|parent| !recorded.contains(parent))
            .copied()
            .collect();
        if !unclaimed.is_empty() {
            return Err(WorkItemRollbackRefusal::MergedWorkNotClaimed {
                merge: entry.change,
                unclaimed_parents: unclaimed,
            });
        }
    }

    match line.get(newest_run) {
        Some(target) => Ok(WorkItemRollbackPlan {
            target: target.change,
            reverted: positions.iter().map(|index| line[*index].change).collect(),
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
///
/// Each entry keeps every parent, not just the one the walk followed, so a
/// caller can tell a merge from an ordinary change.
pub fn first_parent_line(report: &crate::commands::log::LogReport) -> Vec<LineChange> {
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
        let parents = by_id
            .get(&change_id)
            .map(|entry| entry.parents.clone())
            .unwrap_or_default();
        cursor = parents.first().copied();
        line.push(LineChange {
            change: change_id,
            parents,
        });
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
    // Clap refuses both arms below before dispatch, with a usage block and
    // exit 2. They stay as the backstop for any other caller, and because they
    // name the remedy and the command that supplies the missing value.
    let change_id = match (change_id, feature) {
        (Some(_), Some(_)) => {
            anyhow::bail!("name a change to roll back to, or a work item with --feature, not both")
        }
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

    /// A line with no merges, head first, each change parented on the next.
    fn linear_line(changes: &[SemanticChangeId]) -> Vec<LineChange> {
        changes
            .iter()
            .enumerate()
            .map(|(index, change)| LineChange {
                change: *change,
                parents: changes.get(index + 1).copied().into_iter().collect(),
            })
            .collect()
    }

    /// The newest run of the line is the only shape rollback can restore as a
    /// unit, and it resolves to the change just before that run.
    #[test]
    fn tip_run_resolves_to_the_change_before_it() {
        let line = linear_line(&[change(4), change(3), change(2), change(1)]);
        let plan = plan_work_item_rollback(&line, false, &[change(3), change(4)]).unwrap();
        assert_eq!(plan.target, change(2));
        assert_eq!(plan.reverted, vec![change(4), change(3)]);
    }

    /// A work item that recorded nothing must not be answered with a guess.
    #[test]
    fn no_recorded_changes_refuses() {
        let line = linear_line(&[change(2), change(1)]);
        assert_eq!(
            plan_work_item_rollback(&line, false, &[]),
            Err(WorkItemRollbackRefusal::NoRecordedChanges)
        );
    }

    /// Someone else's change published after the work item's earliest change
    /// would be discarded by the restore, so the refusal names it.
    #[test]
    fn intervening_change_is_named_rather_than_discarded() {
        let line = linear_line(&[change(9), change(3), change(2), change(1)]);
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(3), change(2)]),
            Err(WorkItemRollbackRefusal::InterveningChanges(vec![change(9)]))
        );
    }

    /// A recorded change on another branch is not silently ignored.
    #[test]
    fn change_off_this_line_is_named() {
        let line = linear_line(&[change(2), change(1)]);
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(7)]),
            Err(WorkItemRollbackRefusal::NotOnBranchLine(vec![change(7)]))
        );
    }

    /// Restoring the state before the first change on the line has no target.
    #[test]
    fn reaching_the_first_change_refuses() {
        let line = linear_line(&[change(2), change(1)]);
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(2), change(1)]),
            Err(WorkItemRollbackRefusal::ReachesRepositoryRoot)
        );
    }

    /// A truncated read cannot tell the first change from an unread one, so it
    /// reports the window rather than claiming a root.
    #[test]
    fn truncated_window_is_reported_as_a_window() {
        let line = linear_line(&[change(2), change(1)]);
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
        let line = linear_line(&[change(3), change(2), change(1)]);
        let plan =
            plan_work_item_rollback(&line, false, &[change(3), change(3), change(3)]).unwrap();
        assert_eq!(plan.target, change(2));
        assert_eq!(plan.reverted, vec![change(3)]);
    }

    /// A merge inside the claimed run brought in a line the first-parent walk
    /// never visits, and the daemon accepts the target on full-DAG
    /// reachability, so restoring the change before the run would discard that
    /// whole side without naming it.
    #[test]
    fn merge_of_unclaimed_work_inside_the_run_refuses() {
        let mut line = linear_line(&[change(5), change(4), change(3)]);
        line[0].parents = vec![change(4), change(9)];
        assert_eq!(
            plan_work_item_rollback(&line, false, &[change(5)]),
            Err(WorkItemRollbackRefusal::MergedWorkNotClaimed {
                merge: change(5),
                unclaimed_parents: vec![change(9)],
            })
        );
    }

    /// The refusal is about unclaimed work, not about merges. A merge whose
    /// every extra parent the work item also claims discards nothing the item
    /// did not ask to discard, so it still plans.
    #[test]
    fn merge_whose_every_parent_is_claimed_still_plans() {
        let mut line = linear_line(&[change(5), change(4), change(3), change(2)]);
        line[0].parents = vec![change(4), change(3)];
        let plan =
            plan_work_item_rollback(&line, false, &[change(5), change(4), change(3)]).unwrap();
        assert_eq!(plan.target, change(2));
    }

    /// A merge older than the claimed run is part of the state being restored
    /// rather than something the restore discards, so it does not refuse.
    #[test]
    fn merge_below_the_claimed_run_does_not_refuse() {
        let mut line = linear_line(&[change(5), change(4), change(3)]);
        line[2].parents = vec![change(2), change(9)];
        let plan = plan_work_item_rollback(&line, false, &[change(5)]).unwrap();
        assert_eq!(plan.target, change(4));
    }

    /// Commands each refusal must name. The match is exhaustive, so a refusal
    /// cannot be added without declaring what the caller can run next.
    fn required_commands(refusal: &WorkItemRollbackRefusal) -> &'static [&'static str] {
        match refusal {
            WorkItemRollbackRefusal::NoRecordedChanges => {
                &["kin work link", "kin rollback <change-id>"]
            }
            WorkItemRollbackRefusal::NotOnBranchLine(_) => &["kin log", "kin rollback <change-id>"],
            WorkItemRollbackRefusal::InterveningChanges(_) => &["kin rollback <change-id>"],
            WorkItemRollbackRefusal::MergedWorkNotClaimed { .. } => {
                &["kin log", "kin rollback <change-id>"]
            }
            WorkItemRollbackRefusal::ReachesRepositoryRoot => {
                &["kin log", "kin rollback <change-id>"]
            }
            WorkItemRollbackRefusal::HistoryWindowExhausted => &["kin rollback <change-id>"],
        }
    }

    /// Every refusal has to name something the caller can run next; a bare
    /// statement of the condition is the first-touch failure this avoids.
    ///
    /// Asserting on the word "change" would not catch that: every one of these
    /// messages is about changes, so descriptive prose alone would satisfy it
    /// and a refusal naming no command at all would pass. Each case declares
    /// the exact commands its text must carry instead.
    #[test]
    fn every_refusal_names_the_commands_it_declares() {
        let refusals = [
            WorkItemRollbackRefusal::NoRecordedChanges,
            WorkItemRollbackRefusal::NotOnBranchLine(vec![change(1)]),
            WorkItemRollbackRefusal::InterveningChanges(vec![change(1)]),
            WorkItemRollbackRefusal::MergedWorkNotClaimed {
                merge: change(5),
                unclaimed_parents: vec![change(9)],
            },
            WorkItemRollbackRefusal::ReachesRepositoryRoot,
            WorkItemRollbackRefusal::HistoryWindowExhausted,
        ];
        for refusal in refusals {
            let rendered = refusal.to_string();
            let commands = required_commands(&refusal);
            assert!(
                !commands.is_empty(),
                "every refusal must declare a command it names: {rendered}"
            );
            for command in commands {
                assert!(
                    rendered.contains(command),
                    "refusal must name `{command}`: {rendered}"
                );
            }
        }
    }
}
